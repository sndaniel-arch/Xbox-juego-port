/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.
 * Released under the BSD license - see LICENSE in the root for more details.
 ******************************************************************************
 *
 * @modified    Aurora, 2026 - Batch 1 (Xbox 360 -> Android compatibility,
 *              Rayman Origins recipe): header-only SPIR-V audit + patch
 *              utilities for translated guest shaders.
 *
 * What this file is
 * -----------------
 * A dependency-free, header-only scanner/rewriter for translated guest
 * SPIR-V binaries. It is called once per shader module, from
 * VulkanShader::VulkanTranslation::GetOrCreateShaderModule()
 * (src/graphics/vulkan/shader.cpp), and answers two questions:
 *
 *   1. Audit(): does this binary stay inside the Vulkan 1.1 / 4-set world?
 *      (Which descriptor sets it uses, which capabilities it declares, and
 *      whether it uses runtime arrays, NonUniform, or Int64.)
 *   2. PatchForVulkan11(): can this binary be made usable on a device
 *      WITHOUT descriptor indexing (Vulkan 1.1, no
 *      VK_EXT_descriptor_indexing)?
 *
 * Why v1 is audit + diagnose, not a full rewrite
 * ----------------------------------------------
 * The audit of the current translator (see batch README) proved that our
 * guest shaders already stay inside 4 descriptor sets, declare NO
 * descriptor-indexing capabilities, and use NO NonUniform and NO Int64.
 * There is nothing to rewrite today. A full Rayman-style rewrite (runtime
 * array -> fixed-size array + 1x1 placeholder fill) would have to rewrite
 * the SPIR-V TYPES, not just the capability declarations: stripping a
 * descriptor-indexing capability while the module still uses runtime arrays
 * or NonUniform would produce an INVALID shader, worse than the original.
 *
 * So PatchForVulkan11() v1 does the one rewrite that IS safe: it strips
 * OpCapability declarations for descriptor indexing ONLY when the module
 * declares them but never uses them (no OpTypeRuntimeArray, no NonUniform
 * decoration). If the module actually uses indexing, v1 refuses to rewrite
 * (returns false, no mutation) and the caller fails the shader with a clear
 * log line instead of letting vkCreateShaderModule fail opaquely. The real
 * type-rewriting pass belongs in a later batch, once a concrete invalid
 * binary is observed in a phone log.
 *
 * All SPIR-V word values below were verified against the vendored
 * SPIRV-Headers (thirdparty/spirv-headers/include/spirv/unified1/
 * spirv.hpp). They are defined here instead of including that header so
 * this file stays dependency-free and usable from unit tests.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace rex::graphics::spirv_patch {

namespace detail {
// SPIR-V magic number (first word of every binary).
constexpr uint32_t kMagicNumber = 0x07230203;

// Opcodes (SPIR-V core, stable since 1.0).
constexpr uint32_t kOpCapability = 17;
constexpr uint32_t kOpTypeRuntimeArray = 29;
constexpr uint32_t kOpDecorate = 71;
constexpr uint32_t kOpMemberDecorate = 72;

// Decorations.
constexpr uint32_t kDecorationBinding = 33;
constexpr uint32_t kDecorationDescriptorSet = 34;
constexpr uint32_t kDecorationNonUniform = 5300;

// Capabilities. NOTE: the descriptor-indexing family lives in the 53xx
// range (SPIR-V 1.3), NOT in the 44xx range — do not "fix" these from
// memory; they were verified against unified1/spirv.hpp.
constexpr uint32_t kCapabilityInt64 = 11;
constexpr uint32_t kCapabilityInt64Atomics = 12;
constexpr uint32_t kCapabilityShaderNonUniform = 5301;
constexpr uint32_t kCapabilityRuntimeDescriptorArray = 5302;
constexpr uint32_t kCapabilityUniformBufferArrayNonUniformIndexing = 5306;
constexpr uint32_t kCapabilitySampledImageArrayNonUniformIndexing = 5307;
constexpr uint32_t kCapabilityStorageBufferArrayNonUniformIndexing = 5308;
constexpr uint32_t kCapabilityStorageImageArrayNonUniformIndexing = 5309;
constexpr uint32_t kCapabilityInputAttachmentArrayNonUniformIndexing = 5310;
constexpr uint32_t kCapabilityUniformTexelBufferArrayNonUniformIndexing = 5311;
constexpr uint32_t kCapabilityStorageTexelBufferArrayNonUniformIndexing = 5312;
}  // namespace detail

inline bool IsDescriptorIndexingCapability(uint32_t capability) {
  using namespace detail;
  switch (capability) {
    case kCapabilityShaderNonUniform:
    case kCapabilityRuntimeDescriptorArray:
    case kCapabilityUniformBufferArrayNonUniformIndexing:
    case kCapabilitySampledImageArrayNonUniformIndexing:
    case kCapabilityStorageBufferArrayNonUniformIndexing:
    case kCapabilityStorageImageArrayNonUniformIndexing:
    case kCapabilityInputAttachmentArrayNonUniformIndexing:
    case kCapabilityUniformTexelBufferArrayNonUniformIndexing:
    case kCapabilityStorageTexelBufferArrayNonUniformIndexing:
      return true;
    default:
      return false;
  }
}

struct AuditResult {
  // False when the input is not a SPIR-V binary at all (bad magic, too
  // short, or a malformed instruction stream).
  bool valid = false;
  // SPIR-V version word (e.g. 0x00010300 = SPIR-V 1.3).
  uint32_t spirv_version = 0;
  // Highest DescriptorSet decoration seen (0 when the shader uses no
  // descriptor sets at all).
  uint32_t max_descriptor_set = 0;
  // Number of OpDecorate Binding seen (diagnostic only).
  uint32_t descriptor_binding_count = 0;
  // OpTypeRuntimeArray present. Legal on its own: our translator emits it
  // only as the last member of a shared-memory SSBO (core Vulkan 1.0).
  bool uses_runtime_array = false;
  // NonUniform decoration present.
  bool uses_non_uniform = false;
  // Int64 / Int64Atomics capability present.
  bool uses_int64 = false;
  // Any descriptor-indexing capability present.
  bool uses_descriptor_indexing = false;
  // First descriptor-indexing capability found (0 when none).
  uint32_t first_indexing_capability = 0;
};

// Read-only scan of a SPIR-V binary. Never modifies the input. Safe on
// truncated or invalid input (returns valid=false).
inline AuditResult Audit(const uint32_t* words, size_t word_count) {
  using namespace detail;
  AuditResult result;
  if (words == nullptr || word_count < 5 || words[0] != kMagicNumber) {
    return result;
  }
  result.valid = true;
  result.spirv_version = words[1];

  // Instructions start after the 5-word header.
  size_t i = 5;
  while (i < word_count) {
    const uint32_t instruction = words[i];
    const uint32_t word_count_instruction = instruction >> 16;
    const uint32_t opcode = instruction & 0xFFFF;
    // A zero word count (or one that runs past the end) is malformed.
    if (word_count_instruction == 0 || i + word_count_instruction > word_count) {
      result.valid = false;
      return result;
    }
    switch (opcode) {
      case kOpCapability: {
        if (word_count_instruction >= 2) {
          const uint32_t capability = words[i + 1];
          if (capability == kCapabilityInt64 ||
              capability == kCapabilityInt64Atomics) {
            result.uses_int64 = true;
          }
          if (IsDescriptorIndexingCapability(capability)) {
            result.uses_descriptor_indexing = true;
            if (result.first_indexing_capability == 0) {
              result.first_indexing_capability = capability;
            }
          }
        }
        break;
      }
      case kOpTypeRuntimeArray:
        result.uses_runtime_array = true;
        break;
      case kOpDecorate: {
        // Operands: target id, decoration, [literals...].
        if (word_count_instruction >= 3) {
          const uint32_t decoration = words[i + 2];
          if (decoration == kDecorationDescriptorSet &&
              word_count_instruction >= 4) {
            if (words[i + 3] > result.max_descriptor_set) {
              result.max_descriptor_set = words[i + 3];
            }
          } else if (decoration == kDecorationBinding) {
            ++result.descriptor_binding_count;
          } else if (decoration == kDecorationNonUniform) {
            result.uses_non_uniform = true;
          }
        }
        break;
      }
      case kOpMemberDecorate: {
                // Operands: struct type id, member index literal, decoration,
                // [literals...]. NOTE: unlike OpDecorate, the decoration is the
                // FOURTH word (words[i + 3]) — words[i + 2] is the member index,
                // not the decoration; reading words[i + 2] here would never match
                // NonUniform (and could misread a member index as a decoration).
                // (Caza v1.4.6 ronda 8, A1-R8-02.) NonUniform on a struct member
                // must count exactly like NonUniform on a whole variable: if the
                // module declares a descriptor-indexing capability, stripping it
                // while a member still carries NonUniform would leave an invalid
                // module, and PatchForVulkan11() must refuse instead. The
                // translator emits neither NonUniform nor OpMemberDecorate today,
                // so this changes no current audit result — defense in depth only.
                // Only NonUniform is scanned here: DescriptorSet/Binding apply to
                // variables, not struct members, so they cannot appear in
                // OpMemberDecorate.
                if (word_count_instruction >= 4 &&
                              words[i + 3] == kDecorationNonUniform) {
                            result.uses_non_uniform = true;
                }
                break;
      }
      default:
        break;
    }
    i += word_count_instruction;
  }
  return result;
}

// Tries to make a translated guest SPIR-V binary usable on a device WITHOUT
// descriptor indexing (Vulkan 1.1, no VK_EXT_descriptor_indexing).
//
// - Returns true when the binary is usable: either it never needed indexing,
//   or it only DECLARED indexing capabilities without using them (in that
//   case the unused OpCapability instructions are stripped in place and
//   *word_count is updated — the header and all IDs stay valid, only the
//   stream shortens).
// - Returns false when the binary actually USES descriptor indexing
//   (NonUniform decorations, or an indexing capability the module depends
//   on). v1 does NOT mutate the binary in that case: a real fix needs the
//   type rewrite (runtime array -> fixed-size array + placeholder fill, the
//   Rayman recipe), which is a later batch. The caller should fail the
//   shader with a clear log line. (A runtime array on its own is NOT a
//   blocker: as an SSBO payload it is core Vulkan 1.0.)
// - Returns false (no mutation) when the input is not a valid SPIR-V
//   binary.
inline bool PatchForVulkan11(uint32_t* words, size_t* word_count) {
  using namespace detail;
  if (words == nullptr || word_count == nullptr) {
    return false;
  }
  const AuditResult audit = Audit(words, *word_count);
  if (!audit.valid) {
    return false;
  }
  // The one case v1 can fix: capabilities declared but never used. If the
  // module uses NonUniform, stripping the capability would leave an invalid
  // module — refuse. A runtime array on its own does NOT block the strip:
  // our translator emits it only as the last member of a shared-memory
  // SSBO, which is core Vulkan 1.0 and does not depend on the indexing
  // capability (that capability is for arrays OF descriptors).
  if (audit.uses_non_uniform) {
    return false;
  }
  if (!audit.uses_descriptor_indexing) {
    return true;
  }
  // Strip every OpCapability for a descriptor-indexing capability, in
  // place, preserving instruction order. OpCapability is always exactly
  // 2 words: (2 << 16) | 17, capability.
  size_t read = 5;
  size_t write = 5;
  const size_t total = *word_count;
  while (read < total) {
    const uint32_t instruction = words[read];
    const uint32_t count = instruction >> 16;
    const uint32_t opcode = instruction & 0xFFFF;
    if (count == 0 || read + count > total) {
      return false;
    }
    const bool strip = opcode == kOpCapability && count == 2 &&
                       IsDescriptorIndexingCapability(words[read + 1]);
    if (!strip) {
      for (uint32_t w = 0; w < count; ++w) {
        words[write + w] = words[read + w];
      }
      write += count;
    }
    read += count;
  }
  *word_count = write;
  return true;
}

}  // namespace rex::graphics::spirv_patch
