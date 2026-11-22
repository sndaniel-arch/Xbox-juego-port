/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <atomic>
#include <cstdint>
#include <vector>

#include <rex/assert.h>
#include <rex/cvar.h>
#include <rex/graphics/pipeline/shader/spirv_patch.h>
#include <rex/graphics/vulkan/shader.h>
#include <rex/logging.h>
#include <rex/ui/vulkan/provider.h>

namespace rex::graphics::vulkan {

// (Batch 1 — descriptor-set audit.) Master switch for the SPIR-V rewrite
// (spirv_patch.h). Default false: with it off, only the read-only audit
// runs (zero behavior change); with it on, a shader that actually needs
// descriptor indexing fails here with a clear message instead of failing
// opaquely inside vkCreateShaderModule, and unused indexing capabilities
// are stripped. A full type rewrite (Rayman recipe) is a later batch.
REXCVAR_DEFINE_BOOL(spirv_patch_enable, false, "GPU/Shader",
                    "Run the SPIR-V patcher on translated guest shaders "
                    "before creating the Vulkan module: strip descriptor-"
                    "indexing capabilities a shader declares without using, "
                    "and refuse modules that actually need descriptor "
                    "indexing the device lacks. Off by default; the read-"
                    "only audit always runs.");

VulkanShader::VulkanTranslation::~VulkanTranslation() {
  if (shader_module_) {
    const ui::vulkan::VulkanDevice* const vulkan_device =
        static_cast<const VulkanShader&>(shader()).vulkan_device_;
    vulkan_device->functions().vkDestroyShaderModule(vulkan_device->device(), shader_module_,
                                                     nullptr);
  }
}

VkShaderModule VulkanShader::VulkanTranslation::GetOrCreateShaderModule() {
  if (!is_valid()) {
    return VK_NULL_HANDLE;
  }
  if (shader_module_ != VK_NULL_HANDLE) {
    return shader_module_;
  }
  const ui::vulkan::VulkanDevice* const vulkan_device =
      static_cast<const VulkanShader&>(shader()).vulkan_device_;
  // (Batch 1 — descriptor-set audit.) Audit the translated SPIR-V once per
  // module: version, descriptor sets used, capabilities. Read-only; the
  // audit itself never changes the binary. The first audited shader is
  // logged as proof the hook runs, and any shader that steps outside the
  // Vulkan 1.1 / 4-set world is logged too — with the current translator
  // that should never happen, so if one shows up in a phone log it is a
  // concrete case for the batch-2 type rewrite.
  {
    const auto audit = rex::graphics::spirv_patch::Audit(
        reinterpret_cast<const uint32_t*>(translated_binary().data()),
        translated_binary().size() / sizeof(uint32_t));
    // (Audit run #16, J-19; corregido en ronda 5, S-R5-01.)
    // GetOrCreateShaderModule only runs on the command processor thread
    // today (sole caller: VulkanPipelineCache::TranslateAnalyzedShader),
    // so no second thread can race on the plain static — the atomic
    // below is kept as cheap defense in depth for the log-once flag, not
    // because a live race exists. The check-then-set below can still log
    // the first audit twice (benign, log-only).
    static std::atomic<bool> logged_first_audit{false};
    const bool noteworthy =
        audit.valid && (audit.max_descriptor_set > 3 ||
                        audit.uses_descriptor_indexing ||
                        audit.uses_non_uniform || audit.uses_int64);
    if (!audit.valid) {
      REXLOG_WARN(
          "SpirvPatch: translated SPIR-V binary failed the audit (not a "
          "valid module); creating it unchanged");
    } else if (!logged_first_audit.load() || noteworthy) {
      logged_first_audit.store(true);
      REXLOG_INFO(
          "SpirvPatch: shader module SPIR-V {}.{} uses descriptor sets "
          "0..{}, {} bindings, runtime array: {}, NonUniform: {}, "
          "descriptor indexing: {}, Int64: {}",
          (audit.spirv_version >> 16) & 0xFF, (audit.spirv_version >> 8) & 0xFF,
          audit.max_descriptor_set, audit.descriptor_binding_count,
          audit.uses_runtime_array, audit.uses_non_uniform,
          audit.uses_descriptor_indexing, audit.uses_int64);
    }
  }

  // (Batch 1.) The rewrite runs only behind the spirv_patch_enable cvar
  // (default false = the original binary goes to vkCreateShaderModule
  // unchanged). When enabled, the binary is copied to a mutable buffer so
  // the patcher can strip unused indexing capabilities in place.
  std::vector<uint8_t> patched_binary;
  const uint8_t* module_bytes = translated_binary().data();
  size_t module_size = translated_binary().size();
  if (REXCVAR_GET(spirv_patch_enable)) {
    patched_binary = translated_binary();
    size_t word_count = patched_binary.size() / sizeof(uint32_t);
    if (!rex::graphics::spirv_patch::PatchForVulkan11(
            reinterpret_cast<uint32_t*>(patched_binary.data()), &word_count)) {
      REXLOG_ERROR(
          "SpirvPatch: guest shader needs descriptor indexing the device "
          "lacks (Vulkan 1.1, no VK_EXT_descriptor_indexing); refusing to "
          "create the module. A type rewrite (runtime array -> fixed-size "
          "array) is needed for this shader — see batch 1 README.");
      MakeInvalid();
      return VK_NULL_HANDLE;
    }
    module_size = word_count * sizeof(uint32_t);
    module_bytes = patched_binary.data();
  }

  VkShaderModuleCreateInfo shader_module_create_info;
  shader_module_create_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
  shader_module_create_info.pNext = nullptr;
  shader_module_create_info.flags = 0;
  shader_module_create_info.codeSize = module_size;
  shader_module_create_info.pCode = reinterpret_cast<const uint32_t*>(module_bytes);
  if (vulkan_device->functions().vkCreateShaderModule(vulkan_device->device(),
                                                      &shader_module_create_info, nullptr,
                                                      &shader_module_) != VK_SUCCESS) {
    REXGPU_ERROR(
        "VulkanShader::VulkanTranslation: Failed to create a Vulkan shader "
        "module for shader {:016X} modification {:016X}",
        shader().ucode_data_hash(), modification());
    // (Caza v1.4.6 ronda 5, S-R5-02.) Do NOT mark the translation
    // invalid here: unlike the spirv_patch rejection above (a
    // deterministic property of the SPIR-V), a failed
    // vkCreateShaderModule can be transient driver OOM
    // (VK_ERROR_OUT_OF_HOST_MEMORY / VK_ERROR_OUT_OF_DEVICE_MEMORY).
    // The translation itself is valid; only the module handle is
    // missing. Leaving is_valid_ true lets EnsureShadersTranslated
    // retry the module creation on the next call instead of poisoning
    // this shader forever; TryGet... refuses a valid translation with
    // no module yet, so no VK_NULL_HANDLE ever reaches pipeline
    // creation. shader_module_ stays VK_NULL_HANDLE on this path.
    return VK_NULL_HANDLE;
  }
  return shader_module_;
}

VulkanShader::VulkanShader(const ui::vulkan::VulkanDevice* const vulkan_device,
                           const xenos::ShaderType shader_type, const uint64_t ucode_data_hash,
                           const uint32_t* const ucode_dwords, const size_t ucode_dword_count,
                           const std::endian ucode_source_endian)
    : SpirvShader(shader_type, ucode_data_hash, ucode_dwords, ucode_dword_count,
                  ucode_source_endian),
      vulkan_device_(vulkan_device) {
  assert_not_null(vulkan_device);
}

Shader::Translation* VulkanShader::CreateTranslationInstance(uint64_t modification) {
  return new VulkanTranslation(*this, modification);
}

}  // namespace rex::graphics::vulkan
