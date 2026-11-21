#pragma once
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
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <rex/graphics/pipeline/shader/spirv_translator.h>
#include <rex/hash.h>
#include <rex/platform.h>
#include <rex/thread.h>
#include <rex/graphics/primitive_processor.h>
#include <rex/graphics/register_file.h>
#include <rex/graphics/registers.h>
#include <rex/graphics/vulkan/render_target_cache.h>
#include <rex/graphics/vulkan/shader.h>
#include <rex/graphics/xenos.h>
#include <rex/ui/vulkan/api.h>

namespace rex::graphics::vulkan {

class VulkanCommandProcessor;

// TODO(Triang3l): Create a common base for both the Vulkan and the Direct3D
// implementations.
class VulkanPipelineCache {
 public:
  static constexpr size_t kLayoutUIDEmpty = 0;

  class PipelineLayoutProvider {
   public:
    virtual ~PipelineLayoutProvider() {}
    virtual VkPipelineLayout GetPipelineLayout() const = 0;

   protected:
    PipelineLayoutProvider() = default;
  };

  VulkanPipelineCache(VulkanCommandProcessor& command_processor, const RegisterFile& register_file,
                      VulkanRenderTargetCache& render_target_cache,
                      VkShaderStageFlags guest_shader_vertex_stages);
  ~VulkanPipelineCache();

  bool Initialize();
  void Shutdown();
  void InitializeShaderStorage(const std::filesystem::path& cache_root, uint32_t title_id,
                               bool blocking);
  void ShutdownShaderStorage();
  // Driver pipeline cache (VkPipelineCache) persistence, see
  // pipeline_cache.cpp. LoadDriverPipelineCache seeds the cache from the
  // previous run; SaveDriverPipelineCache writes it back. Both are
  // fail-open: any failure leaves pipeline_cache_ null and pipeline
  // creation behaves exactly as before.
  void LoadDriverPipelineCache(const std::filesystem::path& shareable_root, uint32_t title_id);
  void SaveDriverPipelineCache();
  void EndSubmission();

  VulkanShader* LoadShader(xenos::ShaderType shader_type, const uint32_t* host_address,
                           uint32_t dword_count);
  // Analyze shader microcode on the translator thread.
  void AnalyzeShaderUcode(Shader& shader) { shader.AnalyzeUcode(ucode_disasm_buffer_); }

  // Retrieves the shader modification for the current state. The shader must
  // have microcode analyzed.
  SpirvShaderTranslator::Modification GetCurrentVertexShaderModification(
      const Shader& shader, Shader::HostVertexShaderType host_vertex_shader_type,
      uint32_t interpolator_mask, bool ps_param_gen_used) const;
  SpirvShaderTranslator::Modification GetCurrentPixelShaderModification(
      const Shader& shader, uint32_t interpolator_mask, uint32_t param_gen_pos,
      reg::RB_DEPTHCONTROL normalized_depth_control) const;

  bool EnsureShadersTranslated(VulkanShader::VulkanTranslation* vertex_shader,
                               VulkanShader::VulkanTranslation* pixel_shader);
  // TODO(Triang3l): Return a deferred creation handle.
  bool ConfigurePipeline(
      VulkanShader::VulkanTranslation* vertex_shader, VulkanShader::VulkanTranslation* pixel_shader,
      const PrimitiveProcessor::ProcessingResult& primitive_processing_result,
      reg::RB_DEPTHCONTROL normalized_depth_control, uint32_t normalized_color_mask,
      VulkanRenderTargetCache::RenderPassKey render_pass_key, VkPipeline& pipeline_out,
      const PipelineLayoutProvider*& pipeline_layout_out, void** pipeline_handle_out = nullptr,
      // (Caza ronda 8, auditor C, R8-C1.) Set to true when this call returns
      // false only because a previous creation failure for this pipeline is
      // still inside its retry cooldown (see Pipeline::
      // last_creation_failure_submission_): the caller must then fail the
      // draw silently instead of logging another draw_fail line for it.
      bool* creation_failure_throttled_out = nullptr);
  bool IsCreatingPipelines() const;
  void GetPipelineAndLayoutByHandle(void* handle, VkPipeline& pipeline_out,
                                    const PipelineLayoutProvider*& pipeline_layout_out,
                                    bool* is_placeholder_out = nullptr) const;
  // (Caza ronda 16, auditor D, R16-D1.) Counts one skipped draw for the
  // pipeline behind `handle` (a const Pipeline*, as handed out by
  // ConfigurePipeline) and returns its per-pipeline throttle index
  // (first 8 + every 1024th OF THIS PIPELINE). Called only from the
  // IssueDraw skip branch, so it counts exactly skipped draws. Returns
  // 0 for a null handle.
  uint32_t CountSkippedPlaceholderDraw(void* handle) const;

 private:
  REXPACKEDSTRUCT(ShaderStoredHeader, {
    uint64_t ucode_data_hash;

    uint32_t ucode_dword_count : 31;
    xenos::ShaderType type : 1;

    static constexpr uint32_t kVersion = 0x20201219;
  });

  enum class PipelineGeometryShader : uint32_t {
    kNone,
    kPointList,
    kRectangleList,
    kQuadList,
  };

  enum class PipelinePrimitiveTopology : uint32_t {
    kPointList,
    kLineList,
    kLineStrip,
    kTriangleList,
    kTriangleStrip,
    kTriangleFan,
    kLineListWithAdjacency,
    kPatchList,
  };

  enum class PipelinePolygonMode : uint32_t {
    kFill,
    kLine,
    kPoint,
  };

  enum class PipelineBlendFactor : uint32_t {
    kZero,
    kOne,
    kSrcColor,
    kOneMinusSrcColor,
    kDstColor,
    kOneMinusDstColor,
    kSrcAlpha,
    kOneMinusSrcAlpha,
    kDstAlpha,
    kOneMinusDstAlpha,
    kConstantColor,
    kOneMinusConstantColor,
    kConstantAlpha,
    kOneMinusConstantAlpha,
    kSrcAlphaSaturate,
  };

  // Update PipelineDescription::kVersion if anything is changed!
  REXPACKEDSTRUCT(PipelineRenderTarget, {
    PipelineBlendFactor src_color_blend_factor : 4;  // 4
    PipelineBlendFactor dst_color_blend_factor : 4;  // 8
    xenos::BlendOp color_blend_op : 3;               // 11
    PipelineBlendFactor src_alpha_blend_factor : 4;  // 15
    PipelineBlendFactor dst_alpha_blend_factor : 4;  // 19
    xenos::BlendOp alpha_blend_op : 3;               // 22
    uint32_t color_write_mask : 4;                   // 26
  });

  REXPACKEDSTRUCT(PipelineDescription, {
    uint64_t vertex_shader_hash;
    uint64_t vertex_shader_modification;
    // 0 if no pixel shader.
    uint64_t pixel_shader_hash;
    uint64_t pixel_shader_modification;
    VulkanRenderTargetCache::RenderPassKey render_pass_key;

    // Shader stages.
    PipelineGeometryShader geometry_shader : 2;  // 2
    // Input assembly.
    PipelinePrimitiveTopology primitive_topology : 3;  // 5
    uint32_t primitive_restart : 1;                    // 6
    xenos::TessellationMode tessellation_mode : 2;     // 8
    // Rasterization.
    uint32_t depth_clamp_enable : 1;       // 9
    PipelinePolygonMode polygon_mode : 2;  // 11
    uint32_t cull_front : 1;               // 12
    uint32_t cull_back : 1;                // 13
    uint32_t front_face_clockwise : 1;     // 14
    uint32_t rasterizer_discard : 1;       // 15
    // Depth / stencil.
    uint32_t depth_write_enable : 1;                      // 16
    xenos::CompareFunction depth_compare_op : 3;          // 19
    uint32_t stencil_test_enable : 1;                     // 20
    xenos::StencilOp stencil_front_fail_op : 3;           // 23
    xenos::StencilOp stencil_front_pass_op : 3;           // 26
    xenos::StencilOp stencil_front_depth_fail_op : 3;     // 29
    xenos::CompareFunction stencil_front_compare_op : 3;  // 32
    xenos::StencilOp stencil_back_fail_op : 3;            // 35

    xenos::StencilOp stencil_back_pass_op : 3;           // 3
    xenos::StencilOp stencil_back_depth_fail_op : 3;     // 6
    xenos::CompareFunction stencil_back_compare_op : 3;  // 9
    uint32_t sample_rate_shading : 1;                    // 10

    // Filled only for the attachments present in the render pass object.
    PipelineRenderTarget render_targets[xenos::kMaxColorRenderTargets];

    // Including all the padding, for a stable hash.
    static constexpr uint32_t kVersion = 0x20260228;
    PipelineDescription() {
      Reset();
    }
    PipelineDescription(const PipelineDescription& description) {
      std::memcpy(this, &description, sizeof(*this));
    }
    PipelineDescription& operator=(const PipelineDescription& description) {
      std::memcpy(this, &description, sizeof(*this));
      return *this;
    }
    bool operator==(const PipelineDescription& description) const {
      return std::memcmp(this, &description, sizeof(*this)) == 0;
    }
    void Reset() {
      std::memset(this, 0, sizeof(*this));
    }
    uint64_t GetHash() const {
      return XXH3_64bits(this, sizeof(*this));
    }
    struct Hasher {
      size_t operator()(const PipelineDescription& description) const {
        return size_t(description.GetHash());
      }
    };
  });
  REXPACKEDSTRUCT(PipelineStoredDescription, {
    uint64_t description_hash;
    PipelineDescription description;
  });

  struct Pipeline {
    std::atomic<VkPipeline> pipeline{VK_NULL_HANDLE};
    // The layouts are owned by the VulkanCommandProcessor, and must not be
    // destroyed by it while the pipeline cache is active.
    std::atomic<const PipelineLayoutProvider*> pipeline_layout{nullptr};
    std::atomic<bool> is_placeholder{false};
    // (Caza ronda 9, auditor C, R9-C1.) Set when a real creation failed
    // while a placeholder was resident (CreationThread or
    // CreateQueuedPipelinesOnProcessorThread): the placeholder stays
    // resident and keeps being drawn (is_placeholder is still cleared,
    // as before), but ConfigurePipeline re-attempts the real creation
    // once the R8-C1 retry cooldown has expired, instead of rendering
    // the trivial placeholder shader forever (R8-C4). Written by the
    // worker and drain threads as well as read on the processor thread,
    // so it is atomic; the retry cooldown stamp itself
    // (last_creation_failure_submission_) is still only written on the
    // processor thread.
    std::atomic<bool> placeholder_creation_failed{false};
    // (Caza ronda 15, auditor D, R15-D1.) Per-pipeline throttle counter
    // for the R14-D1 WARN (draws binding a failed placeholder): the
    // counter used to be a single process-global static inside
    // ConfigurePipeline, so its first-8 window was consumed by whichever
    // pipelines failed first during warmup, and a pipeline that got stuck
    // later (e.g. in the lake scene) only logged every 1024th failed
    // draw GLOBALLY -- B-n could read zero lines after seconds of staring
    // at the hole and wrongly discard failed placeholders as the cause.
    // Each entry now counts its own draws (first 8 + every 1024th OF
    // THIS PIPELINE). mutable: last_pipeline_ is a const pair, so the
    // fast path in ConfigurePipeline only has const access to the entry.
    // Copied in the copy ctor / assignment below like the other atomics;
    // reset to 0 when the retry succeeds (flag cleared), so the counter
    // is 0 whenever placeholder_creation_failed is false.
    mutable std::atomic<uint32_t> drawn_failed_placeholder_count{0};
    // (Caza ronda 16, auditor D, R16-D1.) Per-pipeline throttle counter
    // for the R13-D1 WARN (draws SKIPPED while their pipeline is still a
    // placeholder): the counter used to be a single process-global static
    // inside IssueDraw, so its first-8 window was consumed by whichever
    // pipelines skipped first during warmup, and a pipeline that got stuck
    // on its placeholder later (e.g. deep in the creation queue in a new
    // scene) only logged every 1024th skipped draw GLOBALLY -- B-m could
    // read zero lines after seconds of staring at the hole and wrongly
    // discard stuck placeholders as the cause (same dilution R15-D1 fixed
    // for B-n, now B-o). Each entry now counts its own skipped draws
    // (first 8 + every 1024th OF THIS PIPELINE), counted by
    // CountSkippedPlaceholderDraw(), called only from the IssueDraw skip
    // branch. mutable: GetPipelineAndLayoutByHandle hands IssueDraw a
    // const Pipeline* handle, and the counter is only ever touched
    // through that const handle. Copied in the copy ctor / assignment
    // below like the other atomics. No reset: an entry has a single
    // observable placeholder episode -- it becomes a placeholder once,
    // at creation, and is_placeholder clears for good when the real
    // creation lands (the re-mark inside ConfigurePipeline's retry
    // branch is transient within that one call and never produces a
    // skip); the counter is born 0 with the entry, so the first 8
    // skipped draws of the episode always log.
    mutable std::atomic<uint32_t> skipped_placeholder_draw_count{0};
    // (Caza ronda 8, auditor C, R8-C1.) Submission index of the last failed
    // synchronous creation attempt for this pipeline (ConfigurePipeline),
    // or kNoCreationFailure when no failure is recorded. A pipeline whose
    // creation fails deterministically (bad description, driver rejecting
    // it, the R5-E1 independentBlend gate) used to be retried on EVERY draw
    // that referenced it -- one full vkCreateGraphicsPipelines plus up to
    // three unthrottled REXGPU_ERROR lines per draw, forever -- because the
    // entry was erased on failure and re-created on the next draw. The
    // stamp makes the retry back off for
    // kFailedPipelineCreationRetryCooldownSubmissions (see
    // ConfigurePipeline); it is only ever written on the GPU command
    // processor thread, like the rest of ConfigurePipeline, so it needs no
    // atomic. A successful creation clears it.
    static constexpr uint64_t kNoCreationFailure = UINT64_MAX;
    uint64_t last_creation_failure_submission_ = kNoCreationFailure;
    Pipeline() = default;
    Pipeline(const PipelineLayoutProvider* pipeline_layout_provider)
        : pipeline_layout(pipeline_layout_provider) {}
    Pipeline(const Pipeline& other)
        : pipeline(other.pipeline.load(std::memory_order_acquire)),
          pipeline_layout(other.pipeline_layout.load(std::memory_order_acquire)),
          is_placeholder(other.is_placeholder.load(std::memory_order_acquire)),
          placeholder_creation_failed(
              other.placeholder_creation_failed.load(std::memory_order_acquire)),
          drawn_failed_placeholder_count(
              other.drawn_failed_placeholder_count.load(std::memory_order_acquire)),
          skipped_placeholder_draw_count(
              other.skipped_placeholder_draw_count.load(std::memory_order_acquire)),
          last_creation_failure_submission_(other.last_creation_failure_submission_) {}
    Pipeline& operator=(const Pipeline& other) {
      if (this == &other) {
        return *this;
      }
      pipeline.store(other.pipeline.load(std::memory_order_acquire), std::memory_order_release);
      pipeline_layout.store(other.pipeline_layout.load(std::memory_order_acquire),
                            std::memory_order_release);
      is_placeholder.store(other.is_placeholder.load(std::memory_order_acquire),
                           std::memory_order_release);
      placeholder_creation_failed.store(
          other.placeholder_creation_failed.load(std::memory_order_acquire),
          std::memory_order_release);
      drawn_failed_placeholder_count.store(
          other.drawn_failed_placeholder_count.load(std::memory_order_acquire),
          std::memory_order_release);
      skipped_placeholder_draw_count.store(
          other.skipped_placeholder_draw_count.load(std::memory_order_acquire),
          std::memory_order_release);
      last_creation_failure_submission_ = other.last_creation_failure_submission_;
      return *this;
    }
  };

  // Description that can be passed from the command processor thread to the
  // creation threads, with everything needed from caches pre-looked-up.
  struct PipelineCreationArguments {
    uint8_t priority = 0;
    std::pair<const PipelineDescription, Pipeline>* pipeline = nullptr;
    const PipelineLayoutProvider* pipeline_layout = nullptr;
    // Guest shader translation (VS or TES depending on host vertex type).
    const VulkanShader::VulkanTranslation* vertex_shader = nullptr;
    const VulkanShader::VulkanTranslation* pixel_shader = nullptr;
    // Non-guest stages for tessellation.
    VkShaderModule tessellation_vertex_shader = VK_NULL_HANDLE;
    VkShaderModule tessellation_control_shader = VK_NULL_HANDLE;
    uint32_t tessellation_patch_control_points = 0;
    VkShaderModule geometry_shader = VK_NULL_HANDLE;
    // VK_NULL_HANDLE when dynamic rendering is used.
    VkRenderPass render_pass = VK_NULL_HANDLE;
  };
  struct PipelineCreationArgumentsPriorityComparator {
    bool operator()(const PipelineCreationArguments& a, const PipelineCreationArguments& b) const {
      return a.priority < b.priority;
    }
  };

  union TessellationControlShaderKey {
    uint32_t key;
    struct {
      Shader::HostVertexShaderType host_vertex_shader_type : Shader::kHostVertexShaderTypeBitCount;
      xenos::TessellationMode tessellation_mode : 2;
    };

    TessellationControlShaderKey() : key(0) { static_assert_size(*this, sizeof(key)); }

    struct Hasher {
      size_t operator()(const TessellationControlShaderKey& key) const {
        return std::hash<uint32_t>{}(key.key);
      }
    };
    bool operator==(const TessellationControlShaderKey& other_key) const {
      return key == other_key.key;
    }
  };

  union GeometryShaderKey {
    uint32_t key;
    struct {
      PipelineGeometryShader type : 2;
      uint32_t interpolator_count : 5;
      uint32_t user_clip_plane_count : 3;
      uint32_t user_clip_plane_cull : 1;
      uint32_t has_vertex_kill_and : 1;
      uint32_t has_point_size : 1;
      uint32_t has_point_coordinates : 1;
      // PA_CL_CLIP_CNTL::ps_ucp_mode for point primitives.
      uint32_t point_ps_ucp_mode : 2;
    };

    GeometryShaderKey() : key(0) { static_assert_size(*this, sizeof(key)); }

    struct Hasher {
      size_t operator()(const GeometryShaderKey& key) const {
        return std::hash<uint32_t>{}(key.key);
      }
    };
    bool operator==(const GeometryShaderKey& other_key) const { return key == other_key.key; }
    bool operator!=(const GeometryShaderKey& other_key) const { return !(*this == other_key); }
  };

  VulkanShader* LoadShader(xenos::ShaderType shader_type, const uint32_t* host_address,
                           uint32_t dword_count, uint64_t data_hash);

  // Can be called from multiple threads.
  bool TranslateAnalyzedShader(SpirvShaderTranslator& translator,
                               VulkanShader::VulkanTranslation& translation);

  void WritePipelineRenderTargetDescription(reg::RB_BLENDCONTROL blend_control, uint32_t write_mask,
                                            PipelineRenderTarget& render_target_out) const;
  bool GetCurrentStateDescription(
      const VulkanShader::VulkanTranslation* vertex_shader,
      const VulkanShader::VulkanTranslation* pixel_shader,
      const PrimitiveProcessor::ProcessingResult& primitive_processing_result,
      reg::RB_DEPTHCONTROL normalized_depth_control, uint32_t normalized_color_mask,
      VulkanRenderTargetCache::RenderPassKey render_pass_key,
      PipelineDescription& description_out) const;

  // Whether the pipeline for the given description is supported by the device.
  bool ArePipelineRequirementsMet(const PipelineDescription& description) const;

  static bool GetGeometryShaderKey(PipelineGeometryShader geometry_shader_type,
                                   SpirvShaderTranslator::Modification vertex_shader_modification,
                                   SpirvShaderTranslator::Modification pixel_shader_modification,
                                   GeometryShaderKey& key_out);
  static uint32_t GetTessellationPatchControlPointCount(
      Shader::HostVertexShaderType host_vertex_shader_type,
      xenos::TessellationMode tessellation_mode);
  VkShaderModule GetTessellationVertexShader(bool adaptive);
  VkShaderModule GetTessellationControlShader(Shader::HostVertexShaderType host_vertex_shader_type,
                                              xenos::TessellationMode tessellation_mode);
  VkShaderModule GetGeometryShader(GeometryShaderKey key);
  bool TryGetPipelineCreationArgumentsForDescription(
      const PipelineDescription& description,
      std::pair<const PipelineDescription, Pipeline>* pipeline,
      PipelineCreationArguments& creation_arguments, bool for_placeholder = false);

  // Can be called from creation threads - all needed data must be fully set up
  // at the point of the call: shaders must be translated, and the pipeline
  // layout and render pass object (unless dynamic rendering is used) must be
  // available.
  bool EnsurePipelineCreated(const PipelineCreationArguments& creation_arguments,
                             VkShaderModule fragment_shader_override = VK_NULL_HANDLE);
  void CreationThread(size_t thread_index);
  void CreateQueuedPipelinesOnProcessorThread();
  // (Caza ronda 11, auditor C, R11-C1.) Consumes one unit of the
  // per-submission budget for synchronous real-pipeline creation attempts
  // in ConfigurePipeline (see synchronous_retry_budget_submission_ below):
  // at most one retry per submission, shared by the null-handle path and
  // the placeholder retry path. Processor thread only, like the rest of
  // ConfigurePipeline.
  bool ConsumeSynchronousRetryBudget(uint64_t current_submission);
  void ProcessDeferredPipelineDestructions(bool force_all);

  VulkanCommandProcessor& command_processor_;
  const RegisterFile& register_file_;
  VulkanRenderTargetCache& render_target_cache_;
  VkShaderStageFlags guest_shader_vertex_stages_;

  // Temporary storage for AnalyzeUcode calls on the processor thread.
  string::StringBuffer ucode_disasm_buffer_;
  // Reusable shader translator on the command processor thread.
  std::unique_ptr<SpirvShaderTranslator> shader_translator_;

  struct LayoutUID {
    size_t uid;
    size_t vector_span_offset;
    size_t vector_span_length;
  };
  std::mutex layouts_mutex_;
  // Texture binding layouts of different shaders, for obtaining layout UIDs.
  std::vector<VulkanShader::TextureBinding> texture_binding_layouts_;
  // Map of texture binding layouts used by shaders, for obtaining UIDs. Keys
  // are XXH3 hashes of layouts, values need manual collision resolution using
  // layout_vector_offset:layout_length of texture_binding_layouts_.
  std::unordered_multimap<uint64_t, LayoutUID, rex::IdentityHasher<uint64_t>>
      texture_binding_layout_map_;

  // Ucode hash -> shader.
  std::unordered_map<uint64_t, VulkanShader*, rex::IdentityHasher<uint64_t>> shaders_;

  // (Caza v1.4.6 ronda 4, A1-R4-01; corregido en ronda 5, S-R5-01.)
  // GetTessellationVertexShader, GetTessellationControlShader and
  // GetGeometryShader below only run on the command processor thread
  // today: they are reached from TryGetPipelineCreationArgumentsForDescription
  // (ConfigurePipeline / IssueDraw, and InitializeShaderStorage), never
  // from the pipeline creation threads — EnsurePipelineCreated only
  // consumes the pre-looked-up arguments, so the race A1-R4-01 assumed
  // never existed. The mutex stays as defense in depth: it serializes the
  // lazy caches if these getters ever move off the processor thread, and
  // it is never contended today. One mutex for the three caches: the
  // getters never call each other, and the shader compile / module
  // creation inside does not call back into this cache, so holding it
  // across the creation is deadlock-free.
// (V-A1-01, same round, second sweep: layouts_mutex_ below is also
  // taken for the texture-binding-layout map in TranslateAnalyzedShader.)
  std::mutex lazy_shader_cache_mutex_;

  // Geometry shaders for Xenos primitive types not supported by Vulkan.
  // Stores VK_NULL_HANDLE if failed to create.
  std::unordered_map<GeometryShaderKey, VkShaderModule, GeometryShaderKey::Hasher>
      geometry_shaders_;

  // Fixed-function emulation shaders for tessellation.
  bool tessellation_indexed_vertex_shader_attempted_ = false;
  VkShaderModule tessellation_indexed_vertex_shader_ = VK_NULL_HANDLE;
  bool tessellation_adaptive_vertex_shader_attempted_ = false;
  VkShaderModule tessellation_adaptive_vertex_shader_ = VK_NULL_HANDLE;
  std::unordered_map<TessellationControlShaderKey, VkShaderModule,
                     TessellationControlShaderKey::Hasher>
      tessellation_control_shaders_;

  // Empty depth-only pixel shader for writing to depth buffer using fragment
  // shader interlock when no Xenos pixel shader provided.
  VkShaderModule depth_only_fragment_shader_ = VK_NULL_HANDLE;
  VkShaderModule placeholder_pixel_shader_ = VK_NULL_HANDLE;
  // Depth-only shaders for float24 emulation when no Xenos pixel shader is
  // provided in host render target mode.
  VkShaderModule depth_float24_truncate_fragment_shader_ = VK_NULL_HANDLE;
  VkShaderModule depth_float24_round_fragment_shader_ = VK_NULL_HANDLE;

  std::unordered_map<PipelineDescription, Pipeline, PipelineDescription::Hasher> pipelines_;

  // Previously used pipeline, to avoid lookups if the state wasn't changed.
  const std::pair<const PipelineDescription, Pipeline>* last_pipeline_ = nullptr;
  // (Caza ronda 11, auditor C, R11-C1.) Per-submission budget for
  // synchronous real-pipeline creation attempts in ConfigurePipeline
  // (null-handle path + placeholder retry path). The per-pipeline
  // cooldown (60 submissions, R8-C1) bounds retries per pipeline, but
  // with R10-A1 making the placeholder retry real, N distinct pipelines
  // whose cooldown expired together could each pay one synchronous
  // vkCreateGraphicsPipelines in the same submission, on top of the
  // drain's 4 (R6-C1) -- a hitch proportional to the burst. One retry
  // per submission keeps the draw path's share at one synchronous
  // creation; the rest stay due (stamp untouched) and retry in later
  // submissions, one per submission, while their placeholders keep
  // rendering. Processor thread only, like last_pipeline_ and the
  // retry stamp, so plain (non-atomic) members.
  uint64_t synchronous_retry_budget_submission_ = 0;
  uint32_t synchronous_retries_this_submission_ = 0;
  // <Submission index, pipeline>. The index is the submission after which
  // the pipeline may be destroyed (ProcessDeferredPipelineDestructions
  // destroys when index <= completed submission; the queue is sorted by
  // index).
  // (Audit BL-2.) Entries are stamped by the command-processor thread,
  // not by the creation worker: EnsurePipelineCreated enqueues with
  // kDeferredDestroyUnstamped and EndSubmission stamps it with
  // GetCurrentSubmission() on first sight. GetCurrentSubmission() reads
  // submission_completed_ (plain uint64_t) + submissions_in_flight_fences_
  // .size() (plain vector), both mutated only by the CP thread, so the
  // worker cannot call it (a torn/low stamp destroys a pipeline the GPU
  // still uses; an out-of-order stamp leaks entries). Stamping in
  // TryGetPipelineCreationArgumentsForDescription would be too early:
  // the old placeholder keeps rendering in later submissions until the
  // real pipeline is installed, so only a stamp taken at/after the
  // install is safe. The CP-side stamp is taken later still, which only
  // delays the destroy by at most one submission.
  static constexpr uint64_t kDeferredDestroyUnstamped = UINT64_MAX;
  std::deque<std::pair<uint64_t, VkPipeline>> deferred_destroy_pipelines_;
  std::mutex deferred_destroy_lock_;

  // Currently open shader storage path.
  std::filesystem::path shader_storage_cache_root_;
  uint32_t shader_storage_title_id_ = 0;

  // Shader storage output stream, for preload in the next emulator runs.
  FILE* shader_storage_file_ = nullptr;
  // For only writing shaders to the currently open storage once, incremented
  // when switching the storage.
  uint32_t shader_storage_index_ = 0;
  bool shader_storage_file_flush_needed_ = false;

  // Pipeline storage output stream, for preload in the next emulator runs.
  FILE* pipeline_storage_file_ = nullptr;
  bool pipeline_storage_file_flush_needed_ = false;

  // Driver pipeline cache object (VkPipelineCache), created empty in
  // Initialize(), optionally seeded from disk in InitializeShaderStorage(),
  // and saved back in ShutdownShaderStorage(). Null means "no driver
  // cache", which is the historical behavior.
  VkPipelineCache pipeline_cache_ = VK_NULL_HANDLE;
  bool driver_pipeline_cache_loaded_from_storage_ = false;

  // (Caza ronda 6, auditor C, R6-C2.) Bookkeeping for the periodic driver
  // pipeline cache save in EndSubmission(): until now the blob was only
  // saved at shutdown / after the preload (R5-C1), so pipelines created
  // mid-session were lost on a crash. The baseline is (re)set by the R5-C1
  // save in InitializeShaderStorage() and cleared in
  // ShutdownShaderStorage().
  std::chrono::steady_clock::time_point last_driver_cache_save_time_{};
  size_t last_driver_cache_save_pipeline_count_ = 0;
  // (Caza ronda 9, auditor C, R9-C2.) Number of pipelines successfully
  // created (placeholder and real alike: both are real
  // vkCreateGraphicsPipelines calls, so both land in the driver cache
  // blob). The periodic-save gate in EndSubmission() counts these
  // instead of pipelines_.size(): since R8-C1, entries whose creation
  // failed stay in the map forever, so size() also grows for pipelines
  // that never entered the blob, and every minute with a new failing
  // pipeline rewrote the unchanged blob to flash. Deliberately never
  // reset: the baselines assigned in InitializeShaderStorage() and
  // EndSubmission() absorb its value, which mirrors the old size()
  // behavior after a re-init and avoids a lost-increment race with
  // creation threads still running on the re-init path.
  std::atomic<size_t> pipelines_created_count_{0};

  // Thread for asynchronous writing to the storage streams.
  void StorageWriteThread();
  std::mutex storage_write_request_lock_;
  std::condition_variable storage_write_request_cond_;
  // Storage thread input is protected with storage_write_request_lock_, and the
  // thread is notified about its change via storage_write_request_cond_.
  std::deque<const Shader*> storage_write_shader_queue_;
  std::deque<PipelineStoredDescription> storage_write_pipeline_queue_;
  bool storage_write_flush_shaders_ = false;
  bool storage_write_flush_pipelines_ = false;
  bool storage_write_thread_shutdown_ = false;
  std::unique_ptr<rex::thread::Thread> storage_write_thread_;

  mutable std::mutex creation_request_lock_;
  std::condition_variable creation_request_cond_;
  std::priority_queue<PipelineCreationArguments, std::vector<PipelineCreationArguments>,
                      PipelineCreationArgumentsPriorityComparator>
      creation_queue_;
  size_t creation_threads_busy_ = 0;
  bool startup_loading_ = false;
  std::unique_ptr<rex::thread::Event> creation_completion_event_;
  bool creation_completion_set_event_ = false;
  size_t creation_threads_shutdown_from_ = SIZE_MAX;
  std::vector<std::unique_ptr<rex::thread::Thread>> creation_threads_;
};

}  // namespace rex::graphics::vulkan
