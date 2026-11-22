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

#include <array>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <rex/graphics/pipeline/texture/cache.h>
#include <rex/graphics/vulkan/shader.h>
#include <rex/graphics/vulkan/shared_memory.h>
#include <rex/hash.h>
#include <rex/ui/vulkan/mem_alloc.h>
#include <rex/ui/vulkan/upload_buffer_pool.h>

namespace rex::graphics::vulkan {

class VulkanCommandProcessor;

class VulkanTextureCache final : public TextureCache {
 public:
  // Sampler parameters that can be directly converted to a host sampler or used
  // for checking whether samplers bindings are up to date.
  union SamplerParameters {
    uint32_t value;
    struct {
      xenos::ClampMode clamp_x : 3;         // 3
      xenos::ClampMode clamp_y : 3;         // 6
      xenos::ClampMode clamp_z : 3;         // 9
      xenos::BorderColor border_color : 2;  // 11
      uint32_t mag_linear : 1;              // 12
      uint32_t min_linear : 1;              // 13
      uint32_t mip_linear : 1;              // 14
      xenos::AnisoFilter aniso_filter : 3;  // 17
      uint32_t mip_min_level : 4;           // 21
      uint32_t mip_base_map : 1;            // 22
      // Maximum mip level is in the texture resource itself, but mip_base_map
      // can be used to limit fetching to mip_min_level.
    };

    SamplerParameters() : value(0) { static_assert_size(*this, sizeof(value)); }
    struct Hasher {
      size_t operator()(const SamplerParameters& parameters) const {
        return std::hash<uint32_t>{}(parameters.value);
      }
    };
    bool operator==(const SamplerParameters& parameters) const { return value == parameters.value; }
    bool operator!=(const SamplerParameters& parameters) const { return value != parameters.value; }
  };

  // Transient descriptor set layouts must be initialized in the command
  // processor.
  static std::unique_ptr<VulkanTextureCache> Create(
      const RegisterFile& register_file, VulkanSharedMemory& shared_memory,
      uint32_t draw_resolution_scale_x, uint32_t draw_resolution_scale_y,
      VulkanCommandProcessor& command_processor,
      VkPipelineStageFlags guest_shader_pipeline_stages) {
    std::unique_ptr<VulkanTextureCache> texture_cache(new VulkanTextureCache(
        register_file, shared_memory, draw_resolution_scale_x, draw_resolution_scale_y,
        command_processor, guest_shader_pipeline_stages));
    if (!texture_cache->Initialize()) {
      return nullptr;
    }
    return std::move(texture_cache);
  }

  ~VulkanTextureCache();

  void BeginSubmission(uint64_t new_submission_index) override;
  void BeginFrame() override;
  void EndFrame();
  void ClearCache() override;
  void OnTextureEvicted(const TextureKey& key) override;

  // Must be called within a frame - creates and untiles textures needed by
  // shaders, and enqueues transitioning them into the sampled usage. This may
  // bind compute pipelines (notifying the command processor about that), and
  // also since it may insert deferred barriers, before flushing the barriers
  // preceding host GPU work.
  void RequestTextures(uint32_t used_texture_mask) override;

  VkImageView GetActiveBindingOrNullImageView(uint32_t fetch_constant_index,
                                              xenos::FetchOpDimension dimension, bool is_signed);

  SamplerParameters GetSamplerParameters(const VulkanShader::SamplerBinding& binding) const;

  // Must be called for every used sampler at least once in a single submission,
  // and a submission must be open for this to be callable.
  // Returns:
  // - The sampler, if obtained successfully - and increases its last usage
  //   submission index - and has_overflown_out = false.
  // - VK_NULL_HANDLE and has_overflown_out = true if there's a total sampler
  //   count overflow in a submission that potentially hasn't completed yet.
  // - VK_NULL_HANDLE and has_overflown_out = false in case of a general failure
  //   to create a sampler.
  VkSampler UseSampler(SamplerParameters parameters, bool& has_overflown_out);
  // Returns the submission index to await (may be the current submission in
  // case of an overflow within a single submission - in this case, it must be
  // ended, and a new one must be started) in case of sampler count overflow, so
  // samplers may be freed, and UseSamplers may take their slots.
  uint64_t GetSubmissionToAwaitOnSamplerOverflow(uint32_t overflowed_sampler_count) const;

  // Returns the 2D view of the front buffer texture (for fragment shader
  // reading - the barrier will be pushed in the command processor if needed),
  // or VK_NULL_HANDLE in case of failure. May call LoadTextureData.
  // (Hunt v1.4.6 round 5, T-R5-03.) If the frontbuffer cannot be loaded, the
  // 1x1 null image (plain 2D view) is served instead of VK_NULL_HANDLE, so
  // the present still runs and shows a degraded (black) frame rather than
  // aborting the present on every frame. The texture stays outdated, so the
  // next frame retries the load.
  // If swap_source_needs_rb_swap_out is not nullptr, writes whether the final
  // guest-to-host swizzle requires swapping red and blue (R <- B, B <- R) with
  // green preserved, which is needed by the presentation fallback path on
  // devices without imageViewFormatSwizzle.
  VkImageView RequestSwapTexture(uint32_t& width_scaled_out, uint32_t& height_scaled_out,
                                 xenos::TextureFormat& format_out,
                                 uint32_t* width_unscaled_out = nullptr,
                                 uint32_t* height_unscaled_out = nullptr,
                                 bool* swap_source_needs_rb_swap_out = nullptr);

  bool GetScaledResolveRange(uint32_t start_unscaled, uint32_t length_unscaled,
                             uint32_t length_scaled_alignment_log2, uint64_t& start_scaled_out,
                             uint64_t& length_scaled_out) const;
  bool CommitScaledResolveRange(uint32_t start_unscaled, uint32_t length_unscaled,
                                uint32_t length_scaled_alignment_log2 = 0) {
    return EnsureScaledResolveMemoryCommitted(start_unscaled, length_unscaled,
                                              length_scaled_alignment_log2);
  }
  VkBuffer scaled_resolve_buffer() const { return scaled_resolve_buffer_; }
  void UseScaledResolveBufferForRead();
  void UseScaledResolveBufferForWrite(uint64_t written_start_scaled,
                                      uint64_t written_length_scaled);

 protected:
  bool IsSignedVersionSeparateForFormat(TextureKey key) const override;
  bool IsScaledResolveSupportedForFormat(TextureKey key) const override;
  uint32_t GetHostFormatSwizzle(TextureKey key) const override;

  uint32_t GetMaxHostTextureWidthHeight(xenos::DataDimension dimension) const override;
  uint32_t GetMaxHostTextureDepthOrArraySize(xenos::DataDimension dimension) const override;

  std::unique_ptr<Texture> CreateTexture(TextureKey key) override;

  bool EnsureScaledResolveMemoryCommitted(uint32_t start_unscaled, uint32_t length_unscaled,
                                          uint32_t length_scaled_alignment_log2 = 0) override;

  bool LoadTextureDataFromResidentMemoryImpl(Texture& texture, bool load_base,
                                             bool load_mips) override;

  void UpdateTextureBindingsImpl(uint32_t fetch_constant_mask) override;

 private:
  // (Run #12 fix for run #11, F3 points 6-7.) BC -> ETC2 / placeholder
  // helpers. They take TextureKey, a PROTECTED nested type of TextureCache:
  // they must be members of VulkanTextureCache (which inherits it), not
  // free functions in an anonymous namespace — free functions cannot name
  // the type at all, which broke the run #12 build. All callers are
  // members, so call sites are unchanged. The placeholder set is an
  // instance member, not a function-local static (audit A1-R6-03): a new
  // cache on re-init / title change must not inherit the previous
  // instance's placeholders, like the R5-C2 eviction counters in the base
  // TextureCache.
  std::unordered_set<TextureKey, TextureKey::Hasher> placeholder_texture_keys_;
  bool IsTexturePlaceholder(const TextureKey& key);
  void MarkTexturePlaceholder(const TextureKey& key);
  void ClearTexturePlaceholder(const TextureKey& key);

  // (Audit A-3.) CPU BC -> ETC2 transcode budget + failure cooldown
  // state. Instance members on purpose (audit A1-R6-03): the transcode
  // runs on the graphics thread (same as RequestTextures), so no lock is
  // needed, and a new VulkanTextureCache on re-init / title change must
  // not inherit the previous instance's budget stamp, failure cooldowns
  // or placeholders. The budget is shared across all textures in one
  // submission, stamped by submission index.
  struct Etc2TranscodeBudget {
    uint64_t submission = 0;
    // (Hunt v1.4.6 round 6, A2-R6-04.) 64-bit: a single slice's block
    // count (x_blocks * y_blocks * level_depth) can exceed 2^32 for
    // absurd extents, and a 32-bit counter would wrap and undercount the
    // budget, letting one submission transcode far past the cap.
    uint64_t blocks_used = 0;
  };
  Etc2TranscodeBudget etc2_budget_;
  struct Etc2TranscodeFailure {
    uint32_t consecutive_failures = 0;
    uint64_t last_failure_submission = 0;
  };
  std::unordered_map<TextureKey, Etc2TranscodeFailure, TextureKey::Hasher>
      etc2_failed_textures_;
  void RecordEtc2TranscodeFailure(const TextureKey& key, uint64_t submission);
  // (Hunt v1.4.6 round 5, T-R5-02.) Watch callback for a partially loaded
  // ETC2 texture: a guest write into the texture's guest range while the
  // load is incomplete invalidates the saved resume position, so the next
  // load restarts from slice 0 instead of mixing slices from two guest
  // generations. Only clears progress (and the watch handles, which the
  // shared memory invalidates after firing); never watches or unwatches
  // from within the callback.
  static void Etc2PartialLoadWatchCallback(
      const std::unique_lock<std::recursive_mutex>& global_lock, void* context, void* data,
      uint64_t argument, bool invalidated_by_gpu);
  // (Run #11, F3, point 6.) CPU staging for BC -> ETC2 transcoded uploads.
  // Instance member (audit A1-R6-03), destroyed with the cache: the pool
  // is bound to this cache's device, so a new cache on re-init must not
  // reuse the previous instance's pool. Pages are 16 MiB: one page holds a
  // whole 4096x4096 ETC2 RGBA level. Pages are reclaimed in
  // BeginSubmission().
  std::unique_ptr<ui::vulkan::VulkanUploadBufferPool> etc2_upload_pool_;
  // (Audit A1-R6-04.) Memo for Dxt1TextureHasOneBitAlpha. Instance member
  // (audit A1-R6-03, same class as the A-3 statics above; this one is the
  // run15 B-M3 memo): it dies with the cache, so a title change cannot
  // inherit stale alpha decisions. Mutable: the scan is consulted from the
  // const GetHostFormatPair().
  mutable std::unordered_map<TextureKey, bool, TextureKey::Hasher> dxt1_alpha_memo_;
  static void ReadGuestBcBlock(const SharedMemory& shared_memory,
                               const texture_util::TextureGuestLayout::Level& level_layout,
                               uint32_t guest_level_base, const TextureKey& key,
                               bool is_3d_tiling, uint32_t bx, uint32_t by, uint32_t bz,
                               uint32_t slice, uint8_t* block_out, uint32_t bytes_per_block);
  bool Dxt1TextureHasOneBitAlpha(const SharedMemory& shared_memory, const TextureKey& key,
                                 const texture_util::TextureGuestLayout& guest_layout) const;

  enum LoadDescriptorSetIndex {
    kLoadDescriptorSetIndexDestination,
    kLoadDescriptorSetIndexSource,
    kLoadDescriptorSetCount,
  };

  struct HostFormat {
    LoadShaderIndex load_shader;
    // Do NOT add integer formats to this - they are not filterable, can only be
    // read with ImageFetch, not ImageSample! If any game is seen using
    // num_format 1 for fixed-point formats (for floating-point, it's normally
    // set to 1 though), add a constant buffer containing multipliers for the
    // textures and multiplication to the tfetch implementation.
    VkFormat format;
    // Whether the format is block-compressed on the host (the host block size
    // matches the guest format block size in this case), and isn't decompressed
    // on load.
    bool block_compressed;

    // Set up dynamically based on what's supported by the device.
    bool linear_filterable;
  };

  struct HostFormatPair {
    HostFormat format_unsigned;
    HostFormat format_signed;
    // Mapping of Xenos swizzle components to Vulkan format components.
    uint32_t swizzle;
    // Whether the unsigned and the signed formats are compatible for one image
    // and the same image data (on a portability subset device, this should also
    // take imageViewFormatReinterpretation into account).
    bool unsigned_signed_compatible;
  };

  class VulkanTexture final : public Texture {
   public:
    enum class Usage {
      kUndefined,
      kTransferDestination,
      kGuestShaderSampled,
      kSwapSampled,
    };

    // Takes ownership of the image and its memory.
    explicit VulkanTexture(VulkanTextureCache& texture_cache, const TextureKey& key, VkImage image,
                           VmaAllocation allocation, bool track_usage = true);
    ~VulkanTexture();

    VkImage image() const { return image_; }

    // Doesn't transition (the caller must insert the barrier).
    Usage SetUsage(Usage new_usage) {
      Usage old_usage = usage_;
      usage_ = new_usage;
      return old_usage;
    }

    VkImageView GetView(bool is_signed, uint32_t host_swizzle, bool is_array = true);
    VkImageView GetOrCreate3DAs2DImageView(bool is_signed, uint32_t host_swizzle);

    // (Audit A1-R6-01.) BC -> ETC2 transcode progress: the next (loop
    // level, array slice) not yet uploaded. The ETC2 load uploads the
    // slices it transcoded in each submission and resumes here on the next
    // one, so a texture larger than the per-submission budget completes
    // over several submissions instead of re-burning its level 0 every
    // time. Lives on the texture, so it dies with it and never leaks
    // across textures. It is only ever set while the texture is outdated
    // and only cleared when the load completes, so a re-upload after the
    // guest data changes (which requires a prior completed load, and
    // clears this) never skips levels.
    // (Hunt v1.4.6 round 5, T-R5-02.) Correction to the last sentence
    // above: the guest CAN rewrite the texture while a load is still
    // partial, with no completed load in between -- and until this fix
    // there was no watch on the range during the partial load, so the
    // resume silently mixed slices from two guest generations. While
    // progress is active the texture now also carries a shared-memory
    // watch over its guest base+mips ranges (see
    // ArmEtc2PartialLoadWatch); a guest write fires
    // Etc2PartialLoadWatchCallback, which only clears the progress, so
    // the next load restarts from slice 0.
    bool etc2_progress_active() const { return etc2_progress_active_; }
    uint32_t etc2_next_loop_level() const { return etc2_next_loop_level_; }
    uint32_t etc2_next_slice() const { return etc2_next_slice_; }
    void SetEtc2Progress(uint32_t loop_level, uint32_t slice) {
      etc2_progress_active_ = true;
      etc2_next_loop_level_ = loop_level;
      etc2_next_slice_ = slice;
    }
    void ClearEtc2Progress() { etc2_progress_active_ = false; }
    // Registers the partial-load watch (base range, and mips range when
    // the texture has one) if not already armed. No-op when already
    // armed: the watch survives across the submissions of one partial
    // load. Must be called with the global critical region held, like
    // MakeUpToDateAndWatch.
    void ArmEtc2PartialLoadWatch(SharedMemory& shared_memory);
    // Unregisters the partial-load watch, if armed. Called when the load
    // completes and from the destructor.
    void DisarmEtc2PartialLoadWatch(SharedMemory& shared_memory);
    // Called by Etc2PartialLoadWatchCallback when the guest writes into
    // the watched range: drops the resume position and forgets ONLY the
    // handle of the range that fired (argument 0 = base, 1 = mips).
    // (Hunt v1.4.6 round 6, A2-R6-01.) SharedMemory::FireWatches cancels
    // only the range that fired, so the other watch stays registered: the
    // old code nulled BOTH handles, orphaning the surviving watch (it
    // could later fire into a destroyed texture) and letting Arm re-arm
    // a duplicate. Only clears state; never watches or unwatches.
    void NoteEtc2PartialLoadWatchFired(uint64_t argument) {
      ClearEtc2Progress();
      if (argument == 0) {
       etc2_partial_load_base_watch_handle_ = nullptr;
      } else {
       etc2_partial_load_mips_watch_handle_ = nullptr;
      }
    }

   private:
    union ViewKey {
      uint32_t key;
      struct {
        uint32_t is_signed_separate_view : 1;
        uint32_t host_swizzle : 12;
        uint32_t is_array : 1;
      };

      ViewKey() : key(0) { static_assert_size(*this, sizeof(key)); }

      struct Hasher {
        size_t operator()(const ViewKey& key) const {
          return std::hash<decltype(key.key)>{}(key.key);
        }
      };
      bool operator==(const ViewKey& other_key) const { return key == other_key.key; }
      bool operator!=(const ViewKey& other_key) const { return !(*this == other_key); }
    };

    static constexpr VkComponentSwizzle GetComponentSwizzle(uint32_t texture_swizzle,
                                                            uint32_t component_index) {
      xenos::XE_GPU_TEXTURE_SWIZZLE texture_component_swizzle =
          xenos::XE_GPU_TEXTURE_SWIZZLE((texture_swizzle >> (3 * component_index)) & 0b111);
      if (texture_component_swizzle == xenos::XE_GPU_TEXTURE_SWIZZLE(component_index)) {
        // The portability subset requires all swizzles to be IDENTITY, return
        // IDENTITY specifically, not R, G, B, A.
        return VK_COMPONENT_SWIZZLE_IDENTITY;
      }
      switch (texture_component_swizzle) {
        case xenos::XE_GPU_TEXTURE_SWIZZLE_R:
          return VK_COMPONENT_SWIZZLE_R;
        case xenos::XE_GPU_TEXTURE_SWIZZLE_G:
          return VK_COMPONENT_SWIZZLE_G;
        case xenos::XE_GPU_TEXTURE_SWIZZLE_B:
          return VK_COMPONENT_SWIZZLE_B;
        case xenos::XE_GPU_TEXTURE_SWIZZLE_A:
          return VK_COMPONENT_SWIZZLE_A;
        case xenos::XE_GPU_TEXTURE_SWIZZLE_0:
          return VK_COMPONENT_SWIZZLE_ZERO;
        case xenos::XE_GPU_TEXTURE_SWIZZLE_1:
          return VK_COMPONENT_SWIZZLE_ONE;
        default:
          // An invalid value.
          return VK_COMPONENT_SWIZZLE_IDENTITY;
      }
    }

    VkImage image_;
    VmaAllocation allocation_;

    Usage usage_ = Usage::kUndefined;

    // (Audit A1-R6-01.) See the accessors above.
    bool etc2_progress_active_ = false;
    uint32_t etc2_next_loop_level_ = 0;
    uint32_t etc2_next_slice_ = 0;
    // (Hunt v1.4.6 round 5, T-R5-02.) Partial-load watches, armed while
    // etc2_progress_active_. They are separate from the base Texture
    // base/mips watches, which only exist once the texture is up to date.
    SharedMemory::WatchHandle etc2_partial_load_base_watch_handle_ = nullptr;
    SharedMemory::WatchHandle etc2_partial_load_mips_watch_handle_ = nullptr;

    std::unordered_map<ViewKey, VkImageView, ViewKey::Hasher> views_;
    std::unique_ptr<VulkanTexture> texture_3d_as_2d_;
    // (Hunt v1.4.6 round 5, T-R5-01.) Whether the 3D-as-2D wrapper image
    // has actually been loaded. The wrapper is kept across a failed first
    // load (A1-R3-03), but until this flag is set the load must be
    // RETRIED on every call: creating the image view over an unloaded
    // wrapper (layout UNDEFINED, texels uninitialized) and caching it
    // forever was the R3-03 regression.
    bool texture_3d_as_2d_loaded_ = false;
    VkImageView image_view_3d_as_2d_unsigned_ = VK_NULL_HANDLE;
    VkImageView image_view_3d_as_2d_signed_ = VK_NULL_HANDLE;
  };

  struct VulkanTextureBinding {
    VkImageView image_view_unsigned;
    VkImageView image_view_signed;

    VulkanTextureBinding() { Reset(); }

    void Reset() {
      image_view_unsigned = VK_NULL_HANDLE;
      image_view_signed = VK_NULL_HANDLE;
    }
  };

  struct Sampler {
    VkSampler sampler;
    bool uses_custom_border_color;
    uint64_t last_usage_submission;
    std::pair<const SamplerParameters, Sampler>* used_previous;
    std::pair<const SamplerParameters, Sampler>* used_next;
  };

  static constexpr bool AreDimensionsCompatible(xenos::FetchOpDimension binding_dimension,
                                                xenos::DataDimension resource_dimension) {
    switch (binding_dimension) {
      case xenos::FetchOpDimension::k1D:
      case xenos::FetchOpDimension::k2D:
        return resource_dimension == xenos::DataDimension::k1D ||
               resource_dimension == xenos::DataDimension::k2DOrStacked ||
               resource_dimension == xenos::DataDimension::k3D;
      case xenos::FetchOpDimension::k3DOrStacked:
        return resource_dimension == xenos::DataDimension::k3D;
      case xenos::FetchOpDimension::kCube:
        return resource_dimension == xenos::DataDimension::kCube;
      default:
        return false;
    }
  }

  explicit VulkanTextureCache(const RegisterFile& register_file, VulkanSharedMemory& shared_memory,
                              uint32_t draw_resolution_scale_x, uint32_t draw_resolution_scale_y,
                              VulkanCommandProcessor& command_processor,
                              VkPipelineStageFlags guest_shader_pipeline_stages);

  bool Initialize();
  bool InitializeScaledResolveBuffer();
  void ShutdownScaledResolveBuffer();

  const HostFormatPair& GetHostFormatPair(TextureKey key) const;

  void GetTextureUsageMasks(VulkanTexture::Usage usage, VkPipelineStageFlags& stage_mask,
                            VkAccessFlags& access_mask, VkImageLayout& layout);
  bool EnsureScaledResolveBufferAllocated(uint64_t start_scaled, uint64_t length_scaled);
  void GetScaledResolveUsageMasks(VkPipelineStageFlags& stage_mask_out,
                                  VkAccessFlags& access_mask_out, bool write) const;

  xenos::ClampMode NormalizeClampMode(xenos::ClampMode clamp_mode) const;

  VulkanCommandProcessor& command_processor_;
  VkPipelineStageFlags guest_shader_pipeline_stages_;

  // Using the Vulkan Memory Allocator because texture count in games is
  // naturally pretty much unbounded, while Vulkan implementations, especially
  // on Windows versions before 10, may have an allocation count limit as low as
  // 4096.
  VmaAllocator vma_allocator_ = VK_NULL_HANDLE;

  static const HostFormatPair kBestHostFormats[64];
  static const HostFormatPair kHostFormatGBGRUnaligned;
  static const HostFormatPair kHostFormatBGRGUnaligned;
  static const HostFormatPair kHostFormatDXT1Unaligned;
  static const HostFormatPair kHostFormatDXT2_3Unaligned;
  static const HostFormatPair kHostFormatDXT4_5Unaligned;
  static const HostFormatPair kHostFormatDXNUnaligned;
  static const HostFormatPair kHostFormatDXT5AUnaligned;
  HostFormatPair host_formats_[64];

  VkPipelineLayout load_pipeline_layout_ = VK_NULL_HANDLE;
  std::array<VkPipeline, kLoadShaderCount> load_pipelines_{};
  std::array<VkPipeline, kLoadShaderCount> load_pipelines_scaled_{};

  // If both images can be placed in the same allocation, it's one allocation,
  // otherwise it's two separate.
  std::array<VkDeviceMemory, 2> null_images_memory_{};
  VkImage null_image_2d_array_cube_ = VK_NULL_HANDLE;
  VkImage null_image_3d_ = VK_NULL_HANDLE;
  VkImageView null_image_view_2d_array_ = VK_NULL_HANDLE;
  VkImageView null_image_view_cube_ = VK_NULL_HANDLE;
  VkImageView null_image_view_3d_ = VK_NULL_HANDLE;
  // (Hunt v1.4.6 round 5, T-R5-03.) Plain 2D view of the 1x1 null image,
  // for the swap path: the swap gamma shaders declare `texture2D`, and a
  // 2D_ARRAY view bound there is a view-type mismatch (spec: the view
  // type must match the OpTypeImage Dim/Arrayed), so the 2D_ARRAY null
  // view used for shader fetches cannot serve the present path.
  VkImageView null_image_view_2d_ = VK_NULL_HANDLE;
  bool null_images_cleared_ = false;

  std::array<VulkanTextureBinding, xenos::kTextureFetchConstantCount> vulkan_texture_bindings_;

  // Unsupported texture formats used during this frame (for research and
  // testing).
  enum : uint8_t {
    kUnsupportedResourceBit = 1,
    kUnsupportedUnormBit = kUnsupportedResourceBit << 1,
    kUnsupportedSnormBit = kUnsupportedUnormBit << 1,
  };
  uint8_t unsupported_format_features_used_[64] = {};

  uint32_t sampler_max_count_;

  xenos::AnisoFilter max_anisotropy_;

  std::unordered_map<SamplerParameters, Sampler, SamplerParameters::Hasher> samplers_;
  std::pair<const SamplerParameters, Sampler>* sampler_used_first_ = nullptr;
  std::pair<const SamplerParameters, Sampler>* sampler_used_last_ = nullptr;
  uint32_t custom_border_color_sampler_count_ = 0;

  VkBuffer scaled_resolve_buffer_ = VK_NULL_HANDLE;
  uint64_t scaled_resolve_buffer_size_ = 0;
  bool scaled_resolve_buffer_sparse_ = false;
  uint32_t scaled_resolve_buffer_memory_type_ = UINT32_MAX;
  std::vector<VkDeviceMemory> scaled_resolve_buffer_memory_;
  uint32_t scaled_resolve_sparse_granularity_log2_ = UINT32_MAX;
  std::vector<uint64_t> scaled_resolve_sparse_allocated_;
  bool scaled_resolve_last_usage_write_ = false;
  std::pair<uint64_t, uint64_t> scaled_resolve_last_written_range_{0, 0};
};

}  // namespace rex::graphics::vulkan
