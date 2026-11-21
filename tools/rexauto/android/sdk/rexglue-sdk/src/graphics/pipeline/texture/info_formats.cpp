/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2014 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

// clang-format off

#include <rex/graphics/pipeline/texture/info.h>

#include <rex/logging.h>

namespace rex::graphics {

using namespace rex::graphics::xenos;

#define FORMAT_INFO(texture_format, format, block_width, block_height, bits_per_pixel, \
                     cb0, cb1, cb2, cb3, fixed) \
    {xenos::TextureFormat::texture_format, #texture_format, FormatType::format, \
     block_width, block_height, bits_per_pixel, {cb0, cb1, cb2, cb3}, fixed}
const FormatInfo* FormatInfo::Get(uint32_t gpu_format) {
  // (Caza v1.4.6 ronda 4, A1-R4-06.) The table has exactly 64 entries,
  // one per xenos::TextureFormat (0..63, xenos.h), and every current
  // caller passes a value that is in range by construction: 6-bit
  // bitfields (TextureKey::format, RB_COPY_DEST_INFO::copy_dest_format,
  // VertexFetchConstant / stream format), TextureFormat / ColorFormat
  // enum values (ColorFormat is a subset with the same numbering), or
  // a loop index bounded by 64 (Vulkan/D3D12 texture_cache EndFrame).
  // A raw uint32_t outside 0..63 used to index out of bounds. Returning
  // nullptr is not an option: ~25 call sites dereference the result
  // unchecked (format_info->block_width, ->name, *Get(...)), so it
  // would turn a latent OOB read into immediate null dereferences.
  // Instead, log loudly and fall back to the k_8_8_8_8 entry (index 6):
  // 1x1 block, 32 bpp, bytes_per_block() == 4 — never a zero divisor
  // (cache.cpp divides by bytes_per_block(), util.cpp by block_width /
  // block_height), and the most common guest format, so downstream size
  // math stays in a plausible range. Only reachable with an already
  // invalid format value, never on the normal path.
  static const FormatInfo format_infos[64] = {
      FORMAT_INFO(k_1_REVERSE                , kUncompressed, 1, 1, 1,    0, 0, 0, 0, false),
      FORMAT_INFO(k_1                        , kUncompressed, 1, 1, 1,    0, 0, 0, 0, false),
      FORMAT_INFO(k_8                        , kResolvable,   1, 1, 8,    8, 0, 0, 0, true),
      FORMAT_INFO(k_1_5_5_5                  , kResolvable,   1, 1, 16,   5, 5, 5, 1, true),
      FORMAT_INFO(k_5_6_5                    , kResolvable,   1, 1, 16,   5, 6, 5, 0, true),
      FORMAT_INFO(k_6_5_5                    , kResolvable,   1, 1, 16,   5, 5, 6, 0, true),
      FORMAT_INFO(k_8_8_8_8                  , kResolvable,   1, 1, 32,   8, 8, 8, 8, true),
      FORMAT_INFO(k_2_10_10_10               , kResolvable,   1, 1, 32,   10, 10, 10, 2, true),
      FORMAT_INFO(k_8_A                      , kResolvable,   1, 1, 8,    8, 0, 0, 0, true),
      FORMAT_INFO(k_8_B                      , kResolvable,   1, 1, 8,    8, 0, 0, 0, true),
      FORMAT_INFO(k_8_8                      , kResolvable,   1, 1, 16,   8, 8, 0, 0, true),
      FORMAT_INFO(k_Cr_Y1_Cb_Y0_REP          , kCompressed,   2, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_Y1_Cr_Y0_Cb_REP          , kCompressed,   2, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_EDRAM              , kUncompressed, 1, 1, 32,   16, 16, 0, 0, true),
      FORMAT_INFO(k_8_8_8_8_A                , kResolvable,   1, 1, 32,   8, 8, 8, 8, true),
      FORMAT_INFO(k_4_4_4_4                  , kResolvable,   1, 1, 16,   4, 4, 4, 4, true),
      FORMAT_INFO(k_10_11_11                 , kResolvable,   1, 1, 32,   11, 11, 10, 0, true),
      FORMAT_INFO(k_11_11_10                 , kResolvable,   1, 1, 32,   10, 11, 11, 0, true),
      FORMAT_INFO(k_DXT1                     , kCompressed,   4, 4, 4,    0, 0, 0, 0, false),
      FORMAT_INFO(k_DXT2_3                   , kCompressed,   4, 4, 8,    0, 0, 0, 0, false),
      FORMAT_INFO(k_DXT4_5                   , kCompressed,   4, 4, 8,    0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_16_16_EDRAM        , kUncompressed, 1, 1, 64,   16, 16, 16, 16, true),
      FORMAT_INFO(k_24_8                     , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_24_8_FLOAT               , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16                       , kResolvable,   1, 1, 16,   16, 0, 0, 0, true),
      FORMAT_INFO(k_16_16                    , kResolvable,   1, 1, 32,   16, 16, 0, 0, true),
      FORMAT_INFO(k_16_16_16_16              , kResolvable,   1, 1, 64,   16, 16, 16, 16, true),
      FORMAT_INFO(k_16_EXPAND                , kUncompressed, 1, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_EXPAND             , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_16_16_EXPAND       , kUncompressed, 1, 1, 64,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_FLOAT                 , kResolvable,   1, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_FLOAT              , kResolvable,   1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_16_16_FLOAT        , kResolvable,   1, 1, 64,   0, 0, 0, 0, false),
      FORMAT_INFO(k_32                       , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_32_32                    , kUncompressed, 1, 1, 64,   0, 0, 0, 0, false),
      FORMAT_INFO(k_32_32_32_32              , kUncompressed, 1, 1, 128,  0, 0, 0, 0, false),
      FORMAT_INFO(k_32_FLOAT                 , kResolvable,   1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_32_32_FLOAT              , kResolvable,   1, 1, 64,   0, 0, 0, 0, false),
      FORMAT_INFO(k_32_32_32_32_FLOAT        , kResolvable,   1, 1, 128,  0, 0, 0, 0, false),
      FORMAT_INFO(k_32_AS_8                  , kCompressed,   4, 1, 8,    0, 0, 0, 0, false),
      FORMAT_INFO(k_32_AS_8_8                , kCompressed,   2, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_MPEG                  , kUncompressed, 1, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_MPEG               , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_8_INTERLACED             , kUncompressed, 1, 1, 8,    8, 0, 0, 0, true),
      FORMAT_INFO(k_32_AS_8_INTERLACED       , kCompressed,   4, 1, 8,    0, 0, 0, 0, false),
      FORMAT_INFO(k_32_AS_8_8_INTERLACED     , kCompressed,   1, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_INTERLACED            , kUncompressed, 1, 1, 16,   16, 0, 0, 0, true),
      FORMAT_INFO(k_16_MPEG_INTERLACED       , kUncompressed, 1, 1, 16,   0, 0, 0, 0, false),
      FORMAT_INFO(k_16_16_MPEG_INTERLACED    , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_DXN                      , kCompressed,   4, 4, 8,    0, 0, 0, 0, false),
      FORMAT_INFO(k_8_8_8_8_AS_16_16_16_16   , kResolvable,   1, 1, 32,   8, 8, 8, 8, true),
      FORMAT_INFO(k_DXT1_AS_16_16_16_16      , kCompressed,   4, 4, 4,    0, 0, 0, 0, false),
      FORMAT_INFO(k_DXT2_3_AS_16_16_16_16    , kCompressed,   4, 4, 8,    0, 0, 0, 0, false),
      FORMAT_INFO(k_DXT4_5_AS_16_16_16_16    , kCompressed,   4, 4, 8,    0, 0, 0, 0, false),
      FORMAT_INFO(k_2_10_10_10_AS_16_16_16_16, kResolvable,   1, 1, 32,   10, 10, 10, 2, true),
      FORMAT_INFO(k_10_11_11_AS_16_16_16_16  , kResolvable,   1, 1, 32,   11, 11, 10, 0, true),
      FORMAT_INFO(k_11_11_10_AS_16_16_16_16  , kResolvable,   1, 1, 32,   10, 11, 11, 0, true),
      FORMAT_INFO(k_32_32_32_FLOAT           , kUncompressed, 1, 1, 96,   0, 0, 0, 0, false),
      FORMAT_INFO(k_DXT3A                    , kCompressed,   4, 4, 4,    0, 0, 0, 0, false),
      FORMAT_INFO(k_DXT5A                    , kCompressed,   4, 4, 4,    0, 0, 0, 0, false),
      FORMAT_INFO(k_CTX1                     , kCompressed,   4, 4, 4,    0, 0, 0, 0, false),
      FORMAT_INFO(k_DXT3A_AS_1_1_1_1         , kCompressed,   4, 4, 4,    0, 0, 0, 0, false),
      FORMAT_INFO(k_8_8_8_8_GAMMA_EDRAM      , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
      FORMAT_INFO(k_2_10_10_10_FLOAT_EDRAM   , kUncompressed, 1, 1, 32,   0, 0, 0, 0, false),
  };
  if (gpu_format >= 64) {
    REXGPU_ERROR("FormatInfo::Get: invalid gpu_format {} (expected 0..63); falling back to "
                 "k_8_8_8_8",
                 gpu_format);
    // k_8_8_8_8 is entry 6 in the table above (see the comment at the
    // top of this function for why this fallback, and not nullptr).
    return &format_infos[6];
  }
  return &format_infos[gpu_format];
}
#undef FORMAT_INFO

}  //  namespace rex::graphics
