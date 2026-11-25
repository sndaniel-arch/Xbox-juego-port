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
 *
 * BC (S3TC/DXT) -> ETC2 CPU transcode, run #11 (F3).
 *
 * Mali GPUs have no BC/DXT support, so the texture cache used to decompress
 * every DXT texture to RGBA8 with a compute shader on every invalidation
 * (4x memory and upload bandwidth). ETC2 is native on Mali at the same
 * 4 bpp (RGB8) / 8 bpp (RGBA8) as the source BC1 / BC3 blocks, so a block
 * can be transcoded once on the CPU at load time and sampled natively.
 *
 * This header is dependency-free (C++17, no SDK headers) so it can be unit
 * tested on the host. Bit layouts follow the OpenGL ES 3.0 specification,
 * annex C.3 (ETC2), i.e. the 64-bit word is built big-endian from the bytes
 * in memory order (byte q0 is the most significant byte):
 * - Individual mode (diff bit 0): R1/R2/G1/G2/B1/B2 are 4-bit codewords in
 *   bytes 0-2 (high nibble = subblock 1), tables in byte 3 bits 7-3.
 * - Differential mode (diff bit 1): R/G/B are 5-bit codewords and dR/dG/dB
 *   are 3-bit two's-complement differences in the low 3 bits of bytes 0-2.
 *   A differential block is only legal when R+dR, G+dG and B+dB all stay in
 *   [0, 31]; otherwise the hardware decodes it as T/H/planar instead.
 * - Pixel indices (bits 31-0): the MSB plane first, then the LSB plane;
 *   plane bit i (i = y * 4 + x) is pixel (x, y). The 2-bit index maps to a
 *   modifier of {+a, +b, -a, -b} for the subblock's table (a, b).
 * - ETC2_RGBA8 is a 16-byte block: the 8-byte EAC alpha block FIRST, then
 *   the 8-byte color block. The alpha block holds an 8-bit base, a 4-bit
 *   multiplier and a 4-bit table codeword (16 tables x 8 modifiers), then
 *   16 3-bit indices, most significant first.
 *
 * Guest BC blocks arrive big-endian in guest memory; ApplyGuestEndian()
 * mirrors rex::graphics::texture_conversion::CopySwapBlock() (same
 * xenos::Endian values: 0 = none, 1 = 8-in-16, 2 = 8-in-32, 3 = 16-in-32)
 * and must be applied to the raw block bytes before decoding.
 * TODO-VERIFY (device): the DXT compute load shaders apply the same swap;
 * if a BC texture ever shows swapped colors on the phone, the swap for BC
 * specifically is the first suspect (see texture_cache.cpp).
 */

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace rex::graphics::vulkan::etc2 {

struct Rgba {
  uint8_t r;
  uint8_t g;
  uint8_t b;
  uint8_t a;
};

// Applies the guest endianness swap to raw block bytes. Mirrors
// texture_conversion::CopySwapBlock(): endian 0 copies, 1 swaps bytes in
// each 16-bit word, 2 swaps bytes in each 32-bit word, 3 swaps the 16-bit
// halves of each 32-bit word. Trailing bytes that don't fill a whole unit
// are copied unchanged.
inline void ApplyGuestEndian(uint32_t endian, uint8_t* dst, const uint8_t* src, size_t length) {
  switch (endian) {
    case 1: {  // k8in16
      size_t i = 0;
      for (; i + 1 < length; i += 2) {
        dst[i] = src[i + 1];
        dst[i + 1] = src[i];
      }
      if (i < length) {
        dst[i] = src[i];
      }
      break;
    }
    case 2: {  // k8in32
      size_t i = 0;
      for (; i + 3 < length; i += 4) {
        dst[i] = src[i + 3];
        dst[i + 1] = src[i + 2];
        dst[i + 2] = src[i + 1];
        dst[i + 3] = src[i];
      }
      for (; i < length; ++i) {
        dst[i] = src[i];
      }
      break;
    }
    case 3: {  // k16in32
      size_t i = 0;
      for (; i + 3 < length; i += 4) {
        dst[i] = src[i + 2];
        dst[i + 1] = src[i + 3];
        dst[i + 2] = src[i];
        dst[i + 3] = src[i + 1];
      }
      for (; i < length; ++i) {
        dst[i] = src[i];
      }
      break;
    }
    default:  // kNone
      std::memcpy(dst, src, length);
      break;
  }
}

namespace detail {

// ETC1/ETC2 color modifier tables (ES 3.0 spec table 3.17.2): pairs (a, b);
// the 2-bit pixel index selects {+a, +b, -a, -b} (spec table 3.17.3).
constexpr int kColorTables[8][2] = {
    {2, 8}, {5, 17}, {9, 29}, {13, 42}, {18, 60}, {24, 80}, {33, 106}, {47, 183},
};

// EAC alpha modifier tables (ES 3.0 spec table C.18): 16 tables x 8 entries,
// selected by the 3-bit pixel index.
constexpr int kAlphaTables[16][8] = {
    {-3, -6, -9, -15, 2, 5, 8, 14},  {-3, -7, -10, -13, 2, 6, 9, 12},
    {-2, -5, -8, -13, 1, 4, 7, 12},  {-2, -4, -6, -13, 1, 3, 5, 12},
    {-3, -6, -8, -12, 2, 5, 7, 11},  {-3, -7, -9, -11, 2, 6, 8, 10},
    {-4, -7, -8, -11, 3, 6, 7, 10},  {-3, -5, -8, -11, 2, 4, 7, 10},
    {-2, -6, -8, -10, 1, 5, 7, 9},   {-2, -5, -8, -10, 1, 4, 7, 9},
    {-2, -4, -8, -10, 1, 3, 7, 9},   {-2, -5, -7, -10, 1, 4, 6, 9},
    {-3, -4, -7, -10, 2, 3, 6, 9},   {-1, -2, -3, -10, 0, 1, 2, 9},
    {-4, -6, -8, -9, 3, 5, 7, 8},    {-3, -5, -7, -9, 2, 4, 6, 8},
};

inline uint8_t Expand565R(uint16_t c) {
  uint32_t v = (c >> 11) & 0x1F;
  return uint8_t((v << 3) | (v >> 2));
}
inline uint8_t Expand565G(uint16_t c) {
  uint32_t v = (c >> 5) & 0x3F;
  return uint8_t((v << 2) | (v >> 4));
}
inline uint8_t Expand565B(uint16_t c) {
  uint32_t v = c & 0x1F;
  return uint8_t((v << 3) | (v >> 2));
}

inline uint16_t ReadU16Le(const uint8_t* p) {
  return uint16_t(p[0] | (uint16_t(p[1]) << 8));
}
inline uint32_t ReadU32Le(const uint8_t* p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
         (uint32_t(p[3]) << 24);
}

inline int ClampInt(int v, int lo, int hi) { return std::max(lo, std::min(hi, v)); }

// Best (lowest squared error) modifier index for one texel channel value
// against base + table[index], with the result clamped to [0, 255].
inline int BestColorIndex(int value, int base, int table) {
  const int a = kColorTables[table][0];
  const int b = kColorTables[table][1];
  const int mods[4] = {a, b, -a, -b};
  int best_index = 0;
  int best_error = 1 << 30;
  for (int i = 0; i < 4; ++i) {
    int decoded = ClampInt(base + mods[i], 0, 255);
    int error = decoded - value;
    error *= error;
    if (error < best_error) {
      best_error = error;
      best_index = i;
    }
  }
  return best_index;
}

inline int ColorIndexError(int value, int base, int table, int index) {
  const int a = kColorTables[table][0];
  const int b = kColorTables[table][1];
  const int mods[4] = {a, b, -a, -b};
  int decoded = ClampInt(base + mods[index], 0, 255);
  int error = decoded - value;
  return error * error;
}

// One ETC2 color subblock (8 texels): pick the best table and indices for
// fixed per-channel bases, returning the squared error.
inline int FitColorSubblock(const Rgba* pixels, const int* order, const int base[3],
                            int* table_out, int* indices_out) {
  int best_table = 0;
  int best_error = 1 << 30;
  int best_indices[8];
  for (int table = 0; table < 8; ++table) {
    int error = 0;
    int indices[8];
    for (int i = 0; i < 8; ++i) {
      const Rgba& px = pixels[order[i]];
      // The index must be shared by R, G and B: score the best index per
      // channel sum, i.e. pick the index minimizing the total RGB error.
      int best_index = 0;
      int best_index_error = 1 << 30;
      for (int index = 0; index < 4; ++index) {
        int e = ColorIndexError(px.r, base[0], table, index) +
                ColorIndexError(px.g, base[1], table, index) +
                ColorIndexError(px.b, base[2], table, index);
        if (e < best_index_error) {
          best_index_error = e;
          best_index = index;
        }
      }
      indices[i] = best_index;
      error += best_index_error;
    }
    if (error < best_error) {
      best_error = error;
      best_table = table;
      std::memcpy(best_indices, indices, sizeof(best_indices));
    }
  }
  *table_out = best_table;
  std::memcpy(indices_out, best_indices, sizeof(best_indices));
  return best_error;
}

// Recomputes the optimal 8-bit base per channel from the assigned indices:
// base = mean(pixel - modifier), clamped to [0, 255].
inline void RefineColorBase(const Rgba* pixels, const int* order, int table,
                            const int* indices, int base[3]) {
  for (int c = 0; c < 3; ++c) {
    const int a = kColorTables[table][0];
    const int b = kColorTables[table][1];
    const int mods[4] = {a, b, -a, -b};
    int sum = 0;
    for (int i = 0; i < 8; ++i) {
      const Rgba& px = pixels[order[i]];
      int value = c == 0 ? px.r : (c == 1 ? px.g : px.b);
      sum += value - mods[indices[i]];
    }
    base[c] = ClampInt((sum + 4) / 8, 0, 255);
  }
}

}  // namespace detail

// Whether a BC1 block uses 1-bit alpha: color0 <= color1 AND at least one
// texel uses index 3 (transparent). `block` must already be endian-swapped.
inline bool Bc1BlockHasOneBitAlpha(const uint8_t block[8]) {
  uint16_t c0 = detail::ReadU16Le(block);
  uint16_t c1 = detail::ReadU16Le(block + 2);
  if (c0 > c1) {
    return false;
  }
  uint32_t indices = detail::ReadU32Le(block + 4);
  for (int i = 0; i < 16; ++i) {
    if (((indices >> (2 * i)) & 3u) == 3u) {
      return true;
    }
  }
  return false;
}

// Decodes a BC1 (DXT1) block to 16 RGBA texels, row-major (i = y * 4 + x).
// `block` must already be endian-swapped. If force_opaque is set, the color
// block is always decoded in 4-color mode (BC3 color part).
inline void DecodeBc1Block(const uint8_t block[8], Rgba out[16], bool force_opaque = false) {
  uint16_t c0 = detail::ReadU16Le(block);
  uint16_t c1 = detail::ReadU16Le(block + 2);
  uint32_t indices = detail::ReadU32Le(block + 4);
  Rgba palette[4];
  palette[0] = {detail::Expand565R(c0), detail::Expand565G(c0), detail::Expand565B(c0), 255};
  palette[1] = {detail::Expand565R(c1), detail::Expand565G(c1), detail::Expand565B(c1), 255};
  if (c0 > c1 || force_opaque) {
    palette[2] = {uint8_t((2 * palette[0].r + palette[1].r) / 3),
                  uint8_t((2 * palette[0].g + palette[1].g) / 3),
                  uint8_t((2 * palette[0].b + palette[1].b) / 3), 255};
    palette[3] = {uint8_t((palette[0].r + 2 * palette[1].r) / 3),
                  uint8_t((palette[0].g + 2 * palette[1].g) / 3),
                  uint8_t((palette[0].b + 2 * palette[1].b) / 3), 255};
  } else {
    palette[2] = {uint8_t((palette[0].r + palette[1].r) / 2),
                  uint8_t((palette[0].g + palette[1].g) / 2),
                  uint8_t((palette[0].b + palette[1].b) / 2), 255};
    palette[3] = {0, 0, 0, 0};
  }
  for (int i = 0; i < 16; ++i) {
    out[i] = palette[(indices >> (2 * i)) & 3u];
  }
}

// Decodes a BC3 (DXT5) block to 16 RGBA texels, row-major.
// `block` must already be endian-swapped.
inline void DecodeBc3Block(const uint8_t block[16], Rgba out[16]) {
  uint8_t a0 = block[0];
  uint8_t a1 = block[1];
  uint64_t alpha_bits = 0;
  for (int i = 0; i < 6; ++i) {
    alpha_bits |= uint64_t(block[2 + i]) << (8 * i);
  }
  uint8_t alpha_palette[8];
  if (a0 > a1) {
    alpha_palette[0] = a0;
    alpha_palette[1] = a1;
    alpha_palette[2] = uint8_t((6 * a0 + a1) / 7);
    alpha_palette[3] = uint8_t((5 * a0 + 2 * a1) / 7);
    alpha_palette[4] = uint8_t((4 * a0 + 3 * a1) / 7);
    alpha_palette[5] = uint8_t((3 * a0 + 4 * a1) / 7);
    alpha_palette[6] = uint8_t((2 * a0 + 5 * a1) / 7);
    alpha_palette[7] = uint8_t((a0 + 6 * a1) / 7);
  } else {
    alpha_palette[0] = a0;
    alpha_palette[1] = a1;
    alpha_palette[2] = uint8_t((4 * a0 + a1) / 5);
    alpha_palette[3] = uint8_t((3 * a0 + 2 * a1) / 5);
    alpha_palette[4] = uint8_t((2 * a0 + 3 * a1) / 5);
    alpha_palette[5] = uint8_t((a0 + 4 * a1) / 5);
    alpha_palette[6] = 0;
    alpha_palette[7] = 255;
  }
  DecodeBc1Block(block + 8, out, /*force_opaque=*/true);
  for (int i = 0; i < 16; ++i) {
    out[i].a = alpha_palette[(alpha_bits >> (3 * i)) & 7u];
  }
}

// Decodes a BC2 (DXT3) block to 16 RGBA texels, row-major.
// `block` must already be endian-swapped. The first 8 bytes are the
// explicit 4-bit alpha values: texel i is nibble i of the little-endian
// 64-bit value, expanded x17 (0 -> 0, 15 -> 255). The last 8 bytes are a
// BC1 color block in 4-color (opaque) mode, exactly like the color part
// of BC3 above. Same 16 bytes per 4x4 block as BC3, so the transcode to
// ETC2 RGBA8 is a block-for-block replacement.
// (Hunt v1.4.6 ronda 20, A1-R20-02.)
inline void DecodeBc2Block(const uint8_t block[16], Rgba out[16]) {
  uint64_t alpha_bits = 0;
  for (int i = 0; i < 8; ++i) {
    alpha_bits |= uint64_t(block[i]) << (8 * i);
  }
  DecodeBc1Block(block + 8, out, /*force_opaque=*/true);
  for (int i = 0; i < 16; ++i) {
    out[i].a = uint8_t(((alpha_bits >> (4 * i)) & 0xFu) * 17u);
  }
}

// Encodes 16 RGBA texels (row-major) as one ETC2_RGB8 block (8 bytes).
// Only the individual and differential modes are used; T/H/planar are never
// emitted, and a differential candidate is only accepted when R+dR, G+dG
// and B+dB all stay in [0, 31] (otherwise the hardware would decode it as
// T/H/planar). Alpha is ignored.
inline void EncodeEtc2Rgb8(const Rgba pixels[16], uint8_t out[8]) {
  // Subblock pixel order: flip 0 splits left/right (x < 2), flip 1 splits
  // top/bottom (y < 2).
  int best_error = 1 << 30;
  bool best_differential = false;
  bool best_flip = false;
  int best_base1[3] = {0, 0, 0};
  int best_base2[3] = {0, 0, 0};  // Individual: 4-bit codewords. Diff: 5-bit
                                   // base (base1) and 3-bit diffs (base2).
  int best_table1 = 0;
  int best_table2 = 0;
  int best_indices[16] = {};

  for (int flip = 0; flip < 2; ++flip) {
    int order[2][8];
    int count[2] = {0, 0};
    for (int i = 0; i < 16; ++i) {
      int x = i & 3;
      int y = i >> 2;
      int half = flip ? (y >= 2 ? 1 : 0) : (x >= 2 ? 1 : 0);
      order[half][count[half]++] = i;
    }
    // Per-half means.
    int mean[2][3] = {};
    for (int half = 0; half < 2; ++half) {
      int sum[3] = {0, 0, 0};
      for (int i = 0; i < 8; ++i) {
        const Rgba& px = pixels[order[half][i]];
        sum[0] += px.r;
        sum[1] += px.g;
        sum[2] += px.b;
      }
      for (int c = 0; c < 3; ++c) {
        mean[half][c] = (sum[c] + 4) / 8;
      }
    }
    // Individual mode: 4-bit endpoints from the means, then one refinement.
    for (int mode = 0; mode < 2; ++mode) {
      bool differential = mode == 1;
      int base1[3];
      int base2[3];
      if (differential) {
        int q5[2][3];
        for (int half = 0; half < 2; ++half) {
          for (int c = 0; c < 3; ++c) {
            q5[half][c] = detail::ClampInt((mean[half][c] * 31 + 127) / 255, 0, 31);
          }
        }
        bool legal = true;
        for (int c = 0; c < 3; ++c) {
          int d = q5[1][c] - q5[0][c];
          if (d < -4 || d > 3) {
            legal = false;
          }
        }
        if (!legal) {
          continue;
        }
        for (int c = 0; c < 3; ++c) {
          base1[c] = (q5[0][c] << 3) | (q5[0][c] >> 2);
          base2[c] = q5[1][c] - q5[0][c];
        }
      } else {
        for (int half = 0; half < 2; ++half) {
          for (int c = 0; c < 3; ++c) {
            int q4 = detail::ClampInt((mean[half][c] * 15 + 127) / 255, 0, 15);
            if (half == 0) {
              base1[c] = q4 * 17;
            } else {
              base2[c] = q4 * 17;
            }
          }
        }
      }
      int table1 = 0;
      int table2 = 0;
      int indices[16] = {};
      int error = 0;
      // Two passes: fit tables/indices, refine the bases, refit once.
      for (int pass = 0; pass < 2; ++pass) {
        int expanded2[3];
        if (differential) {
          for (int c = 0; c < 3; ++c) {
            int q5 = detail::ClampInt(((base1[c] * 31 + 127) / 255) + base2[c], 0, 31);
            expanded2[c] = (q5 << 3) | (q5 >> 2);
          }
        } else {
          std::memcpy(expanded2, base2, sizeof(expanded2));
        }
        int e0 = detail::FitColorSubblock(pixels, order[0], base1, &table1, indices);
        int e1 = detail::FitColorSubblock(pixels, order[1], expanded2, &table2, indices + 8);
        error = e0 + e1;
        if (pass == 0) {
          detail::RefineColorBase(pixels, order[0], table1, indices, base1);
          if (differential) {
            int refined2[3];
            detail::RefineColorBase(pixels, order[1], table2, indices + 8, refined2);
            bool legal = true;
            for (int c = 0; c < 3; ++c) {
              int q5_1 = detail::ClampInt((base1[c] * 31 + 127) / 255, 0, 31);
              int q5_2 = detail::ClampInt((refined2[c] * 31 + 127) / 255, 0, 31);
              int d = q5_2 - q5_1;
              if (d < -4 || d > 3) {
                legal = false;
              }
              base2[c] = d;
            }
            if (!legal) {
              // A refined differential candidate whose diffs leave [0, 31]
              // would decode as T/H/planar on hardware: discard it.
              error = 1 << 29;
              break;
            }
            // Keep base1 as the refined 5-bit base: re-expand it.
            for (int c = 0; c < 3; ++c) {
              int q5 = detail::ClampInt((base1[c] * 31 + 127) / 255, 0, 31);
              base1[c] = (q5 << 3) | (q5 >> 2);
            }
          } else {
            int refined2[3];
            detail::RefineColorBase(pixels, order[1], table2, indices + 8, refined2);
            for (int c = 0; c < 3; ++c) {
              int q4 = detail::ClampInt((refined2[c] * 15 + 127) / 255, 0, 15);
              base2[c] = q4 * 17;
            }
            for (int c = 0; c < 3; ++c) {
              int q4 = detail::ClampInt((base1[c] * 15 + 127) / 255, 0, 15);
              base1[c] = q4 * 17;
            }
          }
        }
      }
      if (error < best_error) {
        best_error = error;
        best_differential = differential;
        best_flip = flip != 0;
        std::memcpy(best_base1, base1, sizeof(best_base1));
        std::memcpy(best_base2, base2, sizeof(best_base2));
        best_table1 = table1;
        best_table2 = table2;
        // Indices are stored per subblock in `indices`; map them back to
        // pixel order.
        for (int half = 0; half < 2; ++half) {
          for (int i = 0; i < 8; ++i) {
            best_indices[order[half][i]] = indices[half * 8 + i];
          }
        }
      }
    }
  }

  // Pack the winning block. The 2-bit pixel index is (msb << 1) | lsb and
  // plane bit i (i = y * 4 + x) belongs to pixel i.
  uint16_t msb_plane = 0;
  uint16_t lsb_plane = 0;
  for (int i = 0; i < 16; ++i) {
    int index = best_indices[i];
    if (index & 2) {
      msb_plane |= uint16_t(1u << i);
    }
    if (index & 1) {
      lsb_plane |= uint16_t(1u << i);
    }
  }
  if (best_differential) {
    int q5[3];
    int diff[3];
    for (int c = 0; c < 3; ++c) {
      q5[c] = detail::ClampInt((best_base1[c] * 31 + 127) / 255, 0, 31);
      diff[c] = best_base2[c];
    }
    out[0] = uint8_t((q5[0] << 3) | (diff[0] & 7));
    out[1] = uint8_t((q5[1] << 3) | (diff[1] & 7));
    out[2] = uint8_t((q5[2] << 3) | (diff[2] & 7));
  } else {
    int q4_1[3];
    int q4_2[3];
    for (int c = 0; c < 3; ++c) {
      q4_1[c] = detail::ClampInt((best_base1[c] * 15 + 127) / 255, 0, 15);
      q4_2[c] = detail::ClampInt((best_base2[c] * 15 + 127) / 255, 0, 15);
    }
    out[0] = uint8_t((q4_1[0] << 4) | q4_2[0]);
    out[1] = uint8_t((q4_1[1] << 4) | q4_2[1]);
    out[2] = uint8_t((q4_1[2] << 4) | q4_2[2]);
  }
  out[3] = uint8_t((best_table1 << 5) | (best_table2 << 2) | ((best_differential ? 1 : 0) << 1) |
                   (best_flip ? 1 : 0));
  out[4] = uint8_t(msb_plane >> 8);
  out[5] = uint8_t(msb_plane & 0xFF);
  out[6] = uint8_t(lsb_plane >> 8);
  out[7] = uint8_t(lsb_plane & 0xFF);
}

// Encodes the 16 alpha values of a 4x4 block as one EAC alpha block
// (8 bytes): 8-bit base, 4-bit multiplier, 4-bit table, 16 3-bit indices
// most significant first. The encoder never emits a zero multiplier.
inline void EncodeEtc2AlphaBlock(const uint8_t alpha[16], uint8_t out[8]) {
  int amin = 255;
  int amax = 0;
  for (int i = 0; i < 16; ++i) {
    amin = std::min(amin, int(alpha[i]));
    amax = std::max(amax, int(alpha[i]));
  }
  int span = amax - amin;
  int best_error = 1 << 30;
  int best_table = 0;
  int best_multiplier = 1;
  int best_base = amin;
  int best_indices[16] = {};
  for (int table = 0; table < 16; ++table) {
    int tmin = 255;
    int tmax = -255;
    for (int i = 0; i < 8; ++i) {
      tmin = std::min(tmin, detail::kAlphaTables[table][i]);
      tmax = std::max(tmax, detail::kAlphaTables[table][i]);
    }
    int tspan = tmax - tmin;
    int multiplier = span == 0 ? 1 : detail::ClampInt((span + tspan / 2) / tspan, 1, 15);
    int base = amin - tmin * multiplier;
    base = detail::ClampInt(base, 0, 255);
    int indices[16] = {};
    int error = 0;
    for (int pass = 0; pass < 2; ++pass) {
      error = 0;
      for (int i = 0; i < 16; ++i) {
        int best_index = 0;
        int best_index_error = 1 << 30;
        for (int index = 0; index < 8; ++index) {
          int decoded =
              detail::ClampInt(base + detail::kAlphaTables[table][index] * multiplier, 0, 255);
          int e = decoded - int(alpha[i]);
          e *= e;
          if (e < best_index_error) {
            best_index_error = e;
            best_index = index;
          }
        }
        indices[i] = best_index;
        error += best_index_error;
      }
      if (pass == 0) {
        int sum = 0;
        for (int i = 0; i < 16; ++i) {
          sum += int(alpha[i]) - detail::kAlphaTables[table][indices[i]] * multiplier;
        }
        base = detail::ClampInt((sum + 8) / 16, 0, 255);
      }
    }
    if (error < best_error) {
      best_error = error;
      best_table = table;
      best_multiplier = multiplier;
      best_base = base;
      std::memcpy(best_indices, indices, sizeof(best_indices));
    }
  }
  uint64_t index_bits = 0;
  for (int i = 0; i < 16; ++i) {
    index_bits |= uint64_t(best_indices[i]) << (3 * (15 - i));
  }
  out[0] = uint8_t(best_base);
  out[1] = uint8_t((best_multiplier << 4) | best_table);
  out[2] = uint8_t((index_bits >> 40) & 0xFF);
  out[3] = uint8_t((index_bits >> 32) & 0xFF);
  out[4] = uint8_t((index_bits >> 24) & 0xFF);
  out[5] = uint8_t((index_bits >> 16) & 0xFF);
  out[6] = uint8_t((index_bits >> 8) & 0xFF);
  out[7] = uint8_t(index_bits & 0xFF);
}

// Encodes 16 RGBA texels (row-major) as one ETC2_RGBA8 block (16 bytes):
// the EAC alpha block first, then the ETC2_RGB8 color block.
inline void EncodeEtc2Rgba8(const Rgba pixels[16], uint8_t out[16]) {
  uint8_t alpha[16];
  for (int i = 0; i < 16; ++i) {
    alpha[i] = pixels[i].a;
  }
  EncodeEtc2AlphaBlock(alpha, out);
  EncodeEtc2Rgb8(pixels, out + 8);
}

}  // namespace rex::graphics::vulkan::etc2
