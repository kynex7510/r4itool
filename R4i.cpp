#define _CRT_SECURE_NO_WARNINGS

#include "DES.h"

#include "R4i.hpp"

#include <cstdio>

using namespace r4i;

// Globals

constexpr static u16 SECRET_MAGIC_1 = 0x2F3F;
constexpr static u16 SECRET_MAGIC_2 = 0x4023;

constexpr static u8 DES_KEY_1[7] = {0x32, 0xF3, 0x12, 0xED, 0x21, 0x55, 0xDC};
constexpr static u8 DES_KEY_2[7] = {0x75, 0xB2, 0xCF, 0x11, 0x89, 0x43, 0xDF};

constexpr static u16 CRC16_TABLE[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241, 0xC601,
    0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440, 0xCC01, 0x0CC0,
    0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40, 0x0A00, 0xCAC1, 0xCB81,
    0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841, 0xD801, 0x18C0, 0x1980, 0xD941,
    0x1B00, 0xDBC1, 0xDA81, 0x1A40, 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01,
    0x1DC0, 0x1C80, 0xDC41, 0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0,
    0x1680, 0xD641, 0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081,
    0x1040, 0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441, 0x3C00,
    0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41, 0xFA01, 0x3AC0,
    0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840, 0x2800, 0xE8C1, 0xE981,
    0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41, 0xEE01, 0x2EC0, 0x2F80, 0xEF41,
    0x2D00, 0xEDC1, 0xEC81, 0x2C40, 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700,
    0xE7C1, 0xE681, 0x2640, 0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0,
    0x2080, 0xE041, 0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281,
    0x6240, 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41, 0xAA01,
    0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840, 0x7800, 0xB8C1,
    0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41, 0xBE01, 0x7EC0, 0x7F80,
    0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40, 0xB401, 0x74C0, 0x7580, 0xB541,
    0x7700, 0xB7C1, 0xB681, 0x7640, 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101,
    0x71C0, 0x7080, 0xB041, 0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0,
    0x5280, 0x9241, 0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481,
    0x5440, 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841, 0x8801,
    0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40, 0x4E00, 0x8EC1,
    0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41, 0x4400, 0x84C1, 0x8581,
    0x4540, 0x8701, 0x47C0, 0x4681, 0x8641, 0x8201, 0x42C0, 0x4380, 0x8341,
    0x4100, 0x81C1, 0x8081, 0x4040};

// Helpers

static u16 crc16(std::span<const u16> const data, bool ldr) {
  u16 crc = 0xFFFF;

  for (auto i = 0u; i < data.size(); ++i) {
    auto const idx = (crc ^ data[i]) & 0xFF;
    auto k = CRC16_TABLE[idx];

    // For ldrchk table[246] has first bit clear.
    // Someone woke up and chose violence.
    // Dont feel like embedding a different table just for this.
    if (ldr && idx == 246)
      k &= ~1;

    crc = k ^ (crc >> 8);
  }

  return crc;
}

static void cipher(std::span<const u8> const in, std::span<u8> out) {
  u8 tmp0[8];
  u8 tmp1[8];

  if (in.size() != 8 || out.size() != 16)
    return;

  des_encrypt(tmp0, in.data(), DES_KEY_1);
  des_encrypt(tmp1, tmp0, DES_KEY_2);
  des_encrypt(tmp0, tmp1, DES_KEY_2);

  for (auto i = 0; i < 8; ++i) {
    out[i] = tmp0[i];
    out[i + 8] = tmp1[i];
  }
}

// R4i

// Many thanks to stuckpixel for this clean version!
u16 r4i::decodeU16(u16 in) {
  u16 out = 0;

  out |= ((in & 0x0040) >> 6);
  out |= ((in & 0x0002) >> 0);
  out |= ((in & 0x1000) >> 10);
  out |= ((in & 0x4000) >> 11);
  out |= ((in & 0x2000) >> 9);
  out |= ((in & 0x0800) >> 6);
  out |= ((in & 0x0100) >> 2);
  out |= ((in & 0x0004) << 5);
  out |= ((in & 0x0010) << 4);
  out |= ((in & 0x0020) << 4);
  out |= ((in & 0x0001) << 10);
  out |= ((in & 0x0200) << 2);
  out |= ((in & 0x0080) << 5);
  out |= ((in & 0x0400) << 3);
  out |= ((in & 0x8000) >> 1);
  out |= ((in & 0x0008) << 12);

  return out;
}

u16 r4i::encodeU16(u16 in) {
  u16 out = 0;

  out |= ((in >> 12) & 0x0008);
  out |= ((in << 1) & 0x8000);
  out |= ((in >> 3) & 0x0400);
  out |= ((in >> 5) & 0x0080);
  out |= ((in >> 2) & 0x0200);
  out |= ((in >> 10) & 0x0001);
  out |= ((in >> 4) & 0x0020);
  out |= ((in >> 4) & 0x0010);
  out |= ((in >> 5) & 0x0004);
  out |= ((in << 2) & 0x0100);
  out |= ((in << 6) & 0x0800);
  out |= ((in << 9) & 0x2000);
  out |= ((in << 11) & 0x4000);
  out |= ((in << 10) & 0x1000);
  out |= ((in << 0) & 0x0002);
  out |= ((in << 6) & 0x0040);

  return out;
}

std::string r4i::decodeString(std::span<u16 const> const in) {
  char buffer[256] = {};
  u32 const numChars = (decodeU16(in[0]) - 192) & 0xFF;

  for (auto i = 0u; i < numChars; ++i) {
    buffer[i] = static_cast<char>(
        decodeU16(in[i + 1]) -
        static_cast<u8>(CRC16_TABLE[i + (numChars & 0xF) + (numChars >> 4)]));
  }

  buffer[numChars] = '\0';
  return buffer;
}

SecretArea *r4i::findSecretArea(std::span<u8> arm9bin) {
  u16 *p = reinterpret_cast<u16 *>(arm9bin.data());
  auto const size = (arm9bin.size() >> 1) - 1;
  for (auto i = 0u; i < size; ++i) {
    if (p[i] == SECRET_MAGIC_1 && p[i + 1] == SECRET_MAGIC_2)
      return reinterpret_cast<SecretArea *>(&p[i]);
  }

  return nullptr;
}

u16 r4i::genChecksum9(std::span<u8 const> const arm9bin) {
  u16 crc = 0xFFFF;
  u16 const *p = reinterpret_cast<u16 const *>(arm9bin.data());
  auto const size = ((arm9bin.size() >> 1) - 1) & 0xFFFFF;

  for (auto i = 0u; i < size; ++i) {
    while (true) {
      if (p[i] != SECRET_MAGIC_1 || p[i + 1] != SECRET_MAGIC_2)
        break;

      i += 8;
      if (size <= i)
        return crc;
    }

    if ((size - 0x900) >= i || (size - 0x200) <= i)
      crc = (crc >> 8) ^ CRC16_TABLE[(p[i] ^ crc) & 0xFF];
  }

  return crc;
}

u16 r4i::genChecksum7(std::span<u8 const> const arm7bin) {
  return crc16({reinterpret_cast<u16 const *>(arm7bin.data()),
                ((arm7bin.size() >> 1) - 3) & 0xFFFFF},
               false);
}

u16 r4i::genChecksumLdr(std::span<u8 const> const ldr9bin,
                        std::span<u8 const> const ldr7bin) {
  u16 const chk9 = crc16({reinterpret_cast<u16 const *>(ldr9bin.data()),
                          ((ldr9bin.size() >> 1) - 1) & 0xFFFFF},
                         true);
  u16 const chk7 = crc16({reinterpret_cast<u16 const *>(ldr7bin.data()),
                          ((ldr7bin.size() >> 1) - 1) & 0xFFFFF},
                         true);
  return chk9 + chk7;
}

u32 r4i::genAreaChk(u16 arm9chk, u16 arm7chk, u16 ldrchk) {
  char buffer[9];
  u32 words[4];

  sprintf(buffer, "%08lx", (static_cast<u32>(arm7chk) << 16) | arm9chk);
  cipher({reinterpret_cast<uint8_t *>(buffer), 8},
         {reinterpret_cast<u8 *>(words), 16});

  auto const chk = words[0];
  return chk >= 0x2000000 ? (chk - ldrchk) : (chk + ldrchk);
}