#ifndef _R4I_HPP
#define _R4I_HPP

#include <cstdint>
#include <span>
#include <string>

namespace r4i {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;

#if defined(_MSC_VER)
#pragma pack(push, 2)
#endif

struct alignas(2) SecretArea {
  u32 magic;
  u16 arm9chk;
  u16 arm7chk;
  u16 ldrchk;
  u32 areachk;
  u32 dldiOffset;
};

#if defined(_MSC_VER)
#pragma pack(pop)
#endif

static_assert(sizeof(SecretArea) == 0x12, "Invalid SecretArea size!");

u16 decodeU16(u16 in);
u16 encodeU16(u16 in);

std::string decodeString(std::span<u16 const> const in);

inline std::string decodeString(std::span<u8 const> const in) {
  return decodeString(
      {reinterpret_cast<u16 const *>(in.data()), in.size() >> 1});
}

SecretArea *findSecretArea(std::span<u8> arm9bin);

u16 genChecksum9(std::span<u8 const> const arm9bin);
u16 genChecksum7(std::span<u8 const> const arm7bin);
u16 genChecksumLdr(std::span<u8 const> const ldr9bin,
                   std::span<u8 const> const ldr7bin);
u32 genAreaChk(u16 arm9chk, u16 arm7chk, u16 ldrchk);

} // namespace r4i

#endif /* _R4I_HPP */