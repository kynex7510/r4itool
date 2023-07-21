#include "R4i.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace r4i;

static std::vector<u8> readFile(std::string const &path) {
  std::vector<u8> buffer;
  std::ifstream h(path, std::ios::ate | std::ios::binary);
  if (h.is_open()) {
    buffer.resize(h.tellg());
    h.seekg(0, h.beg);
    h.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
  }

  return buffer;
}

static bool writeFile(std::string const &path,
                      std::span<u8 const> const buffer) {
  std::ofstream h(path, std::ios::binary);
  if (h.is_open()) {
    h.write(reinterpret_cast<char const *>(buffer.data()), buffer.size());
    return true;
  }

  return false;
}

static void parseROM(std::vector<u8> &buffer, std::span<u8> &arm9,
                     std::span<u8> &arm7) {
  if (buffer.size() < 0x40)
    return;

  auto const arm9off = *reinterpret_cast<u32 *>(buffer.data() + 0x20);
  auto const arm9size = *reinterpret_cast<u32 *>(buffer.data() + 0x2C);
  if (arm9off > buffer.size() || (arm9off + arm9size) > buffer.size())
    return;

  auto const arm7off = *reinterpret_cast<u32 *>(buffer.data() + 0x30);
  auto const arm7size = *reinterpret_cast<u32 *>(buffer.data() + 0x3C);
  if (arm7off > buffer.size() || (arm7off + arm7size) > buffer.size())
    return;

  arm9 = {buffer.data() + arm9off, arm9size};
  arm7 = {buffer.data() + arm7off, arm7size};
}

int main(int argc, char const *const *argv) {
  if (argc < 3) {
    std::cout << "USAGE: path/to/R4.dat path/to/R4iLoader.dat\n";
    return 1;
  }

  auto r4 = readFile(argv[1]);
  if (r4.empty()) {
    std::cout << "ERROR: Could not load R4.dat!\n";
    return 2;
  }

  auto loader = readFile(argv[2]);
  if (loader.empty()) {
    std::cout << "ERROR: Could not load R4iLoader.dat!\n";
    return 3;
  }

  std::span<u8> arm9;
  std::span<u8> arm7;
  parseROM(r4, arm9, arm7);
  if (arm9.empty() || arm7.empty()) {
    std::cout << "ERROR: R4.dat parsing failed!\n";
    return 4;
  }

  std::span<u8> ldr9;
  std::span<u8> ldr7;
  parseROM(loader, ldr9, ldr7);
  if (ldr9.empty() || ldr7.empty()) {
    std::cout << "ERROR: R4iLoader.dat parsing failed!\n";
    return 5;
  }

  auto secretArea = findSecretArea(arm9);
  if (!secretArea) {
    std::cout << "ERROR: Could not find secret area!\n";
    return 6;
  }

  std::cout << "Secret area:\n";
  std::cout << std::hex;

  // Checksum9
  auto const checksum9 = decodeU16(secretArea->arm9chk);
  auto const computed9 = genChecksum9(arm9);
  std::cout << "- checksum9: " << checksum9 << '\n';
  std::cout << "- computed: " << computed9 << '\n';

  if (checksum9 != computed9)
    std::cout << "DOES NOT MATCH\n";

  std::cout << '\n';

  // Checksum7
  auto const checksum7 = decodeU16(secretArea->arm7chk);
  auto const computed7 = genChecksum7(arm7);
  std::cout << "- checksum7: " << checksum7 << '\n';
  std::cout << "- computed: " << computed7 << '\n';

  if (checksum7 != computed7)
    std::cout << "DOES NOT MATCH\n";

  std::cout << '\n';

  // ChecksumLdr
  auto const checksumLdr = decodeU16(secretArea->ldrchk);
  auto const computedLdr = genChecksumLdr(ldr9, ldr7);
  std::cout << "- checksumLdr: " << checksumLdr << '\n';
  std::cout << "- computed: " << computedLdr << '\n';

  if (checksumLdr != computedLdr)
    std::cout << "DOES NOT MATCH\n";

  std::cout << '\n';

  // Area checksum
  auto const checksumArea = secretArea->areachk;
  auto const computedArea =
      genAreaChk(encodeU16(computed9), encodeU16(computed7), encodeU16(computedLdr));
  std::cout << "- checksumArea: " << checksumArea << '\n';
  std::cout << "- computed: " << computedArea << '\n';

  if (checksumArea != computedArea)
    std::cout << "DOES NOT MATCH\n";

  std::cout << '\n';

  // FIX.
  secretArea->arm9chk = encodeU16(computed9);
  secretArea->arm7chk = encodeU16(computed7);
  secretArea->ldrchk = encodeU16(computedLdr);
  secretArea->areachk = computedArea;

  if (!writeFile("R4-fixed.dat", r4)) {
    std::cout << "ERROR: Could not save R4-fixed.dat!\n";
    return 7;
  }

  std::cout << "File fixed: R4-fixed.dat\n";
  return 0;
}