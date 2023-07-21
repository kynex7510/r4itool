// Adapted from https://github.com/mbrown1413/des/blob/master/des.c

/*
    MIT License

    Copyright (c) 2019 Michael S. Brown

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
   deal in the Software without restriction, including without limitation the
   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
   sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.
*/

#include "des.h"

// Globals

static uint8_t const IP_LEFT[32] = {57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43,
                                    35, 27, 19, 11, 3,  61, 53, 45, 37, 29, 21,
                                    13, 5,  63, 55, 47, 39, 31, 23, 15, 7};

static uint8_t const IP_RIGHT[32] = {56, 48, 40, 32, 24, 16, 8,  0,  58, 50, 42,
                                     34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20,
                                     12, 4,  62, 54, 46, 38, 30, 22, 14, 6};

static uint8_t const FINAL_PERM[64] = {
    7, 39, 15, 47, 23, 55, 31, 63, 6, 38, 14, 46, 22, 54, 30, 62,
    5, 37, 13, 45, 21, 53, 29, 61, 4, 36, 12, 44, 20, 52, 28, 60,
    3, 35, 11, 43, 19, 51, 27, 59, 2, 34, 10, 42, 18, 50, 26, 58,
    1, 33, 9,  41, 17, 49, 25, 57, 0, 32, 8,  40, 16, 48, 24, 56};

static uint8_t const EXPANSION_PERM[48] = {
    31, 0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9,  10,
    11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
    21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0};

static uint8_t const FEISTEL_END_PERM[32] = {
    15, 6, 19, 20, 28, 11, 27, 16, 0,  14, 22, 25, 4,  17, 30, 9,
    1,  7, 23, 13, 31, 26, 2,  8,  18, 12, 29, 5,  21, 10, 3,  24};

// Modified to match the one used by r4i.
static uint8_t const PC1[56] = {
    49, 42, 35, 28, 21, 14, 7,  0,  50, 43, 36, 29, 22, 15, 8,  1,  51, 44, 37,
    30, 23, 16, 9,  2,  52, 45, 38, 31, 55, 48, 41, 34, 27, 20, 13, 6,  54, 47,
    40, 33, 26, 19, 12, 5,  53, 46, 39, 32, 25, 18, 11, 4,  24, 17, 10, 3};

static uint8_t const PC2[48] = {13, 16, 10, 23, 0,  4,  2,  27, 14, 5,  20, 9,
                                22, 18, 11, 3,  25, 7,  15, 6,  26, 19, 12, 1,
                                40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
                                43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31};

static uint8_t const SBOX_0[64] = {
    14, 0,  4,  15, 13, 7,  1,  4,  2,  14, 15, 2, 11, 13, 8,  1,
    3,  10, 10, 6,  6,  12, 12, 11, 5,  9,  9,  5, 0,  3,  7,  8,
    4,  15, 1,  12, 14, 8,  8,  2,  13, 4,  6,  9, 2,  1,  11, 7,
    15, 5,  12, 11, 9,  3,  7,  14, 3,  10, 10, 0, 5,  6,  0,  13};

static uint8_t const SBOX_1[64] = {
    15, 3,  1,  13, 8,  4,  14, 7,  6,  15, 11, 2,  3,  8,  4,  14,
    9,  12, 7,  0,  2,  1,  13, 10, 12, 6,  0,  9,  5,  11, 10, 5,
    0,  13, 14, 8,  7,  10, 11, 1,  10, 3,  4,  15, 13, 4,  1,  2,
    5,  11, 8,  6,  12, 7,  6,  12, 9,  0,  3,  5,  2,  14, 15, 9};

static uint8_t const SBOX_2[64] = {
    10, 13, 0,  7,  9,  0,  14, 9,  6,  3,  3,  4,  15, 6,  5, 10,
    1,  2,  13, 8,  12, 5,  7,  14, 11, 12, 4,  11, 2,  15, 8, 1,
    13, 1,  6,  10, 4,  13, 9,  0,  8,  6,  15, 9,  3,  8,  0, 7,
    11, 4,  1,  15, 2,  14, 12, 3,  5,  11, 10, 5,  14, 2,  7, 12};

static uint8_t const SBOX_3[64] = {
    7,  13, 13, 8,  14, 11, 3,  5,  0,  6,  6,  15, 9, 0,  10, 3,
    1,  4,  2,  7,  8,  2,  5,  12, 11, 1,  12, 10, 4, 14, 15, 9,
    10, 3,  6,  15, 9,  0,  0,  6,  12, 10, 11, 1,  7, 13, 13, 8,
    15, 9,  1,  4,  3,  5,  14, 11, 5,  12, 2,  7,  8, 2,  4,  14};

static uint8_t const SBOX_4[64] = {
    2,  14, 12, 11, 4,  2,  1,  12, 7,  4,  10, 7,  11, 13, 6,  1,
    8,  5,  5,  0,  3,  15, 15, 10, 13, 3,  0,  9,  14, 8,  9,  6,
    4,  11, 2,  8,  1,  12, 11, 7,  10, 1,  13, 14, 7,  2,  8,  13,
    15, 6,  9,  15, 12, 0,  5,  9,  6,  10, 3,  4,  0,  5,  14, 3};

static uint8_t const SBOX_5[64] = {
    12, 10, 1,  15, 10, 4,  15, 2,  9,  7, 2,  12, 6,  9,  8,  5,
    0,  6,  13, 1,  3,  13, 4,  14, 14, 0, 7,  11, 5,  3,  11, 8,
    9,  4,  14, 3,  15, 2,  5,  12, 2,  9, 8,  5,  12, 15, 3,  10,
    7,  11, 0,  14, 4,  1,  10, 7,  1,  6, 13, 0,  11, 8,  6,  13};

static uint8_t const SBOX_6[64] = {
    4,  13, 11, 0,  2,  11, 14, 7,  15, 4,  0,  9,  8, 1,  13, 10,
    3,  14, 12, 3,  9,  5,  7,  12, 5,  2,  10, 15, 6, 8,  1,  6,
    1,  6,  4,  11, 11, 13, 13, 8,  12, 1,  3,  4,  7, 10, 14, 7,
    10, 9,  15, 5,  6,  0,  8,  15, 0,  14, 5,  2,  9, 3,  2,  12};

static uint8_t const SBOX_7[64] = {
    13, 1,  2,  15, 8,  13, 4,  8,  6,  10, 15, 3,  11, 7, 1, 4,
    10, 12, 9,  5,  3,  6,  14, 11, 5,  0,  0,  14, 12, 9, 7, 2,
    7,  2,  11, 1,  4,  14, 1,  7,  9,  4,  12, 10, 14, 8, 2, 13,
    0,  15, 6,  12, 10, 9,  13, 0,  15, 3,  3,  5,  5,  6, 8, 11};

static uint8_t const SHIFT_AMOUNTS[16] = {1, 1, 2, 2, 2, 2, 2, 2,
                                          1, 2, 2, 2, 2, 2, 2, 1};

// Helpers

static void xorBlocks(uint8_t const *in1, uint8_t const *in2, uint8_t *out,
                      size_t size) {
  for (size_t i = 0; i < size; i++)
    out[i] = in1[i] ^ in2[i];
}

static void permute(uint8_t const *in, uint8_t const *table, uint8_t *out,
                    size_t size) {
  for (size_t i = 0; i < size; i++) {
    uint8_t result_byte = 0x00;

    for (size_t j = 0; j < 8; j++) {
      uint8_t bit_pos = *table % 8;
      uint8_t mask = 0x80 >> bit_pos;
      uint8_t result_bit = (in[*table / 8] & mask) << bit_pos;
      result_byte |= result_bit >> j;
      table++;
    }

    out[i] = result_byte;
  }
}

static void keyShift(uint8_t const key[7], uint8_t output[7], uint8_t amount) {
  uint8_t mask;

  for (size_t i = 0; i < 7; i++)
    output[i] = (key[i] << amount) | (key[i + 1] >> (8 - amount));

  if (amount == 1) {
    mask = 0xEF;
  } else {
    mask = 0xCF;
  }

  output[3] &= mask;
  output[3] |= (key[0] >> (4 - amount)) & ~mask;

  if (amount == 1) {
    mask = 0x01;
  } else {
    mask = 0x03;
  }

  output[6] = (key[6] << amount) | ((key[3] >> (4 - amount)) & mask);
}

static void sbox(uint8_t const input[6], uint8_t output[4]) {
  uint8_t input_byte;

  input_byte = (input[0] & 0xFC) >> 2;
  output[0] = SBOX_0[input_byte] << 4;

  input_byte = ((input[0] & 0x03) << 4) + ((input[1] & 0xF0) >> 4);
  output[0] = output[0] | SBOX_1[input_byte];

  input_byte = ((input[1] & 0x0F) << 2) + ((input[2] & 0xC0) >> 6);
  output[1] = SBOX_2[input_byte] << 4;

  input_byte = (input[2] & 0x3F);
  output[1] = output[1] | SBOX_3[input_byte];

  input_byte = (input[3] & 0xFC) >> 2;
  output[2] = SBOX_4[input_byte] << 4;
  output[2] = SBOX_4[input_byte] << 4;

  input_byte = ((input[3] & 0x03) << 4) + ((input[4] & 0xF0) >> 4);
  output[2] = output[2] | SBOX_5[input_byte];

  input_byte = ((input[4] & 0x0F) << 2) + ((input[5] & 0xC0) >> 6);
  output[3] = SBOX_6[input_byte] << 4;

  input_byte = (input[5] & 0x3F);
  output[3] = output[3] | SBOX_7[input_byte];
}

static void feistel(uint8_t const input[4], uint8_t const subkey[6],
                    uint8_t output[4]) {
  uint8_t expanded[6];
  uint8_t SBOXoutput[4];

  permute(input, EXPANSION_PERM, expanded, 6);
  xorBlocks(expanded, subkey, expanded, 6);
  sbox(expanded, SBOXoutput);
  permute(SBOXoutput, FEISTEL_END_PERM, output, 4);
}

// DES

void des_encrypt(uint8_t *out, uint8_t const *block, uint8_t const *key) {
  uint8_t keyHalves1[7];
  uint8_t keyHalves2[7];
  uint8_t subkey[6];
  uint8_t fiestelOutput[4];
  uint8_t leftBlock[8];
  uint8_t *rightBlock = &leftBlock[4];

  permute(block, IP_LEFT, leftBlock, 4);
  permute(block, IP_RIGHT, rightBlock, 4);
  permute(key, PC1, keyHalves1, 7);

  for (size_t i = 0; i < 16; i += 2) {
    keyShift(keyHalves1, keyHalves2, SHIFT_AMOUNTS[i]);
    permute(keyHalves2, PC2, subkey, 6);
    feistel(rightBlock, subkey, fiestelOutput);
    xorBlocks(fiestelOutput, leftBlock, leftBlock, 4);
    keyShift(keyHalves2, keyHalves1, SHIFT_AMOUNTS[i + 1]);
    permute(keyHalves1, PC2, subkey, 6);
    feistel(leftBlock, subkey, fiestelOutput);
    xorBlocks(fiestelOutput, rightBlock, rightBlock, 4);
  }

  permute(leftBlock, FINAL_PERM, out, 8);
}