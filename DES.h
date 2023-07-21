#ifndef _DES_H
#define _DES_H

#if defined(__cplusplus)
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

void des_encrypt(uint8_t *out, uint8_t const *block, uint8_t const *key);

#if defined(__cplusplus)
}
#endif

#endif /* _DES_H */