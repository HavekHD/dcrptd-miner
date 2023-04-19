/*
 * Pufferfish2 - an adaptive password hashing scheme
 *
 * Copyright 2015, Jeremi M Gosney. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
*/

#include <stdint.h>
#include <string.h>
#include <immintrin.h>

#include "pufferfish2.h"

#define shl(x,n) _mm_slli_si128(x, n)
#define shr(x,n) _mm_srli_si128(x, n)

#define chr64(x) itoa64[x]
#define SBOX(x)   S[x]
#define HASH_SBOX(key)                                      \
    do                                                      \
    {                                                       \
        for (i = 0; i < PF_SBOX_N; i++)                      \
        {                                                   \
            for (j = 0; j < (PF_DIGEST_LENGTH / 8); j++)     \
                SBOX(i)[j] = SBOX(i)[j] ^ key_u64[j];       \
            ENCRYPT(SBOX(i));                               \
        }                                                   \
    } while (0)

#define HASH_SBOX_O(key, out)                               \
    do                                                      \
    {                                                       \
        for (i = 0; i < PF_SBOX_N; i++)                      \
        {                                                   \
            for (j = 0; j < (PF_DIGEST_LENGTH / 8); j++)     \
                SBOX(i)[j] = SBOX(i)[j] ^ key_u64[j];       \
            ENCRYPT(SBOX(i));                               \
        }                                                   \
        memcpy(out, key, PF_DIGEST_LENGTH);                  \
    } while (0)

size_t pf_encode(char *dst, void *src, size_t size)
{
    uint8_t *dptr = (uint8_t *) dst;
    uint8_t *sptr = (uint8_t *) src;
    uint8_t *end  = (uint8_t *) sptr + size;
    uint8_t c1, c2;
    uint8_t itoa64[64] = PF_64CHARS;

    do
    {
        c1 = *sptr++;
        *dptr++ = itoa64[shr(c1, 2)];
        c1 = shl((c1 & 0x03), 4);

        if (sptr >= end)
        {
            *dptr++ = itoa64[c1];
            break;
        }

        c2 = *sptr++;
        c1 |= shr(c2, 4) & 0x0f;
        *dptr++ = itoa64[c1];
        c1 = shl((c2 & 0x0f), 2);

        if (sptr >= end)
        {
            *dptr++ = itoa64[c1];
            break;
        }

        c2 = *sptr++;
        c1 |= shr(c2, 6) & 0x03;
        *dptr++ = itoa64[c1];
        *dptr++ = itoa64[c2 & 0x3f];
    }
    while (sptr < end);

    return ((char *)dptr - dst);
}

size_t pf_decode(void *dst, char *src, size_t size)
{
    uint8_t *sptr = (uint8_t *) src;
    uint8_t *dptr = (uint8_t *) dst;
    uint8_t *end = (uint8_t *) dst + size;
    uint8_t c1, c2, c3, c4;
    uint8_t itoa64[256] = { 0 };

    for (int i = 0; i < 64; i++)
        itoa64[(uint8_t)PF