#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>

int main() {
    uint8_t block[16] = {0};
    block[0] = 0x00;
    block[5] = 0x01;
    block[10] = 0x02;
    block[15] = 0x03;
    
    __m128i m = _mm_loadu_si128((__m128i*)block);
    __m128i zero = _mm_setzero_si128();
    __m128i res = _mm_aesenclast_si128(m, zero);
    _mm_storeu_si128((__m128i*)block, res);
    
    printf("%02x %02x %02x %02x\n", block[0], block[5], block[10], block[15]);
    return 0;
}
