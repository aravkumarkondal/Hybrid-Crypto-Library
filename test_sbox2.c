#include <arm_neon.h>
#include <stdio.h>
#include <stdint.h>

int main() {
    uint8_t block[16] = {0};
    block[0] = 0x00;
    block[1] = 0x01;
    block[2] = 0x02;
    block[3] = 0x03;
    
    uint8x16_t m = vld1q_u8(block);
    uint8x16_t zero = vdupq_n_u8(0);
    uint8x16_t res = vaeseq_u8(m, zero);
    vst1q_u8(block, res);
    
    printf("%02x %02x %02x %02x\n", block[0], block[13], block[10], block[7]);
    return 0;
}
