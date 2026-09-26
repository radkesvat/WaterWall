#include "lwip/inet_chksum.h"
#include <stdint.h>
#include <stdio.h>

/* Link from the standalone lwIP archive and call it before any WaterWall init. */
int main(void)
{
    const uint8_t  input[] = {1, 2, 3};
    const uint16_t result  = inet_chksum(input, sizeof(input));
    const uint8_t *bytes   = (const uint8_t *) &result;
    if (bytes[0] != 0xfb || bytes[1] != 0xfd)
    {
        fputs("standalone lwIP checksum bytes differ\n", stderr);
        return 1;
    }
    uint8_t carry_input[24] = {0};
    for (unsigned i = 0; i < 16; ++i)
    {
        carry_input[i] = 255;
    }
    carry_input[23]             = 1;
    const uint16_t carry_result = inet_chksum(carry_input, sizeof(carry_input));
    bytes                       = (const uint8_t *) &carry_result;
    if (bytes[0] != 0xff || bytes[1] != 0xfe)
    {
        fprintf(stderr, "pre-init portable carry: expected ff fe, got %02x %02x\n", bytes[0], bytes[1]);
        return 1;
    }
    return 0;
}
