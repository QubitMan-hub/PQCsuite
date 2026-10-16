#include <stdint.h>

static const uint32_t T[4] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee };

void md5_init(uint32_t h[4])
{
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
}
