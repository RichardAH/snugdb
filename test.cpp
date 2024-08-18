#include <stdint.h>
#include <stdio.h>

#include "snug.hpp"

using namespace snug;

int main()
{
    uint8_t key[]{
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0};

    uint8_t val[] {0xDE, 0xAD, 0xBE, 0xEF, 0, 0};

    uint8_t big_val[66*1024];

    for (int i = 0; i < 66 * 1024; ++i)
        big_val[i] = i % 256;


//    printf("Bigval: ");
//    for (uint64_t i = 0; i < sizeof(big_val); ++i)
//        printf("%02X ", big_val[i]);

//    printf("\n");


    SnugDB db(".");
    
    for (int i = 0; i < 257; ++i)
    {
        key[2] = i >> 8;
        key[3] = i & 0xFF;
        val[4] = i >> 8;
        val[5] = i & 0xFF;

        if (i % 10 == 1)
            db.write_entry(key, big_val, sizeof(big_val));
        else
            db.write_entry(key, val, sizeof(val));
    }


    for (int i = 0; i < 257; ++i)
    {
        key[2] = i >> 8;
        key[3] = i & 0xFF;
        uint8_t buf[102400];

        uint64_t len = sizeof(buf);

        printf("Read result: %d\n", db.read_entry(key, buf, &len));
        printf("Read len: %lu\n", len);
        printf("Buf: ");
        for (uint64_t i = 0; i < len; ++i)
            printf("%02X ", buf[i]);

        printf("\n");

    }
    return 0;
}
