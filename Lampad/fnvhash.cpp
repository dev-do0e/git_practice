#include "fnvhash.h"

unsigned int fnv32(const unsigned char rawData, unsigned int feed)
{
    // multiply by the 32 bit FNV magic prime mod 2^32
    feed *= 16777619; // 2^24+2^8+0x93 = FNV_Prime for 32bit hash
    // xor the bottom with the current octet
    feed ^= rawData;

    return feed;
}

unsigned int fnv32a(const unsigned char rawData, unsigned int feed)
{
    // xor the bottom with the current octet
    feed ^= rawData;
    // multiply by the 32 bit FNV magic prime mod 2^32
    feed *= 16777619; // 2^24+2^8+0x93 = FNV_Prime for 32bit hash

    return feed;
}

unsigned int fnv32(const void *rawData, const int size, unsigned int feed)
{
    const unsigned char *cursor = (const unsigned char *)rawData;
    const unsigned char *boundary = cursor + size; // beyond end of buffer

    while (cursor < boundary) {
        // multiply by the 32 bit FNV magic prime mod 2^32
        feed *= 16777619; // 2^24+2^8+0x93 = FNV_Prime for 32bit hash
        // xor the bottom with the current octet
        feed ^= *cursor++;
    }

    return feed;
}

unsigned int fnv32a(const void *rawData, const int size, unsigned int feed)
{
    const unsigned char *cursor = (const unsigned char *)rawData;
    const unsigned char *boundary = cursor + size; // beyond end of buffer

    while (cursor < boundary) {
        // xor the bottom with the current octet
        feed ^= *cursor++;
        // multiply by the 32 bit FNV magic prime mod 2^32
        feed *= 16777619; // 2^24+2^8+0x93 = FNV_Prime for 32bit hash
    }

    return feed;
}

uint64_t fnv64(const unsigned char rawData, unsigned long long feed)
{
    // multiply by the 64 bit FNV magic prime mod 2^32
    feed *= 1099511628211; // 2^40 + 2^8 + 0xb3  = FNV_Prime for 64bit hash
    // xor the bottom with the current octet
    feed ^= rawData;

    return feed;
}

uint64_t fnv64a(const unsigned char rawData, unsigned long long feed)
{
    // xor the bottom with the current octet
    feed ^= rawData;
    // multiply by the 64 bit FNV magic prime mod 2^32
    feed *= 1099511628211; // 2^40 + 2^8 + 0xb3  = FNV_Prime for 64bit hash

    return feed;
}

uint64_t fnv64(const void *rawData, const int size, unsigned long long feed)
{
    const unsigned char *cursor = (const unsigned char *)rawData;
    const unsigned char *boundary = cursor + size; // beyond end of buffer

    while (cursor < boundary) {
        // multiply by the 64 bit FNV magic prime mod 2^32
        feed *= 1099511628211; // 2^40 + 2^8 + 0xb3  = FNV_Prime for 64bit hash
        // xor the bottom with the current octet
        feed ^= *cursor++;
    }

    return feed;
}

uint64_t fnv64a(const void *rawData, const int size, unsigned long long feed)
{
    const unsigned char *cursor = (const unsigned char *)rawData;
    const unsigned char *boundary = cursor + size; // beyond end of buffer

    while (cursor < boundary) {
        // xor the bottom with the current octet
        feed ^= *cursor++;
        // multiply by the 64 bit FNV magic prime mod 2^32
        feed *= 1099511628211; // 2^40 + 2^8 + 0xb3  = FNV_Prime for 64bit hash
    }

    return feed;
}
