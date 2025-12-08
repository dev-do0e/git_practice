#ifndef FNVHASH_H
#define FNVHASH_H

#include <cstdint>

unsigned int fnv32(const unsigned char rawData, unsigned int feed=2166136261);
unsigned int fnv32a(const unsigned char rawData, unsigned int feed=2166136261);
unsigned int fnv32(const void *rawData, const int size, unsigned int feed=2166136261);
unsigned int fnv32a(const void *rawData, const int size, unsigned int feed=2166136261);
uint64_t fnv64(const unsigned char rawData, unsigned long long feed=2166136261);
uint64_t fnv64a(const unsigned char rawData, unsigned long long feed=2166136261);
uint64_t fnv64(const void *rawData, const int size, unsigned long long feed=14695981039346656037UL);
uint64_t fnv64a(const void *rawData, const int size, unsigned long long feed=14695981039346656037UL);

#endif // FNVHASH_H
