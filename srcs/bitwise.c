#include "ft_ssl.h"

// Word_32bits addMod32(Word_32bits a, Word_32bits b)
// {
//     return (a + b >= UINTMAX ? a - UINTMAX + b : a + b);
// }

inline Word_32bits rotL(Word_32bits x, Word_32bits r)
{
    return (x << r | x >> (32 - r));
}

inline Word_32bits rotR(Word_32bits x, Word_32bits r)
{
    return (x << (32 - r) | x >> r);
}

Mem_8bits   endianReverseByte(Mem_8bits byte)
{
    Mem_8bits tmp = 0;

    // printByte(byte);
    for (int i = 0; i < 8; i++)
    {
        // printf("1 << i: %d\tbyte >> i: %d\t(byte >> i) & 1: %d\n", 128 >> i, byte >> i, (byte >> i) & 1);
        tmp += (128 >> i) * ((byte >> i) & 1);
    }
    // printByte(tmp);
    return tmp;
}

void        endianReverse(Mem_8bits *mem, Long_64bits byteSz)
{
    Mem_8bits   tmp[byteSz];
    ft_bzero(tmp, byteSz);

    // printHex(mem, byteSz);
    ft_memcpy(tmp, mem, byteSz);
    for (Long_64bits c = 0; c < byteSz; c++)
        mem[c] = tmp[byteSz - c - 1];
}
