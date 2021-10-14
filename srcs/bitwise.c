#include "ft_ssl.h"

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

    for (int i = 0; i < 8; i++)
        tmp += (128 >> i) * ((byte >> i) & 1);
    return tmp;
}

void        endianReverse(Mem_8bits *mem, Long_64bits byteSz)
{
    Mem_8bits   tmp[byteSz];
    ft_bzero(tmp, byteSz);

    ft_memcpy(tmp, mem, byteSz);
    for (Long_64bits c = 0; c < byteSz; c++)
        mem[c] = tmp[byteSz - c - 1];
}
