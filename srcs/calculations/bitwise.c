#include "ft_ssl.h"

inline Word_32bits  rotL(Word_32bits x, Word_32bits r)
{
    return (x << r | x >> (32 - r));
}

inline Word_32bits  rotR(Word_32bits x, Word_32bits r)
{
    return (x << (32 - r) | x >> r);
}

Mem_8bits           endianReverseByte(Mem_8bits byte)
{
    Mem_8bits tmp = 0;

    for (int i = 0; i < 8; i++)
        tmp += (128 >> i) * ((byte >> i) & 1);
    return tmp;
}

void                endianReverse(Mem_8bits *mem, Long_64bits byteSz)
{
    Mem_8bits   tmp[byteSz];
    ft_bzero(tmp, byteSz);

    ft_memcpy(tmp, mem, byteSz);
    for (Long_64bits c = 0; c < byteSz; c++)
        mem[c] = tmp[byteSz - c - 1];
}


Long_64bits     bits_permutations(Long_64bits mem, char *ptable, int bitLen)
{
    Long_64bits tk = 0;
    for (int i = 0; i < bitLen; i++)
    {
        int nb = ptable[i] - 1;
        int ni = i;
        int mod = nb % 8;
        int modi = i % 8;
        nb = nb - mod + 7 - mod;
        ni = ni - modi + 7 - modi;
        tk |= (((mem >> (nb)) & 1) << ni);
    }
    return tk;
}

Long_64bits     _bits_permutations(Long_64bits mem, char *ptable, int bitLen)
{
    Long_64bits tk = 0;
    for (int i = 0; i < bitLen; i++)
    {
        int nb = ptable[i] - 1;
        int ni = i;
        tk |= (((mem >> (nb)) & 1) << ni);
    }
    return tk;
}

inline int       count_bytes(Long_64bits n)
{
    int count = 1;
    while (n >> 8)
    {
        count++;
        n >>= 8;
    }
    return count;
}

inline int      count_bits(Long_64bits n)
{
    int bitSz = 0;

    for (int i = 0; i < LONG64_byteSz * 8; i++)
    {
        if (n & 1)
            bitSz = i + 1;
        n >>= 1;
    }
    return bitSz;
}
