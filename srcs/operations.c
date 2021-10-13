#include "ft_ssl.h"

Long_64bits extend_mod_chunkSz(Mem_8bits **data, Long_64bits byteSz)
{
    Long_64bits extend_byteSz = byteSz - (byteSz % CHUNK_ByteSz) + CHUNK_ByteSz;
    Mem_8bits *extend;

    if (!(extend = (Mem_8bits *)malloc(sizeof(Mem_8bits) * (extend_byteSz + 1))))
        md5_failure("Malloc failed.");
    ft_bzero(extend, extend_byteSz + 1); //Padding with zeros
    // ft_fill(extend, extend_byteSz, ' '); //Padding with zeros
    ft_memcpy(extend, *data, byteSz);
    free(*data);
    *data = extend;
    return extend_byteSz;
}

void        padding(Mem_8bits **data, Long_64bits *byteSz, char reverseByteSz)
{
    Long_64bits extend_byteSz = extend_mod_chunkSz(data, *byteSz);

    // printHex(*data, extend_byteSz);
    // printBits(*data, extend_byteSz);

    Mem_8bits   byteSz_mem[LONG64_ByteSz];
    ft_bzero(byteSz_mem, LONG64_ByteSz);

    Long_64bits bitSz = *byteSz * 8;
    ft_memcpy(byteSz_mem, &bitSz, LONG64_ByteSz);
    // printBits(byteSz_mem, LONG64_ByteSz);
    // for (int i = 0; i < LONG64_ByteSz; i++)
    //     byteSz_mem[i] = endianReverseByte(byteSz_mem[i]);
    if (reverseByteSz)
        endianReverse(byteSz_mem, LONG64_ByteSz);

    Mem_8bits endmsg = ENDMSG;
    ft_memcpy(*data + *byteSz, &endmsg, sizeof(Mem_8bits));

    ft_memcpy(*data + extend_byteSz - LONG64_ByteSz, byteSz_mem, LONG64_ByteSz);
    *byteSz = extend_byteSz;
}
