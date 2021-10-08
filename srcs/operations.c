#include "ft_ssl.h"

Word_32bits leftRotate(Word_32bits x, Word_32bits r)
{
    return (x << r | x >> (32 - r));
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

Long_64bits  extend_mod_chunkSz(Mem_8bits **data, Long_64bits byteSz)
{
    Long_64bits extend_byteSz = byteSz - (byteSz % CHUNK_ByteSz) + CHUNK_ByteSz;
    Mem_8bits *extend;

    if (!(extend = (Mem_8bits *)malloc(sizeof(Mem_8bits) * extend_byteSz)))
        md5_failure("Malloc failed.");
    ft_bzero(extend, extend_byteSz); //Padding with zeros
    // ft_fill(extend, extend_byteSz, ' '); //Padding with zeros
    ft_memcpy(extend, *data, byteSz);
    free(*data);
    *data = extend;
    return extend_byteSz;
}

void        padding(Mem_8bits **data, Long_64bits *byteSz)
{
    Long_64bits extend_byteSz = extend_mod_chunkSz(data, *byteSz);

    // printHex(*data, extend_byteSz);
    // printBits(*data, extend_byteSz);

    Mem_8bits   byteSz_mem[LONG64_ByteSz];
    ft_bzero(byteSz_mem, LONG64_ByteSz);
    ft_memcpy(byteSz_mem, byteSz, LONG64_ByteSz);

    // printHex(byteSz_mem, LONG64_ByteSz);
    // printBits(byteSz_mem, LONG64_ByteSz);

    endianReverse((Mem_8bits *)byteSz_mem, LONG64_ByteSz);

    // printf("LONG64_ByteSz: %lu\nbyteSz_mem:\n", LONG64_ByteSz);
    // printHex(byteSz_mem, LONG64_ByteSz);
    // printBits(byteSz_mem, LONG64_ByteSz);

    Mem_8bits endmsg = ENDMSG;
    ft_memcpy(*data + *byteSz, &endmsg, sizeof(Mem_8bits));

    // Mem_8bits   *msgSz_addr = *data + extend_byteSz - LONG64_ByteSz;
    // printHex(msgSz_addr, LONG64_ByteSz);
    // printf("msgSz_addr:\n");
    // printBits(msgSz_addr, LONG64_ByteSz);

    ft_memcpy(*data + extend_byteSz - LONG64_ByteSz, byteSz_mem, LONG64_ByteSz);
    // ft_memcpy(msgSz_addr, byteSz_mem, LONG64_ByteSz);

    // printf("extend_byteSz: %lu\n", extend_byteSz);
    // printHex(*data, extend_byteSz);
    // printBits(*data, extend_byteSz);
    *byteSz = extend_byteSz;
}
