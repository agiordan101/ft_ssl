#include "ft_ssl.h"

Long_64bits extend_mod_chunkSz(Mem_8bits **data, Long_64bits byteSz)
{
    Mem_8bits   *extend;
    Long_64bits extend_byteSz =\
        byteSz - (byteSz % CHUNK_ByteSz) + // Find byteSz of the filled chunks.
        CHUNK_ByteSz * (byteSz % CHUNK_ByteSz >= CHUNK_ByteSz - LONG64_ByteSz ? 2 : 1); // Add 1 chunk (witch is partially written), and add another one if we cannot cpy byteSz_mem at the end (overwritting is not possible)

    if (!(extend = (Mem_8bits *)malloc(sizeof(Mem_8bits) * (extend_byteSz + 1))))
    {
        ft_putstr("Malloc failed.");
        freexit(EXIT_FAILURE);
    }
    ft_bzero(extend, extend_byteSz + 1); //Padding with zeros
    ft_memcpy(extend, *data, byteSz);
    free(*data);
    *data = extend;
    return extend_byteSz;
}

void        padding(Mem_8bits **data, Long_64bits *byteSz, char reverseByteSz)
{
    // Extend data until a multiple of chunk size (64 bytes / 512 bits)
    Long_64bits extend_byteSz = extend_mod_chunkSz(data, *byteSz);

    // Append byte "10000000" after msg
    Mem_8bits endmsg = ENDMSG;
    ft_memcpy(*data + *byteSz, &endmsg, sizeof(Mem_8bits));

    Long_64bits byteSz_bitSz = *byteSz * 8;
    Mem_8bits   byteSz_mem[LONG64_ByteSz];
    ft_bzero(byteSz_mem, LONG64_ByteSz);

    // Transform Long_64bits memory to Mem_8bits memory
    ft_memcpy(byteSz_mem, &byteSz_bitSz, LONG64_ByteSz);
    if (reverseByteSz)
        endianReverse(byteSz_mem, LONG64_ByteSz);

    // Overwrite the last 8 bytes of last chunk with input message bits size
    ft_memcpy(*data + extend_byteSz - LONG64_ByteSz, byteSz_mem, LONG64_ByteSz);

    *byteSz = extend_byteSz;
}
