#include "ft_ssl.h"

Mem_8bits   *padXbits(Mem_8bits **mem, int byteSz, int newSz)
{
    Mem_8bits   *pad;

    if (byteSz < newSz)
    {
        // if (!(pad = (Mem_8bits *)malloc(sizeof(Mem_8bits) * (newSz + 1))))
		//     malloc_failed("Unable to malloc msg in operations padXbits() function\n");
        // pad[newSz] = '\0';
        // ft_bzero(pad, newSz + 1);
        pad = ft_memnew(newSz);
        ft_memcpy(pad, *mem, byteSz);
        free(*mem);
        *mem = pad;
    }
    else if (newSz < byteSz)
        ft_bzero(*mem + newSz, byteSz - newSz);
    return *mem;
}

void        padding(Mem_8bits **data, Long_64bits *byteSz, char reverseByteSz)
{
    // printf("data: %p\n", *data);
    // printf("byteSz: %ld\n", *byteSz);
    // exit(0);

    Long_64bits extend_byteSz =\
        *byteSz - (*byteSz % CHUNK_ByteSz) + // Find byteSz of the filled chunks.
        CHUNK_ByteSz * (*byteSz % CHUNK_ByteSz >= CHUNK_ByteSz - LONG64_ByteSz ? 2 : 1); // Add 1 chunk (witch is partially written), and add another one if we cannot cpy byteSz_mem at the end (overwritting is not possible)

    // printf("byteSz: %ld\n", *byteSz);
    // printf("extend_byteSz: %ld\n", extend_byteSz);

    // Extend data until a multiple of chunk size (64 bytes / 512 bits)
    padXbits(data, *byteSz, extend_byteSz);

    // Append byte "10000000" after msg
    Mem_8bits endmsg = ENDMSG;
    ft_memcpy(*data + *byteSz, &endmsg, sizeof(Mem_8bits));


    // Transform Long_64bits memory to Mem_8bits memory (endianness matter)
    Long_64bits byteSz_bitSz = *byteSz * 8;
    Mem_8bits   byteSz_mem[LONG64_ByteSz];

    ft_bzero(byteSz_mem, LONG64_ByteSz);
    ft_memcpy(byteSz_mem, &byteSz_bitSz, LONG64_ByteSz);
    if (reverseByteSz)
        endianReverse(byteSz_mem, LONG64_ByteSz);

    // Overwrite the last 8 bytes of last chunk with input message bits size
    ft_memcpy(*data + extend_byteSz - LONG64_ByteSz, byteSz_mem, LONG64_ByteSz);

    *byteSz = extend_byteSz;
}
