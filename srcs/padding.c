#include "ft_ssl.h"

Mem_8bits   *padXbits(Mem_8bits **mem, int byteSz, int newSz)
{
    Mem_8bits   *pad;

    if (byteSz < newSz)
    {
        // printf("addr: %p\n", *mem);
        pad = ft_memnew(newSz);
        ft_memcpy(pad, *mem, byteSz);
        free(*mem);
        *mem = pad;
        // printf("addr: %p\n", *mem);
    }
    else if (newSz < byteSz)
        ft_bzero(*mem + newSz, byteSz - newSz);
    return *mem;
}

void        md_padding(Mem_8bits **data, Long_64bits *byteSz, char reverseByteSz)
{
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

Long_64bits des_padding(Mem_8bits *bloc)
{
    Mem_8bits   newbloc[LONG64_ByteSz];
    ft_bzero(newbloc, LONG64_ByteSz);
    int         missing_bytes;
    int         i = -1;

    while (++i < LONG64_ByteSz && bloc[i])
        newbloc[i] = bloc[i];
    missing_bytes = 8 - i;
    // printf("missing_bytes: %d\n", missing_bytes);
    // printf("newbloc: %lx\n", *((Long_64bits *)newbloc));
    while (i < LONG64_ByteSz)
        newbloc[i++] = missing_bytes;
    // printf("newbloc: %lx\n", *((Long_64bits *)newbloc));
    return *((Long_64bits *)newbloc);
}

void        des_unpadding(Long_64bits *lastbloc, int *ptSz)
{
    Mem_8bits   lastbyte = (*lastbloc >> 56) & 0xff;

    // printf("lastbloc : %lx\tptSz : %d\n", *lastbloc, *ptSz);
    // printf("lastbyte : %x\n", lastbyte);
    if (lastbyte == 0x08)
        (*ptSz)--;
    else if (0x01 <= lastbyte && lastbyte <= 0x07)
        *lastbloc = *lastbloc & (((Long_64bits)1 << (64 - lastbyte * 8)) - 1);
    else if (~ssl.flags & nopad)
    {
        ft_putstdout("No padding found in decrypted data.\n");
        freexit(EXIT_FAILURE);
    }
    else
        return ;
    if (ssl.flags & nopad)
    {
        ft_putstdout("-nopad is conflicting with padding found in decrypted data.\n");
        freexit(EXIT_FAILURE);
    }
}
