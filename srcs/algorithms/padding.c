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
        *byteSz - (*byteSz % CHUNK_byteSz) + // Find byteSz of the filled chunks.
        CHUNK_byteSz * (*byteSz % CHUNK_byteSz >= CHUNK_byteSz - LONG64_byteSz ? 2 : 1); // Add 1 chunk (witch is partially written), and add another one if we cannot cpy byteSz_mem at the end (overwritting is not possible)

    // printf("byteSz: %ld\n", *byteSz);
    // printf("extend_byteSz: %ld\n", extend_byteSz);

    // Extend data until a multiple of chunk size (64 bytes / 512 bits)
    padXbits(data, *byteSz, extend_byteSz);

    // Append byte "10000000" after msg
    Mem_8bits endmsg = ENDMSG;
    ft_memcpy(*data + *byteSz, &endmsg, sizeof(Mem_8bits));

    // Transform Long_64bits memory to Mem_8bits memory (endianness matter)
    Long_64bits byteSz_bitSz = *byteSz * 8;
    Mem_8bits   byteSz_mem[LONG64_byteSz];

    ft_bzero(byteSz_mem, LONG64_byteSz);
    ft_memcpy(byteSz_mem, &byteSz_bitSz, LONG64_byteSz);
    if (reverseByteSz)
        endianReverse(byteSz_mem, LONG64_byteSz);

    // Overwrite the last 8 bytes of last chunk with input message bits size
    ft_memcpy(*data + extend_byteSz - LONG64_byteSz, byteSz_mem, LONG64_byteSz);

    // printMemHex(*data, extend_byteSz, "md padding");
    *byteSz = extend_byteSz;
}

Long_64bits des_padding(Mem_8bits *bloc, Long_64bits blocByteSz)
{
    Mem_8bits   newbloc[LONG64_byteSz];
    int         missing_bytes = 8 - blocByteSz;

    // fprintf(stderr, "bloc (byteSz=%d): %lx\n", blocByteSz, bloc);
    ft_memcpy(newbloc, bloc, blocByteSz);
    for (int i = blocByteSz; i < LONG64_byteSz; i++)
        newbloc[i] = missing_bytes;
    // fprintf(stderr, "missing_bytes: %d\n", missing_bytes);
    // fprintf(stderr, "newbloc: %lx\n", *((Long_64bits *)newbloc));
    return *((Long_64bits *)newbloc);
}

void        des_unpadding(Long_64bits *lastbloc, int *ptByteSz)
{
    Mem_8bits   lastbyte = (*lastbloc >> 56) & 0xff;

    // fprintf(stderr, "lastbloc : %lx\tptByteSz : %d\n", *lastbloc, *ptByteSz);
    // printf("lastbyte : %x\n", lastbyte);
    if (lastbyte == 0x08)
        *ptByteSz -= LONG64_byteSz;
    else if (0x01 <= lastbyte && lastbyte <= 0x07)
    {
        *lastbloc = *lastbloc & (((Long_64bits)1 << (64 - lastbyte * 8)) - 1); //Remove padding
        *ptByteSz -= lastbyte;
    }
    else // Padding not found
    {
        if (~ssl.flags & nopad)
            ft_ssl_error("Bad decrypt: No padding found in decrypted data.\n");
        return ;
    }
    // Padding found

    if (ssl.flags & nopad)
        flag_error("-nopad", "-nopad is conflicting with padding found in decrypted data.");
}
