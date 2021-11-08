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

Mem_8bits           *key_discarding(Mem_8bits *key)
{
    Mem_8bits   dk[KEYDISCARD_byteSz];
    Mem_8bits   mask = 0b11111110;
    int         shift = 7;

    // printf("\n--- key_discarding ---\n");
    // printBits(key, KEY_byteSz);
    for (int i = 0; i < (int)KEYDISCARD_byteSz; i++)
    {
        // printf("mask = %d\n", mask);
        // printBits(&mask, 1);
        // printf("shift = %d\n\n", shift);
        dk[i] = ((key[i] & mask) << (7 - shift)) | (key[i + 1] >> shift);
        mask = mask / 2 - 1;
        shift--;
    }
    // printBits(dk, KEYDISCARD_byteSz);
    return ft_memdup(dk, KEYDISCARD_byteSz);
}

Mem_8bits           *bits_permutations(Mem_8bits *plaintext, char *pt)
{
    Mem_8bits       ptperm[KEY_byteSz];
    ft_bzero(ptperm, KEY_byteSz);

    for (int i = 0; i < 64; i++)
        printf("%d ", pt[i]);
        // pt[i] = pt[i] - 1;
    printf("\n");

    printBits(plaintext, 8);
    for (int bytei = 0; bytei < KEY_byteSz; bytei++)
    {
        // printf("Byte value: %d\n", plaintext[bytei]);
        // for (int biti = 0, mask = 0b10000000; biti < 8; biti++, mask /= 2)
        for (int biti = 0; biti < 8; biti++)
        {
            char itop = pt[bytei * 8 + biti] - 1;
            char mask = 0b10000000 >> (itop % 8);
            char bit = plaintext[itop / 8] & mask;
            if (bit)
                ptperm[bytei] = ptperm[bytei] | (0b10000000 >> biti);
            // printBits(&mask, 1);
            // printf("itop = %d\tpi / 8 = %d\t0b10000000 >> (biti %% 8) = %d\tbit = %d\n", itop, itop / 8, 0b10000000 >> (itop % 8), bit);
            // printBits(&bit, 1);
            // printf("\n");
        }
        // printf("Plain text:\n");
        // printBits(plaintext, 8);
        // exit(0);
    }
    // printf("bit_permutations: %s\n", plaintext);
    printBits(ptperm, KEY_byteSz);
    printHex(ptperm, KEY_byteSz);

    printf("Answer:\n");
    printBits(parse_key(ft_strdup("14A7D67818CA18AD")), KEY_byteSz);

    return ft_memdup(ptperm, KEY_byteSz);
}

