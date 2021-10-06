#include "ft_ssl.h"

void    printByte(char byte)
{
    for (int j = 7; j >= 0; j--)
        printf("%u", (byte >> j) & 1);
    printf(" ");
}

void    printBits(void *p, int size)
{
    char *mem = (char *)p;

    // printf("%d ? LITTLEENDIAN : BIGENDIAN (len=%lu) -> >%s<\n", endianness, size, mem);
    printf("len=%d -> >%s<\n", size, mem);

    // if (endianness == LITTLEENDIAN)
    //     for (int i = size - 1; i >= 0; i--)
    //         printByte(mem[i]);
    // else if (endianness == BIGENDIAN)
    for (int i = 0; i < size; i++)
        printByte(mem[i]);

    // else
        // ft_putstr("endianness unknow.");
    puts("");
}

void    printHex(void *p, int size)
{
    char *mem = (char *)p;

    printf("Print memory hex >%s<\n", mem);
    for (int i = 0; i < size; i++)
        if (mem[i])
            printf("%x ", mem[i]);
        else
            printf("00 ");
    puts("");
}

// void    printHex(Mem_8bits *b, Long_64bits size, char endianness)
// {
//     printf("%d ? LITTLEENDIAN : BIGENDIAN -> >%s<\n", endianness, b);
//     if (endianness == LITTLEENDIAN)
//         for (int i = size - 1; i >= 0; i--)
//         {
//             if (b[i])
//                 printf("%x ", b[i]);
//             else
//                 printf("00 ");
//         }

//     else if (endianness == BIGENDIAN)
//         for (int i = 0; i < size; i++)
//         {
//             if (b[i])
//                 printf("%x ", b[i]);
//             else
//                 printf("00 ");
//         }
//     else
//         ft_putstr("endianness unknow.");
//     puts("");
// }

void    print_usage()
{
    ft_putstr("usage: ft_ssl <algorithm> [flags] [file | string]\n\n");
    ft_putstr("Algorithms:\n\tmd5\n\tsha256\n\n");
    ft_putstr("Flags:\n");
    ft_putstr("\t-p: echo STDIN to STDOUT and append the checksum to STDOUT\n");
    ft_putstr("\t-q: quiet mode\n");
    ft_putstr("\t-r: reverse the format of the output\n");
    ft_putstr("\t-s: print the sum of the given string\n");
}
