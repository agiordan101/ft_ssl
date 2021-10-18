#include "ft_ssl.h"

// Debug function, not used in this project
void    printByte(char byte)
{
    for (int j = 7; j >= 0; j--)
        printf("%u", (byte >> j) & 1);
    printf(" ");
}

// Debug function, not used in this project
void    printBits(void *p, int size)
{
    // char *mem = (char *)p;
    char mem[size + 1];
    ft_memcpy(mem, (char *)p, size);
    mem[size] = '\0';

    printf("len=%d -> >%s<\n", size, mem);
    for (int i = 0; i < size; i++)
    {
        if (i && i % 8 == 0)
            puts("");
        printByte(mem[i]);
    }
    puts("");
}

// Debug function, not used in this project
void    printHex(void *p, int size)
{
    char *mem = (char *)p;

    printf("Print memory hex >%s<\n", mem);
    for (int i = 0; i < size; i++)
        if (mem[i] < 0x10)
            printf("0%x ", (unsigned int)mem[i]);
        else
            printf("%x ", (unsigned int)mem[i]);
    puts("");
}
