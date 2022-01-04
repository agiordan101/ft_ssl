#include "ft_ssl.h"

// Debug function, not used in this project
void    printRevByte(char byte)
{
    for (int j = 0; j < 8; j++)
        printf("%u", (byte >> j) & 1);
    printf(" ");
}
void    printByte(char byte)
{
    for (int j = 7; j >= 0; j--)
        printf("%u", (byte >> j) & 1);
    printf(" ");
}

void    printWord(Word_32bits word)
{
    for (int j = 31; j >= 0; j--)
    {
        printf("%u", (word >> j) & 1);
        if (j % 8 == 0)
            putchar(' ');
    }
    printf("\n");
}

void    printLong(Long_64bits l)
{
    for (int j = 63; j >= 0; j--)
    {
        printf("%lu", (l >> j) & 1);
        if (j % 8 == 0)
            putchar(' ');
    }

    printf("\n");
}

// Debug function, not used in this project
void    printBits(void *p, int size)
{
    // char *mem = (char *)p;
    char mem[size + 1];
    ft_memcpy(mem, (char *)p, size);
    mem[size] = '\0';

    // printf("len=%d -> >%s<\n", size, mem);
    for (int i = 0; i < size; i++)
    {
        if (i && i % 8 == 0)
            puts("");
        // printRevByte(mem[i]);
        printByte(mem[i]);
    }
    puts("");
}

// Debug function, not used in this project
void    printMemHex(void *p, int size, char *msg)
{
    unsigned char *mem = (char *)p;

    if (msg)
        printf("\n%s (len=%d) >%s<\n", msg, size, mem);
    else
        printf("\nPrint mem HEX (len=%d) >%s<\n", size, mem);
    for (int i = 0; i < size; i++)
    {
        if (mem[i] < 0x10)
            printf("0%x", mem[i]);
        else
            printf("%x", mem[i]);
        if ((i + 1) % 4 == 0)
            printf(" ");
    }
    puts("");
}
