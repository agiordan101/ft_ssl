#include "ft_ssl.h"

// ---------------------- VERBOSE output ---------------------------

void    des_P_flag_output(t_des *des_data)
{
    ssl.fd_out = STDERR; // For ft_printHex function
    ft_putstrfd(ssl.fd_out, "salt=");
    ft_printHex(des_data->salt);
    ft_putstrfd(ssl.fd_out, "\nkey=");
    ft_printHex(des_data->key);
    if (ssl.command.command == DESCBC)
    {
        ft_putstrfd(ssl.fd_out, "\niv=");
        ft_printHex(des_data->vector);
    }
    ft_putstrfd(ssl.fd_out, "\n");
    freexit(EXIT_SUCCESS);
}


/*
    Debug functions are following, not used in this project    -----------------------------------------
*/


// Debug function, not used in this project
void    printRevByte(char byte)
{
    for (int j = 0; j < 8; j++)
        fprintf(stderr, "%u", (byte >> j) & 1);
    fprintf(stderr, " ");
}
void    printByte(char byte)
{
    for (int j = 7; j >= 0; j--)
        fprintf(stderr, "%u", (byte >> j) & 1);
    fprintf(stderr, " ");
}
void    printWord(Word_32bits word)
{
    for (int j = 31; j >= 0; j--)
    {
        fprintf(stderr, "%u", (word >> j) & 1);
        if (j % 8 == 0)
            fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
}
void    printLong(Long_64bits l)
{
    for (int j = 63; j >= 0; j--)
    {
        fprintf(stderr, "%lu", (l >> j) & 1);
        if (j % 8 == 0)
            fprintf(stderr, " ");
    }

    fprintf(stderr, "\n");
}
// Debug function, not used in this project
void    printBits(void *p, int size)
{
    // char *mem = (char *)p;
    char mem[size + 1];
    ft_memcpy(mem, (char *)p, size);
    mem[size] = '\0';

    // fprintf(stderr, "len=%d -> >%s<\n", size, mem);
    for (int i = 0; i < size; i++)
    {
        if (i && i % 8 == 0)
            fprintf(stderr, "\n");
        // printRevByte(mem[i]);
        printByte(mem[i]);
    }
    fprintf(stderr, "\n");
}
// Debug function, not used in this project
void    printMemHex(void *p, int size, char *msg)
{
    char *mem = (char *)p;

    if (msg)
        fprintf(stderr, "\n%s (len=%d) >%s<\n", msg, size, mem);
    else
        fprintf(stderr, "\nPrint mem HEX (len=%d) >%s<\n", size, mem);
    for (int i = 0; i < size; i++)
    {
        if (mem[i] < 0x10)
            fprintf(stderr, "0%x", mem[i]);
        else
            fprintf(stderr, "%x", mem[i]);
        if ((i + 1) % 4 == 0)
            fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
}
