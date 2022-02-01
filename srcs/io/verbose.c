#include "ft_ssl.h"

// ---------------------- VERBOSE output ---------------------------

void    print_usage_exit()
{
    ft_putstderr("usage: ft_ssl <algorithm> [flags] [file | string]\n\n");
    ft_putstderr("Global flags:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-p\tforce data reception in stdin\n");
    ft_putstderr("\t-s\tinput data as string\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-q\tquiet mode\n");

    // ft_ssl 1st project
    ft_putstderr("\nMessage Digest commands:\n\tmd5\n\tsha256\n");
    ft_putstderr("Message Digest flags:\n");
    ft_putstderr("\t-r\treverse the format of the output\n");

    // ft_ssl 2nd project
    ft_putstderr("\nCipher commands:\n\tbase64\n\tdes\t(Default as des-cbc)\n\tdes-ecb\n\tdes-cbc\n");
    ft_putstderr("Cipher flags:\n");
    ft_putstderr("\t-e\tencrypt mode (default mode) (-e has priority over -d)\n");
    ft_putstderr("\t-d\tdecrypt mode\n");
    ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstderr("\t-ai\tdecode the input in base64\n");
    ft_putstderr("\t-ao\tencode the output in base64\n");
    ft_putstderr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstderr("\t-k\tsend the key in hex\n");
    ft_putstderr("\t-p\tsend password in ascii\t(Override the behavior of global flag -p)\n");
    ft_putstderr("\t-s\tsend the salt in hex\t(Override the behavior of global flag -s)\n");
    ft_putstderr("\t-v\tsend initialization vector in hex\n");
    ft_putstderr("\t-P\tprint the vector/key and exit\n");
    ft_putstderr("\t-nopad\tdisable standard block padding\n");
    ft_putstderr("\t-iter\tSpecify the iteration count of PBKDF2\n");

    // ft_ssl 3rd project
    ft_putstderr("\nStandard commands:\n\tisprime (Handle 64-bits numbers, up to ~19 digits)\n");
    ft_putstderr("isprime command flags:\n");
    ft_putstderr("\t-prob\tprobability requested for Miller-Rabin primality test in percentile (0 < p <= 100)\n");
    ft_putstderr("Standard flags:\n");

    freexit(EXIT_SUCCESS);
}

void    des_P_flag_output(t_des *des_data)
{
    ssl.fd_out = STDERR; // For ft_printHex function
    ft_putstrfd(ssl.fd_out, "salt=");
    ft_printHex(des_data->salt, KEY_byteSz);
    ft_putstrfd(ssl.fd_out, "\nkey=");
    ft_printHex(des_data->key, KEY_byteSz);
    if (des_data->mode == DESCBC)
    {
        ft_putstrfd(ssl.fd_out, "\niv=");
        ft_printHex(des_data->vector, KEY_byteSz);
    }
    ft_putstrfd(ssl.fd_out, "\n");
    freexit(EXIT_SUCCESS);
}










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
    char *mem = (char *)p;

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
