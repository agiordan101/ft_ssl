#include "ft_ssl.h"

// Be carefull printf !

void    ft_printHex(Word_32bits n)
{
    unsigned char hex[16] = "0123456789abcdef";
    unsigned char *word = (unsigned char *)&n;

    // printf("word: %s\n", word);
    // printBits(&n, WORD_ByteSz);
    // printHex(&n, WORD_ByteSz);
    for (int i = 0; i < 4; i++)
    {
        // printf("word[i]: %d\n", word[i]);
        unsigned char c = hex[word[i] / 16];
        write(1, &c, 1);
        c = hex[word[i] % 16];
        write(1, &c, 1);
    }
}

void    hash_output(t_hash *p)
{
    Word_32bits *hash = (Word_32bits *)p->hash;

    ft_printHex(hash);
    for (int i = 0; i < 4; i++)
    {
        // printf("%x", hash[i]);
        endianReverse((Mem_8bits *)&hash[i], WORD_ByteSz);
        ft_printHex(hash[i]);
    }
}

void    file_not_found(t_hash *hash)
{
    ft_putstr("ft_ssl: ");
    ft_putstr(ssl.hash_func);
    ft_putstr(": ");
    ft_putstr(hash->name);
    ft_putstr(": No such file or directory");
}

void    stdin_quiet_output(t_hash *hash)
{
    ft_putstr(hash->name);
    ft_putstr("\n");
    hash_output(hash);
}

void    stdin_output(t_hash *hash)
{
    ft_putstr("(");
    ft_putstr(hash->name);
    ft_putstr(")= ");
    hash_output(hash);
}

void    quiet_output(t_hash *hash)
{
    hash_output(hash);
}

void    reversed_output(t_hash *hash)
{
    hash_output(hash);
    ft_putstr(" ");
    ft_putstr(hash->name);
}

void    classic_output(t_hash *hash)
{
    // printf("?????%s?%s??\n", hash->hash, hash->name);
    ft_putstr(ssl.hash_func);
    ft_putstr(" (");
    ft_putstr(hash->name);
    ft_putstr(") = ");
    hash_output(hash);
}

void    print_hash(t_hash *hash)
{
    if (hash->error == FILENOTFOUND)
        file_not_found(hash);

    else if (hash->stdin)
    {
        if (ssl.flags & Q && ssl.flags & P)
            stdin_quiet_output(hash);
        else if (ssl.flags & Q)
            quiet_output(hash);
        else
            stdin_output(hash);
    }

    else if (ssl.flags & Q)
        quiet_output(hash);
    
    else if (ssl.flags & R)
        reversed_output(hash);
    
    else
        classic_output(hash);

    ft_putstr("\n");
}

// void    print
