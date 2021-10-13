#include "ft_ssl.h"

// Be carefull printf !

void    ft_printHex(Word_32bits n)
{
    unsigned char hex[16] = "0123456789abcdef";
    unsigned char *word = (unsigned char *)&n;
    unsigned char c_16e0;
    unsigned char c_16e1;

    for (int i = 0; i < 4; i++)
    {
        c_16e0 = hex[word[i] % 16];
        c_16e1 = hex[word[i] / 16];
        if (write(1, &c_16e1, 1) == -1 ||\
            write(1, &c_16e0, 1) == -1)
            freexit(EXIT_FAILURE);
    }
}

void    hash_output(t_hash *p)
{
    for (int i = 0; i < (ssl.hash_func == "MD5" ? 4 : 8); i++)
        ft_printHex(p->hash[i]);
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

void    output(t_hash *hash)
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
