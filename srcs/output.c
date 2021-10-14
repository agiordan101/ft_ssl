#include "ft_ssl.h"

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
