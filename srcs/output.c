#include "ft_ssl.h"

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
    ft_putstr(hash->hash);
}

void    stdin_output(t_hash *hash)
{
    ft_putstr("(");
    ft_putstr(hash->name);
    ft_putstr(")= ");
    ft_putstr(hash->hash);
}

void    quiet_output(t_hash *hash)
{
    ft_putstr(hash->hash);
}

void    reversed_output(t_hash *hash)
{
    ft_putstr(hash->hash);
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
    ft_putstr(hash->hash);
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
