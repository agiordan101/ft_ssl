#include "ft_ssl.h"

/*
    Ne pas reverse le stdin avec -r
    MD5 au debut sauf en reverse ou stdin
    -p -q -r alors print STDIN + \n + hash pour la premiere ligne
    .. -q -r = .. -q car -r s'annule en présence de -q
*/

t_ssl    ssl;

void    ssl_free()
{
    t_hash *hash = ssl.hash;
    t_hash *tmp;

    while (hash)
    {
        if (hash->name)
            free(hash->name);
        if (hash->msg)
            free(hash->msg);
        tmp = hash;
        hash = hash->next;
        free(tmp);
    }
}

void    freexit(int failure)
{
    ssl_free();
    if (failure == EXIT_FAILURE)
        exit(EXIT_FAILURE);
}

int     main(int ac, char **av)
{
    int     ret;

    if ((ret = parsing(ac, av)))
        freexit(ret);

    t_hash *hash = ssl.hash;
    while (hash)
    {
        ssl.hash_func_addr(hash);
        output(hash);
        hash = hash->next;
    }

    ssl_free();
    return 0;
}
