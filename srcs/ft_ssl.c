#include "ft_ssl.h"

t_ssl    ssl;

/*
    Ne pas reverse le stdin avec -r
    MD5 au debut sauf en reverse ou stdin
    -p -q -r alors print STDIN + \n + hash pour la premiere ligne
    -q -r = -q car -r s'annule en présence de -q
*/

void    freexit(int failure)
{
    // Free
    if (failure == EXIT_FAILURE)
        exit(EXIT_FAILURE);
}

int     main(int ac, char **av)
{
    int     ret;

    if ((ret = parsing(ac, av)))
    {
        // Free
        // ft_putstr("Parsing failed. EXIT\n");
        return ret;
    }

    // printf("flags: %d\n----------------------------------\n", ssl.flags);

    int i = 0;
    t_hash *hash = ssl.hash;
    while (hash)
    {
        // for (int i = 0; i < 20; i++)
        // {
        // printf("\nNEW HASH TEST %d\n", i);
        // hash->msg = ft_strnew("42 is nice ");
        // hash->msg[10] = i;
        // ssl.hash_func_addr(hash);
        // }

        ssl.hash_func_addr(hash);
        output(hash);
        i++;
        hash = hash->next;
    }
    freexit(EXIT_SUCCESS);
    return 0;
}
