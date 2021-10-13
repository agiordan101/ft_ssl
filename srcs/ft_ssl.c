#include "ft_ssl.h"

/*
    Ne pas reverse le stdin avec -r
    MD5 au debut sauf en reverse ou stdin
    -p -q -r alors print STDIN + \n + hash pour la premiere ligne
    .. -q -r = .. -q car -r s'annule en présence de -q

    Tester avec de gros fichiers
*/

t_ssl    ssl;

void    ssl_free()
{
    t_hash *hash = ssl.hash;
    t_hash *tmp;

    while (hash)
    {
        // if (hash->name)
        //     free(hash->name);
        // if (hash->msg)
        //     free(hash->msg);
        tmp = hash;
        hash = hash->next;
        // free(tmp);
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

    // printf("flags: %d\n----------------------------------\n", ssl.flags);
    // printf("sizeof(int): %ld bytes\n", sizeof(int));
    // printf("sizeof(u_int8_t): %ld bytes\n", sizeof(u_int8_t));
    // printf("sizeof(Mem_8bits): %ld bytes\n", sizeof(Mem_8bits));
    // printf("sizeof(Long_64bits): %ld bytes\n", sizeof(Long_64bits));
    // printf("sizeof(float): %ld bytes\n", sizeof(float));
    // printf("sizeof(double): %ld bytes\n", sizeof(double));
    // printf("sizeof(Word_32bits): %ld bytes\n", sizeof(Word_32bits));

    // Word_32bits a = 1000;
    // Word_32bits b = 101;
    // // Word_32bits c = addMod32(a, b);
    // printf("b=%d\n", (a + b) % INTMAXLESS1);
    // printf("c=%d\n", (a * 2) % INTMAXLESS1);
    // printf("+=%d\n", a + b);
    // printf("^=%d\n", a ^ b);

    // int i = 0;
    t_hash *hash = ssl.hash;
    while (hash)
    {
        ssl.hash_func_addr(hash);
        output(hash);
        hash = hash->next;
        // i++;
    }
    ssl_free();
    return 0;
}
