#include "ft_ssl.h"

t_ssl    ssl;

/*
    Ne pas reverse le stdin avec -r
    MD5 au debut sauf en reverse ou stdin
    -p -q -r alors print STDIN + \n + hash pour la premiere ligne
    -q -r = -q car -r s'annule en présence de -q
*/

int main(int ac, char **av)
{
    int     ret;

    if ((ret = parsing(ac, av)))
    {
        // Free
        ft_putstr("Parsing failed. EXIT\n");
        return ret;
    }

    printf("\n\tMAIN\nflags: %d\n", ssl.flags);

    int i = 0;
    t_hash *hash = ssl.hash;
    while (hash)
    {
        printf("\ntype: %s\n", hash->type);
        // printf("hash: blablabla\n");
        printf("hash:\n>%s<\n", hash->msg);
        i++;
        hash = hash->next;
    }
    printf("%d messages to hash\n", i);

    return 0;
}
