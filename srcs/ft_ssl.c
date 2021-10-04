#include "ft_ssl.h"

t_ssl    ssl;

/*
    changer l'ordre de la liste chaine

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
    t_tohash *tohash = ssl.tohash;
    while (tohash)
    {
        printf("\ntype: %s\n", tohash->type);
        // printf("tohash: blablabla\n");
        printf("tohash:\n>%s<\n", tohash->msg);
        i++;
        tohash = tohash->next;
    }
    printf("%d messages to hash\n", i);

    return 0;
}
