#include "ft_ssl.h"

t_ssl    ssl;

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
        printf("tohash: blablabla\n");
        // printf("tohash:\n%s\n", tohash->msg);
        i++;
        tohash = tohash->next;
    }
    printf("%d messages to hash\n", i);

    return 0;
}
