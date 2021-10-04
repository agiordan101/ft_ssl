#include "ft_ssl.h"

char    *ft_stradd_quote(char *str, int len)
{
    char *newstr;

    if (!(newstr = (char *)malloc(sizeof(char) * (len + 3))))
        return NULL;
    newstr[0] = '\"';
    ft_memcpy(newstr + 1, str, len);
    ft_memcpy(newstr + len + 1, "\"\0", 2);
    return newstr;
}

int     add_msg_tohash()
{
    t_tohash *tmp;

    printf("add msg to hash.\n");
    tmp = ssl.tohash;
    if (!(ssl.tohash = (t_tohash *)malloc(sizeof(t_tohash))))
        return EXIT_FAILURE;
    ssl.tohash->next = tmp;
    return 0;
}

int     get_file_len(char *file)
{
    char    buff[BUFF_SIZE];
    int     len = 0;
    int     ret = BUFF_SIZE;
    int     fd;

    if ((fd = open(file, O_RDONLY)) == -1)
        return EXIT_FAILURE;
    while (ret == BUFF_SIZE)
    {
        if ((ret = read(fd, buff, BUFF_SIZE)) == -1)
            return EXIT_FAILURE;
        printf("Read %d from stdin: %s\n", ret, buff);
        len += ret;
    }
    close(fd);
    // printf("file len: %ld\n", tohash->len);
    return len;
}
////////////////////////// to hash ???
int     file_handler(t_tohash *node, char *file)
{
    int         fd;

    if (!(node->type = ft_strnew(file)))
        return EXIT_FAILURE;
    if ((fd = open(file, O_RDONLY)) == -1)
    {
        ft_putstr("ft_ssl: parsing: ");
        ft_putstr(file);
        ft_putstr(": No such file or directory\n");
        return EXIT_FAILURE;
    }

    node->len = get_file_len(file);
    if (!(node->msg = (char *)malloc(sizeof(char) * (node->len + 1))))
        return EXIT_FAILURE;
    node->msg[node->len] = '\0';

    if (read(fd, node->msg, node->len) == -1)
        return EXIT_FAILURE;
    close(fd);
    // printf("tohash->msg: %s\n", tohash->msg);
    return 0;
}

int     string_handler(t_tohash *node, av_next)
{
    node->msg = ft_strnew(av_next);
    node->len = ft_strlen(av_next);
    node->type = ft_stradd_quote(av_next, node->len);
    return 0;
}

int     s_handler(char *av_next, int *i)
{
    t_tohash    *node;

    if ((node = add_msg_tohash())
        return EXIT_FAILURE;

    if (ssl.flags & S)
        return file_handler(node, flag);
    else
    {
        ssl.flags += S;
        (*i)++;
        return string_handler(node, av_next);
    }
}

int     flags_handler(char *flag, char *av_next, int *i)
{
    printf("Handle flag: %s\n", flag);
    if (!ft_strcmp(flag, "-p"))
        ssl.flags += P;
    if (!ft_strcmp(flag, "-q"))
        ssl.flags += Q;
    if (!ft_strcmp(flag, "-r"))
        ssl.flags += R;
    if (!ft_strcmp(flag, "-s"))
        s_handler(av_next, i);
    return 0;
}

int     hash_func_handler(char *str)
{
    // printf("Handle hash func: %s\n", str);
    if (!ft_strcmp(str, "md5"))
        ssl.hash_func = md5;
    else if (!ft_strcmp(str, "sha256"))
        ssl.hash_func = sha256;
    else
    {
        ft_putstr("ft_ssl: Error: ");
        ft_putstr(str);
        ft_putstr(" is an invalid command.\n\n");
        return EXIT_FAILURE;
    }
    return 0;
}

int     stdin_handler()
{
    char    buff[BUFF_SIZE];
    int     ret = BUFF_SIZE;
    char    *tmp;

    if (add_msg_tohash()) //////
        return EXIT_FAILURE;

    while (ret == BUFF_SIZE)
    {
        if ((ret = read(0, buff, BUFF_SIZE)) == -1)
            return EXIT_FAILURE;
        printf("Read %d from stdin: %s\n", ret, buff);

        tmp = ssl.tohash->msg;
        if (!(ssl.tohash->msg = (char *)malloc(sizeof(char) * (ssl.tohash->len + ret + 1))))
            return EXIT_FAILURE;
        ssl.tohash->msg[ssl.tohash->len + ret] = '\0';
        ft_memcpy(ssl.tohash->msg, tmp, ssl.tohash->len);
        ft_memcpy(ssl.tohash->msg + ssl.tohash->len, buff, ret);
        free(tmp);
        ssl.tohash->len += ret;
    }
    ssl.tohash->len--;
    ssl.tohash->msg[ssl.tohash->len] = '\0'; //Remove \n
    ssl.tohash->type = ssl.flags & P ? ft_stradd_quote(ssl.tohash->msg, ssl.tohash->len) : ft_strnew("stdin");
    // printf("ssl.tohash->type: %s\n", ssl.tohash->type);
    return ssl.tohash->type ? 0 : EXIT_FAILURE;
}

int     parsing(int ac, char **av)
{
    int ret;

    if (ac == 1 || hash_func_handler(av[1]))
    {
        print_usage();
        return EXIT_FAILURE;
    }

    if (ac > 2)
        for (int i = 2; i < ac; i++)
        {
            // printf("\nparam %d: %s\n", i, av[i]);
            if (av[i][0] == '-')
                ret = flags_handler(av[i], i + 1 < ac ? av[i + 1] : NULL, &i);
            else
                ret = file_handler(NULL, av[i]);
            if (ret)
                return EXIT_FAILURE;
        }

    if (ssl.flags & P || !ssl.tohash)
        if (stdin_handler())
            return EXIT_FAILURE;
    return 0;
}
