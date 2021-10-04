#include "ft_ssl.h"

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
    int     ret;
    int     fd;

    if ((fd = open(file, O_RDONLY)) == -1)
        return EXIT_FAILURE;
    while (ret == BUFF_SIZE)
    {
        if ((ret = read(fd, buff, BUFF_SIZE)) == -1)
            return EXIT_FAILURE;
        len += ret;
    }
    close(fd);
    // printf("file len: %ld\n", tohash->len);
    return len;
}

int     read_file(t_tohash *tohash, char *file)
{
    int     fd;

    if ((fd = open(file, O_RDONLY)) == -1)
        return EXIT_FAILURE;
    if (!(tohash->msg = (char *)malloc(sizeof(char) * (tohash->len + 1))))
        return EXIT_FAILURE;
    tohash->msg[tohash->len] = '\0';

    // Fill tohash struct
    tohash->type = file;
    tohash->len = get_file_len(file);
    if (read(fd, tohash->msg, tohash->len) == -1)
        return EXIT_FAILURE;
    close(fd);
    // printf("tohash->msg: %s\n", tohash->msg);

    return 0;
}

int     s_handler(char *str)
{
    printf("Handle -s argument: %s\n", str);
    if (add_msg_tohash())
        return EXIT_FAILURE;
    ssl.tohash->type = "-s";
    ssl.tohash->msg = str;
    ssl.tohash->len = ft_strlen(str);
    return 0;
}

int     file_handler(char *file)
{
    t_tohash *tmp;

    printf("Handle file: %s\n", file);
    if (add_msg_tohash())
        return EXIT_FAILURE;

    return read_file(ssl.tohash, file);
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
        if (ssl.flags & S)
            return file_handler(flag);
        else
        {
            ssl.flags += S;
            s_handler(av_next);
            (*i)++;
        }
    return 0;
}

int     hash_func_handler(char *str)
{
    printf("Handle hash func: %s\n", str);
    if (!ft_strcmp(str, "md5"))
        ssl.hash_func = md5;
    else if (!ft_strcmp(str, "sha256"))
        ssl.hash_func = sha256;
    else
    {
        ft_putstr("ft_ssl: Error: ");
        ft_putstr(str);
        ft_putstr(" is an invalid command.\n");
        return EXIT_FAILURE;
    }
    return 0;
}

int     stdin_handler()
{
    char    buff[BUFF_SIZE];

    read(0, buff, );
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
            printf("\nparam %d: %s\n", i, av[i]);
            if (av[i][0] == '-')
                ret = flags_handler(av[i], i + 1 < ac ? av[i + 1] : NULL, &i);
            else
                ret = file_handler(av[i]);
            if (ret)
                return EXIT_FAILURE;
        }

    if (ssl.flags & P)
        if (stdin_handler())
            return EXIT_FAILURE;
    return 0;
}
