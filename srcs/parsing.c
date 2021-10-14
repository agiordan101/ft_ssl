#include "ft_ssl.h"

inline void  init_hash(t_hash *hash)
{
    *hash = (t_hash){0, 0, 0, 0, {0}, 0, NULL};
}

t_hash *     addmsg_front()
{
    t_hash *tmp;

    tmp = ssl.hash;
    if (!(ssl.hash = (t_hash *)malloc(sizeof(t_hash))))
        return NULL;
    init_hash(ssl.hash);
    ssl.hash->next = tmp;
    return ssl.hash;
}

t_hash *     addmsg_back()
{
    t_hash *tmp;
    t_hash *node;

    if (!(node = (t_hash *)malloc(sizeof(t_hash))))
        return NULL;
    init_hash(node);
    if (ssl.hash)
    {
        tmp = ssl.hash;
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = node;
    }
    else
        ssl.hash = node;
    return node;
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
        len += ret;
    }
    close(fd);
    return len;
}

int     file_handler(t_hash *node, char *file)
{
    int         fd;

    if (!node && !(node = addmsg_back()))
        return EXIT_FAILURE;

    if (!(node->name = ft_strnew(file)))
        return EXIT_FAILURE;
    if ((fd = open(file, O_RDONLY)) == -1)
        node->error = FILENOTFOUND;
    else
    {
        node->len = get_file_len(file);
        if (!(node->msg = (char *)malloc(sizeof(char) * (node->len + 1))))
            return EXIT_FAILURE;
        node->msg[node->len] = '\0';

        if (read(fd, node->msg, node->len) == -1)
            return EXIT_FAILURE;
    }
    close(fd);
    return 0;
}

int     string_handler(t_hash *node, char *av_next)
{
    if (!(node->msg = ft_strnew(av_next)))
        return EXIT_FAILURE;
    node->len = ft_strlen(av_next);
    if (!(node->name = ft_stradd_quote(av_next, node->len)))
        return EXIT_FAILURE;
    return 0;
}

int     s_handler(char *av_next, int *i)
{
    t_hash    *node;

    if (!(node = addmsg_back()))
        return EXIT_FAILURE;

    if (ssl.flags & S)
        return file_handler(node, "-s");
    else
    {
        ssl.flags += S;
        (*i)++;
        return string_handler(node, av_next);
    }
}

int     flags_handler(char *flag, char *av_next, int *i)
{
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
    if (!ft_strcmp(str, "md5"))
    {
        ssl.hash_func = "MD5";
        ssl.hash_func_addr = md5;
    }
    else if (!ft_strcmp(str, "sha256"))
    {
        ssl.hash_func = "SHA256";
        ssl.hash_func_addr = sha256;
    }
    else
    {
        ft_putstr("ft_ssl: Error: '");
        ft_putstr(str);
        ft_putstr("' is an invalid command.\n\n");
        return EXIT_FAILURE;
    }
    return 0;
}

int     stdin_handler()
{
    t_hash    *node;
    char        buff[BUFF_SIZE];
    int         ret = BUFF_SIZE;
    char        *tmp;

    if (!(node = addmsg_front()))
        return EXIT_FAILURE;

    while (ret == BUFF_SIZE)
    {
        if ((ret = read(0, buff, BUFF_SIZE)) == -1)
            return EXIT_FAILURE;

        tmp = node->msg;
        if (!(node->msg = (char *)malloc(sizeof(char) * (node->len + ret + 1))))
            return EXIT_FAILURE;
        node->msg[node->len + ret] = '\0';
        ft_memcpy(node->msg, tmp, node->len);
        ft_memcpy(node->msg + node->len, buff, ret);
        if (tmp)
            free(tmp);
        node->len += ret;
    }

    // Pre-computing for output part
    node->stdin = 1;
    if (ssl.flags & P)
    {
        tmp = ft_strnew(node->msg);
        if (tmp[node->len - 1] == '\n')
            tmp[node->len - 1] = '\0'; //To remove \n, it's like 'echo -n <node->msg> | ./ft_ssl ...'

        // Q will not print name, but when Q, R and P are True, stdin content without quote is required
        if (ssl.flags & Q)
            node->name = tmp;
        else
        {
            node->name = ft_stradd_quote(tmp, node->len - (tmp[node->len - 1] == '\0' ? 1 : 0));
            free(tmp);
        }
    }
    else
        node->name = ft_strnew("stdin");
    return node->name ? 0 : EXIT_FAILURE;
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
            if (av[i][0] == '-')
                ret = flags_handler(av[i], i + 1 < ac ? av[i + 1] : NULL, &i);
            else
                ret = file_handler(NULL, av[i]);
            if (ret)
                return EXIT_FAILURE;
        }

    if (ssl.flags & P || !ssl.hash)
        if (stdin_handler())
            return EXIT_FAILURE;
    return 0;
}
