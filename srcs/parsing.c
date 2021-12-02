#include "ft_ssl.h"

inline void  init_hash(t_hash *hash)
{
    *hash = (t_hash){0, NULL, NULL, 0, NULL, NULL, 0, 0, NULL};
}

t_hash *     addmsg_front()
{
    t_hash *tmp;

    tmp = ssl.hash;
    if (!(ssl.hash = (t_hash *)malloc(sizeof(t_hash))))
		malloc_failed("Unable to malloc new t_hash in parsing addmsg_front() function\n");
    init_hash(ssl.hash);
    ssl.hash->next = tmp;
    return ssl.hash;
}

t_hash *     addmsg_back()
{
    t_hash *tmp;
    t_hash *node;

    if (!(node = (t_hash *)malloc(sizeof(t_hash))))
		malloc_failed("Unable to malloc new t_hash in parsing addmsg_back() function\n");
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
        open_failed(" in parsing get_file_len() function\n", file);
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
    int fd;

    if (!node && !(node = addmsg_back()))
        return EXIT_FAILURE;

    if (!(node->name = ft_strdup(file)))
        return EXIT_FAILURE;
    if ((fd = open(file, O_RDONLY)) == -1)
        node->error = FILENOTFOUND;
    else
    {
        node->len = get_file_len(file);
        // if (!(node->msg = (char *)malloc(sizeof(char) * (node->len + 1))))
		//     malloc_failed("Unable to malloc msg in parsing file_handler() function\n");
        // node->msg[node->len] = '\0';
        node->msg = ft_strnew(node->len);

        if (read(fd, node->msg, node->len) == -1)
            return EXIT_FAILURE;
        close(fd);
    }
    return 0;
}

int     string_handler(t_hash *node, char *av_next)
{
    if (!node && !(node = addmsg_back()))
        return EXIT_FAILURE;

    if (!(node->msg = ft_strdup(av_next)))
        return EXIT_FAILURE;
    node->len = ft_strlen(av_next);
    if (!(node->name = ft_stradd_quote(av_next, node->len)))
        return EXIT_FAILURE;
    return 0;
}

int     s_handler(char *av_next, int *i)
{
    if (ssl.flags & S_md)
    {
        (*i)--; // Cancel -s as a flag parameter
        return file_handler(NULL, "-s");
    }
    else
        return string_handler(NULL, av_next);
}

int     param_handler(e_flags flag, char *av_next, int *i)
{
    // printf("V flag condition %d\n", flag & V);
    // printf("I flag condition %d\n", flag & I);
    if (flag & S_md)
    {
        if (s_handler(av_next, i))
            return EXIT_FAILURE;
    }
    else if (flag & I)
    {
        if (file_handler(NULL, av_next))
            return EXIT_FAILURE;
    }
    else if (flag & O)
        ssl.output_file = av_next;
    else if (flag & K)
        ssl.des.key = ft_strtoHex(av_next);
    else if (flag & P_cipher)
        ssl.des.password = (Mem_8bits *)ft_strdup(av_next);
    else if (flag & S_cipher)
        ssl.des.salt = ft_strtoHex(av_next);
    else if (flag & V)
        ssl.des.vector = ft_strtoHex(av_next);
    (*i)++;
    return 0;
}

e_flags strToFlag(char *str)
{
    if (!ft_strcmp(str, "-p"))
    {
        if (ssl.command & MD)
            return P_md;
        else if (ssl.command & CIPHER)
            return P_cipher;
    }
    if (!ft_strcmp(str, "-q"))
        return Q;
    if (!ft_strcmp(str, "-r"))
        return R;
    if (!ft_strcmp(str, "-s"))
    {
        if (ssl.command & MD)
            return S_md;
        else if (ssl.command & CIPHER)
            return S_cipher;
    }

    if (!ft_strcmp(str, "-d"))
        return D;
    if (!ft_strcmp(str, "-e"))
        return E;
    if (!ft_strcmp(str, "-i"))
        return I;
    if (!ft_strcmp(str, "-o"))
        return O;
    if (!ft_strcmp(str, "-a"))
        return A;
    if (!ft_strcmp(str, "-k"))
        return K;
    if (!ft_strcmp(str, "-v"))
        return V;
    return 0;
}

int     hash_func_handler(char *str)
{
    if (!ft_strcmp(str, "md5"))
    {
        ssl.hash_func = "MD5";
        ssl.hash_func_addr = md5;
        ssl.command = MD;
    }
    else if (!ft_strcmp(str, "sha256"))
    {
        ssl.hash_func = "SHA256";
        ssl.hash_func_addr = sha256;
        ssl.command = MD;
    }
    else if (!ft_strcmp(str, "base64"))
    {
        ssl.hash_func = "BASE64";
        ssl.hash_func_addr = base64;
        ssl.command = CIPHER;
    }
    else if (!ft_strcmp(str, "des") || !ft_strcmp(str, "des-ecb"))
    {
        ssl.hash_func = "DES-ECB";
        ssl.hash_func_addr = des;
        ssl.command = CIPHER;
        ssl.des.mode = DESECB;
    }
    else if (!ft_strcmp(str, "des-cbc"))
    {
        ssl.hash_func = "DES-CBC";
        ssl.hash_func_addr = des;
        ssl.command = CIPHER;
        ssl.des.mode = DESCBC;
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
        // if (!(node->msg = (char *)malloc(sizeof(char) * (node->len + ret + 1))))
		//     malloc_failed("Unable to malloc msg in parsing stdin_handler() function\n");
        // node->msg[node->len + ret] = '\0';
        node->msg = ft_strnew(node->len + ret);
        ft_memcpy(node->msg, tmp, node->len);
        ft_memcpy(node->msg + node->len, buff, ret);
        if (tmp)
            free(tmp);
        node->len += ret;
    }

    // Pre-computing for output part
    node->stdin = 1;
    if (ssl.flags & P_md)
    {
        tmp = ft_strdup(node->msg);
        if (tmp[node->len - 1] == '\n')
            tmp[node->len - 1] = '\0'; //To remove \n, it's like 'echo -n <node->msg> | ./ft_ssl ...'

        // Q will not print name, but when Q, R and P_md are True, stdin content without quote is required
        if (ssl.flags & Q)
            node->name = tmp;
        else
        {
            node->name = ft_stradd_quote(tmp, node->len - (tmp[node->len - 1] == '\0' ? 1 : 0));
            free(tmp);
        }
    }
    else
        node->name = ft_strdup("stdin");
    return node->name ? 0 : EXIT_FAILURE;
}

int     parsing(int ac, char **av)
{
    e_flags flag;
    int     ret = 0;

    if (ac == 1 || hash_func_handler(ft_lower(av[1])))
    {
        print_usage();
        return EXIT_FAILURE;
    }

    if (ac > 2)
        for (int i = 2; i < ac; i++)
        {
            if (av[i][0] == '-')
            {
                flag = strToFlag(av[i]);
                // printf("Flag %d\n", flag);
                if (flag & AVPARAM)
                    ret = param_handler(flag, i + 1 < ac ? av[i + 1] : NULL, &i);
                ssl.flags += ssl.flags & flag ? 0 : flag;
            }
            else
                ret = file_handler(NULL, av[i]);
            if (ret)
                return EXIT_FAILURE;
        }

    if (ssl.flags & P_md || !ssl.hash)
        if (stdin_handler())
            return EXIT_FAILURE;
    return 0;
}
