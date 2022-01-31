#include "ft_ssl.h"

t_hash *     addmsg_front()
{
    t_hash *tmp;

    tmp = ssl.hash;
    if (!(ssl.hash = (t_hash *)malloc(sizeof(t_hash))))
		malloc_failed("Unable to malloc new t_hash in parsing addmsg_front() function\n");
    init_t_hash(ssl.hash);
    ssl.hash->next = tmp;
    return ssl.hash;
}

t_hash *     addmsg_back()
{
    t_hash *tmp;
    t_hash *node;

    if (!(node = (t_hash *)malloc(sizeof(t_hash))))
		malloc_failed("Unable to malloc new t_hash in parsing addmsg_back() function\n");
    init_t_hash(node);
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
        node->msg = (char *)ft_memnew(node->len);

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
    // printf("string handler: %s\n", av_next);
    return 0;
}

// int     s_handler(char *av_next, int *i)
// {
//     if (ssl.flags & s)
//     {
//         (*i)--; // Cancel -s as a flag parameter
//         return file_handler(NULL, "-s");
//     }
//     else
//         return string_handler(NULL, av_next);
// }

Key_64bits  parse_keys(char *av_next)
{
    Key_64bits  key = ft_strtoHex(av_next);
    int         str_zero_count = 0;
    int         hex_zero_count = 0;

    // Zeros at the beginning of -k parameter have to stay here
    while (av_next[str_zero_count] == '0') str_zero_count++;

    // Count missing half-byte left to remove them (Same as padding zero bytes to length, right)
    while (!(key & (0xf000000000000000 >> (hex_zero_count * 4)))) hex_zero_count++;

    // No padding if the right number of zero bytes left is here
    if (hex_zero_count > str_zero_count)
    {
        ft_putstderr("hex string is too short, padding with zero bytes to length\n");
        key <<= (hex_zero_count - str_zero_count) * 4;
    }
    // printf("parse_keys: %lx\n", key);
    return key;
}

int     param_handler(e_flags flag, char *av_next, int *i)
{
    if (flag & s)
        string_handler(NULL, av_next);
    // if (flag & s)
    // {
    //     if (s_handler(av_next, i))
    //         return EXIT_FAILURE;
    // }
    else if (flag & i_)
    {
        if (file_handler(NULL, av_next))
            return EXIT_FAILURE;
    }
    else if (flag & o)
        ssl.output_file = av_next;
    else if (flag & k_des)
        ssl.des.key = parse_keys(av_next);
    else if (flag & p_des)
        ssl.des.password = (Mem_8bits *)ft_strdup(av_next);
    else if (flag & s_des)
        ssl.des.salt = parse_keys(av_next);
    else if (flag & v_des)
        ssl.des.vector = parse_keys(av_next);
    else if (flag & pbkdf2_iter)
    {
        ssl.pbkdf2_iter = ft_atoi(av_next);
        if (ssl.pbkdf2_iter <= 0)
            pbkdf2_iter_error();
    }
    (*i)++;
    return 0;
}

e_flags strToFlag(char *str)
{
    if (!ft_strcmp(str, "-s"))
    {
        if (ssl.command_familly == CIPHER)
            return s_des;
        else 
            return s;
    }
    if (!ft_strcmp(str, "-p"))
    {
        if (ssl.command_familly & CIPHER)
            return p_des;
        else
            return p;
    }
    if (!ft_strcmp(str, "-P"))
        return P_des;
    if (!ft_strcmp(str, "-i"))
        return i_;
    if (!ft_strcmp(str, "-o"))
        return o;
    if (!ft_strcmp(str, "-a"))
        return a;
    if (!ft_strcmp(str, "-ai"))
        return ai;
    if (!ft_strcmp(str, "-ao"))
        return ao;
    if (!ft_strcmp(str, "-A"))
        return A;
    if (!ft_strcmp(str, "-q"))
        return q;
    if (!ft_strcmp(str, "-help"))
        return help;
    if (!ft_strcmp(str, "-r"))
        return r;
    if (!ft_strcmp(str, "-d"))
        return d;
    if (!ft_strcmp(str, "-e"))
        return e;
    if (!ft_strcmp(str, "-k"))
        return k_des;
    if (!ft_strcmp(str, "-v"))
        return v_des;
    if (!ft_strcmp(str, "-nopad"))
        return nopad;
    if (!ft_strcmp(str, "-iter"))
        return pbkdf2_iter;
    if (!ft_strcmp(str, "-prob"))
        return prob;
    return 0;
}

int     hash_func_handler(char *str)
{
    if (!ft_strcmp(str, "md5"))
    {
        ssl.command_title = "MD5";
        ssl.command_addr = md5;
        ssl.command_familly = MD;
    }
    else if (!ft_strcmp(str, "sha256"))
    {
        ssl.command_title = "SHA256";
        ssl.command_addr = sha256;
        ssl.command_familly = MD;
    }
    else if (!ft_strcmp(str, "base64"))
    {
        ssl.command_title = "BASE64";
        ssl.command_addr = base64;
        ssl.command_familly = CIPHER;
    }
    else if (!ft_strcmp(str, "des-ecb"))
    {
        ssl.command_title = "DES-ECB";
        ssl.command_addr = des;
        ssl.command_familly = CIPHER;
        ssl.des.mode = DESECB;
    }
    else if (!ft_strcmp(str, "des") || !ft_strcmp(str, "des-cbc"))
    {
        ssl.command_title = "DES-CBC";
        ssl.command_addr = des;
        ssl.command_familly = CIPHER;
        ssl.des.mode = DESCBC;
    }
    else if (!ft_strcmp(str, "isprime"))
    {
        ssl.command_title = "Is prime ? ";
        ssl.command_addr = isprime;
        ssl.command_familly = STANDARD;
    }
    else
    {
        ft_putstderr("ft_ssl: Error: '");
        ft_putstderr(str);
        ft_putstderr("' is an invalid command_familly.\n\n");
        return EXIT_FAILURE;
    }
    return 0;
}

int     stdin_handler()
{
    t_hash      *node = addmsg_front();
    char    *tmp;
    char    buff[BUFF_SIZE];
    int     ret = BUFF_SIZE;

    while (ret)
    {
        if ((ret = read(0, buff, BUFF_SIZE)) == -1)
            return EXIT_FAILURE;

        tmp = node->msg;
        node->msg = ft_memjoin(tmp, node->len, buff, ret);
        if (tmp)
            free(tmp);
        node->len += ret;
    }

    // Pre-computing for output part
    node->stdin = 1;
    if (ssl.flags & p)
    {
        tmp = ft_strdup(node->msg);
        if (tmp[node->len - 1] == '\n')
            tmp[node->len - 1] = '\0'; //To remove \n, it's like 'echo -n <node->msg> | ./ft_ssl ...'

        // q will not print name, but when q, r and p are True, stdin content without quote is required. Yes, I know, it's sucks
        if (ssl.flags & q)
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

void    flags_conflicts()
{
    // Active input decode / output encode in respect to encryption/decryption mode
    if (ssl.flags & a)
    {
        if (ssl.flags & d)
            ssl.flags += ssl.flags & ai ? 0 : ai;
        else
            ssl.flags += ssl.flags & ao ? 0 : ao;   
    }

    // Handle conflict between e and d flags (Set encryption by default)
    if (ssl.flags & (e | d))
    {
        if (ssl.flags & e && ssl.flags & d)
            ssl.flags -= d;
    }
    else
        ssl.flags += e;
}

int     parsing(int ac, char **av)
{
    e_flags flag;
    int     ret = 0;

    if (ac == 1 || hash_func_handler(ft_lower(av[1])))
        print_usage_exit();

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

    // Read on stdin if no hash found or p flags is provided
    if (ssl.flags & p || !ssl.hash)
        if (stdin_handler())
            return EXIT_FAILURE;        

    flags_conflicts();
    return 0;
}
