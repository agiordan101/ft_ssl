#include "ft_ssl.h"

t_hash      *add_thash_front()
{
    t_hash *tmp;

    tmp = ssl.hash;
    if (!(ssl.hash = (t_hash *)malloc(sizeof(t_hash))))
		malloc_failed("Unable to malloc new t_hash in parsing add_thash_front() function\n");
    init_t_hash(ssl.hash);
    ssl.hash->next = tmp;
    return ssl.hash;
}

t_hash      *add_thash_back()
{
    t_hash *tmp;
    t_hash *node;

    if (!(node = (t_hash *)malloc(sizeof(t_hash))))
		malloc_failed("Unable to malloc new t_hash in parsing add_thash_back() function\n");
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
    int     ret = BUFF_SIZE;
    int     len = 0;
    int     fd;

    if ((fd = open(file, O_RDONLY)) == -1)
        open_failed("get_file_len()\n", file);
    while (ret == BUFF_SIZE)
    {
        if ((ret = read(fd, buff, BUFF_SIZE)) == -1)
            read_failed("parsing failed: get_file_len(): \n", fd);
        len += ret;
    }
    close(fd);
    return len;
}

void    file_handler(t_hash *node, char *file)
{
    int fd;

    if (!node)
        node = add_thash_back();

    node->name = ft_strdup(file);
    if ((fd = open(file, O_RDONLY)) == -1)
        node->error = FILENOTFOUND;
    else
    {
        node->len = get_file_len(file);
        node->msg = ft_memnew(node->len);

        if (read(fd, node->msg, node->len) == -1)
            read_failed("parsing failed: file_handler(): \n", fd);
        close(fd);
    }
}

void    string_handler(t_hash *node, char *av_next)
{
    if (!node)
        node = add_thash_back();
    node->msg = ft_strdup(av_next);
    node->len = ft_strlen(node->msg);
    node->name = ft_stradd_quote(node->msg, node->len);
}

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
    else if (flag & i_)
        file_handler(NULL, av_next);
    else if (flag & o)
        ssl.output_file = av_next;
    else if (flag & k_des)
        ((t_des *)ssl.command_data)->key = parse_keys(av_next);
    else if (flag & s_des)
        ((t_des *)ssl.command_data)->salt = parse_keys(av_next);
    else if (flag & v_des)
        ((t_des *)ssl.command_data)->vector = parse_keys(av_next);
    else if (flag & p_des)
        ((t_des *)ssl.command_data)->password = (Mem_8bits *)ft_strdup(av_next);
    else if (flag & pbkdf2_iter)
    {
        int p = ft_atoi(av_next);
        if (p <= 0)
            pbkdf2_iter_error(p);
        ((t_des *)ssl.command_data)->pbkdf2_iter = p;
    }
    else if (flag & prob)
    {
        int p = ft_atoi(av_next);
        if (p <= 0 || 100 < p)
            isprime_prob_error(p);
        ((t_isprime *)ssl.command_data)->prob_requested = (p == 100 ? PROBMIN_ISPRIME : 1 - (float)p / 100);
    }
    (*i)++;
    return 0;
}

// e_flags strToFlag(char *str)
// {
//     static void *flags_convertion[2] = {
//         {"-i", i_},
//         {"-o", o},
//         {"-P", P_des},
//         {"-a", a}
//     };

//     for (int i = 0; i < N_FLAGS; i++)
//     {
//         if (!ft_strcmp(flags_convertion[i][0], str))
//             return flags_convertion[i][1];
//     }
// }

e_flags strToFlag(char *str)
{
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
    if (!ft_strcmp(str, "-r"))
        return r;
    if (!ft_strcmp(str, "-d"))
        return d;
    if (!ft_strcmp(str, "-e"))
        return e;
    if (!ft_strcmp(str, "-help"))
        return help;

    if (ssl.command_addr == des)
    {
        if (!ft_strcmp(str, "-s"))
            return s_des;
        if (!ft_strcmp(str, "-p"))
            return p_des;
        if (!ft_strcmp(str, "-P"))
            return P_des;
        if (!ft_strcmp(str, "-k"))
            return k_des;
        if (!ft_strcmp(str, "-v"))
            return v_des;
        if (!ft_strcmp(str, "-nopad"))
            return nopad;
        if (!ft_strcmp(str, "-iter"))
            return pbkdf2_iter;
    }
    else
    {
        if (!ft_strcmp(str, "-s"))
            return s;
        if (!ft_strcmp(str, "-p"))
            return p;
    }

    if (ssl.command_addr == isprime)
    {
        if (!ft_strcmp(str, "-prob"))
            return prob;
    }
    return 0;
}

int     hash_func_handler(char *cmd)
{
    cmd = ft_lower(cmd);
    if (!ft_strcmp(cmd, "md5"))
    {
        ssl.command = MD5;
        ssl.command_addr = md5;
        ssl.command_title = "MD5";
    }
    else if (!ft_strcmp(cmd, "sha256"))
    {
        ssl.command = SHA256;
        ssl.command_addr = sha256;
        ssl.command_title = "SHA256";
    }
    else if (!ft_strcmp(cmd, "base64"))
    {
        ssl.command = BASE64;
        ssl.command_addr = base64;
        ssl.command_title = "BASE64";
    }
    else if (!ft_strcmp(cmd, "des-ecb"))
    {
        ssl.command = DESECB;
        ssl.command_addr = des;
        ssl.command_title = "DES-ECB";
        ssl.command_data = ft_memnew(sizeof(t_des));
        ((t_des *)ssl.command_data)->mode = DESECB;
    }
    else if (!ft_strcmp(cmd, "des") || !ft_strcmp(cmd, "des-cbc"))
    {
        ssl.command = DESCBC;
        ssl.command_addr = des;
        ssl.command_title = "DES-CBC";
        ssl.command_data = ft_memnew(sizeof(t_des));
        ((t_des *)ssl.command_data)->mode = DESCBC;
    }
    else if (!ft_strcmp(cmd, "genprime"))
    {
        ssl.command = GENPRIME;
        ssl.command_addr = genprime;
        ssl.command_title = "Generating a big prime number: ";
    }
    else if (!ft_strcmp(cmd, "isprime"))
    {
        ssl.command = ISPRIME;
        ssl.command_addr = isprime;
        ssl.command_title = "Is that a prime number ? ";
        ssl.command_data = ft_memnew(sizeof(t_isprime));
    }
    else if (!ft_strcmp(cmd, "genrsa"))
    {
        ssl.command = GENRSA;
        ssl.command_addr = genrsa;
        ssl.command_title = "Generating RSA private key, 64 bit long modulus\n";
    }
    else
    {
        ft_putstderr("ft_ssl: Error: '");
        ft_putstderr(cmd);
        ft_putstderr("' is an invalid command.\n\n");
        free(cmd);
        print_usage_exit();
    }
    free(cmd);
    return 0;
}

static char     *stdin_handler(char **data, int *data_len, char *msg_out, int only_one_read)
{
    /*
        uilisateur doit renvoyer quune seule ligne
        Mais read doit lire autant qu'il y en as
        read renvoi pas toujours la taille max du buffer
        ????
    */
    char    *msg = NULL;
    char    *tmp;
    char    buff[BUFF_SIZE];
    int     ret = BUFF_SIZE;
    int     len = 0;

    if (msg_out)
        ft_putstderr(msg_out);

    printf("stdin handler %d\n", only_one_read);
    ft_bzero(buff, BUFF_SIZE);
    while (ret && !(only_one_read && len != 0))                 // Work for echo
    {
        if ((ret = read(STDIN, buff, BUFF_SIZE)) == -1)
            read_failed("parsing failed: stdin_handler(): Unable to read stdin.\n", STDIN);

        // printf("Hash(len=%d)= >%s<\n", ret, buff);
        tmp = msg;
        msg = ft_memjoin(tmp, len, buff, ret);
        if (tmp)
            free(tmp);
        len += ret;
        printf("%d / Hash(len=%d)= >%s<\n", only_one_read, len, msg);
    }
    if (data)
        *data = msg;
    if (data_len)
        *data_len = len;
    return msg;
}

static void     add_thash_from_stdin()
{
    t_hash  *node = add_thash_front();
    char    *tmp;

    stdin_handler(&node->msg, &node->len, NULL, 0);

    // Pre-computing for output part
    node->stdin = 1;
    if (ssl.flags & p)
    {
        tmp = ft_strdup(node->msg);
        if (tmp[node->len - 1] == '\n')
        {
            // printf("???????????????????????????????????????????????\n");
            tmp[node->len - 1] = '\0'; // Remove '\n' for name displaying
        }

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
    char    *cmd;
    int     cmd_len;
    int     i = 1;

    if (ac == 1)
    {
        i = 0;
        stdin_handler(&cmd, &cmd_len, "Command> ", 1);
        if (cmd[cmd_len - 1] == '\n')
            cmd[cmd_len-- - 1] = '\0';      // To remove '\n' at the end from user validation ('enter' key) in command line
    }
    else
        cmd = ft_strdup(av[1]);
    hash_func_handler(cmd);

    while (++i < ac)
    {
        // printf("arg %d: %s\n", i, av[i]);
        if (av[i][0] == '-')
        {
            flag = strToFlag(av[i]);
            if (flag & AVPARAM)
                param_handler(flag, i + 1 < ac ? av[i + 1] : NULL, &i);
            ssl.flags += ssl.flags & flag ? 0 : flag;
        }
        else
            file_handler(NULL, av[i]);
    }

    // Only if command needs an input
    // Read on stdin if no hash found or p flags is provided
    if (ssl.command & THASHNEED_COMMANDS &&\
        (ssl.flags & p || !ssl.hash))
        add_thash_from_stdin();

    flags_conflicts();
    return 0;
}
