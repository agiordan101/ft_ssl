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

Key_64bits  parse_keys_des(char *av_next)
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
    // printf("parse_keys_des: %lx\n", key);
    return key;
}

static void     command_handler(t_command *command, char *cmd, e_command mask)
{
    static char         *commands_name[N_COMMANDS] = {
        "md5", "sha256", "base64", "des-ecb", "des-cbc", "genprime", "isprime", "genrsa", "rsa",
    };
    static e_command    commands[N_COMMANDS] = {
        MD5, SHA256, BASE64, DESECB, DESCBC, GENPRIME, ISPRIME, GENRSA, RSA
    };
    static void         *commands_addr[N_COMMANDS] = {
        md5, sha256, base64, des, des, genprime, isprime, genrsa, rsa
    };
    static char         *commands_title[N_COMMANDS] = {
        "MD5", "SHA256", "BASE64", "DESECB", "DESCBC",
        "Generating prime number ", "Is that a prime number ? ",
        "Generating RSA private key ", "RSA keys visualization"
    };
    static unsigned long commands_dataSz[N_COMMANDS] = {
        0, 0, 0, sizeof(t_des), sizeof(t_des), sizeof(t_genprime), sizeof(t_isprime), 0, sizeof(t_rsa)
    };
    static e_command_flags  commands_flags[N_COMMANDS] = {
        MD_flags, MD_flags, BASE64_flags, DES_flags, DES_flags, GENPRIME_flags, ISPRIME_flags, GENRSA_flags, RSA_flags
    };
    int                 cmd_i = -1;

    cmd = ft_lower(cmd);
    if (!ft_strcmp(cmd, "help"))
        print_commands();

    if (!ft_strcmp(cmd, "des"))
        cmd_i = 4;
    else
    {
        while (++cmd_i < N_COMMANDS)
            if ((!mask || commands[cmd_i] & mask) &&\
                !ft_strcmp(cmd, commands_name[cmd_i]))
                break ;
        if (cmd_i == N_COMMANDS)
        {
            ft_putstderr("ft_ssl: Error: '");
            ft_putstderr(cmd);
            ft_putstderr("' is an invalid command.\n");
            print_global_usage();
        }
    }
    command->command = commands[cmd_i];
    command->command_addr = commands_addr[cmd_i];
    command->command_title = commands_title[cmd_i];
    command->command_flags = commands_flags[cmd_i];
    if (commands_dataSz[cmd_i])
        command->command_data = ft_memnew(commands_dataSz[cmd_i]);

    if (commands[cmd_i] & DESECB)
        ((t_des *)(command->command_data))->mode = DESECB;
    if (commands[cmd_i] & DESCBC)
        ((t_des *)(command->command_data))->mode = DESCBC;
    // printf("command= %s\n", command->command_title);
}

int     param_handler(e_flags flag, char *av_next, int *i)
{
    if (flag & i_)
        file_handler(NULL, av_next);
    else if (flag & o)
        ssl.output_file = av_next;
    else if (flag & decin)
        command_handler(&ssl.dec_i_cmd, av_next, HASHING_COMMANDS);
    else if (flag & encout)
        command_handler(&ssl.enc_o_cmd, av_next, HASHING_COMMANDS);
    else if (flag & s)
        string_handler(NULL, av_next);
    else if (flag & s_des)
        ssl.des_flagsdata.salt = parse_keys_des(av_next);
    else if (flag & k_des)
        ssl.des_flagsdata.key = parse_keys_des(av_next);
    else if (flag & v_des)
        ssl.des_flagsdata.vector = parse_keys_des(av_next);
    else if (flag & p_des)
        ssl.des_flagsdata.password = ft_strdup(av_next);
    else if (flag & pbkdf2_iter)
    {
        int p = ft_atoi(av_next);
        if (p <= 0)
            pbkdf2_iter_error(p);
        ssl.des_flagsdata.pbkdf2_iter = p;
    }
    else if (flag & passin)
        ssl.passin = ft_strdup(av_next);
    else if (flag & passout)
        ssl.passout = ft_strdup(av_next);
    else if (flag & prob)
    {
        int p = ft_atoi(av_next);
        if (p <= 0 || 100 < p)
            isprime_prob_error(p);
        ((t_isprime *)ssl.command.command_data)->prob_requested = (p == 100 ? PROBMIN_ISPRIME : 1 - (float)p / 100);
    }
    else if (flag & min)
        ((t_genprime *)ssl.command.command_data)->min = ft_atoi(av_next);
    else if (flag & max)
        ((t_genprime *)ssl.command.command_data)->max = ft_atoi(av_next);
    else if (flag & rand_path)
    {
        free(ssl.ulrandom_path);
        ssl.ulrandom_path = ft_strdup(av_next);
    }
    else if (flag & (inform | outform))
    {
        e_rsa_form form;
        if (!ft_strcmp(av_next, "PEM"))
            form = PEM;
        else if (!ft_strcmp(av_next, "DER"))
            form = DER;
        else
            rsa_format_error(av_next);
        if (flag & inform)
            ((t_rsa *)ssl.command.command_data)->inform = form;
        else
            ((t_rsa *)ssl.command.command_data)->outform = form;
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

e_flags     strToFlag(char *str)
{
    if (!ft_strcmp(str, "-help"))
        return help;
    if (!ft_strcmp(str, "-i"))
        return i_;
    if (!ft_strcmp(str, "-o"))
        return o;
    if (!ft_strcmp(str, "-a"))
        return a;
    if (!ft_strcmp(str, "-A"))
        return A;
    if (!ft_strcmp(str, "-decin"))
        return decin;
    if (!ft_strcmp(str, "-encout"))
        return encout;
    if (!ft_strcmp(str, "-q"))
        return q;
    if (!ft_strcmp(str, "-r"))
        return r;
    if (!ft_strcmp(str, "-d"))
        return d;
    if (!ft_strcmp(str, "-e"))
        return e;
    if (!ft_strcmp(str, "-passin"))
        return passin;
    if (!ft_strcmp(str, "-passout"))
        return passout;

    if (!ft_strcmp(str, "-s"))
        return DES & (ssl.dec_i_cmd.command | ssl.command.command | ssl.enc_o_cmd.command) ? s_des : s;
    if (!ft_strcmp(str, "-p"))
        return DES & (ssl.dec_i_cmd.command | ssl.command.command | ssl.enc_o_cmd.command) ? p_des : p;
    
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
    
    if (!ft_strcmp(str, "-prob"))
        return prob;
    if (!ft_strcmp(str, "-min"))
        return min;
    if (!ft_strcmp(str, "-max"))
        return max;
    
    if (!ft_strcmp(str, "-rand"))
        return rand_path;
    
    if (!ft_strcmp(str, "-inform"))
        return inform;
    if (!ft_strcmp(str, "-outform"))
        return outform;
    if (!ft_strcmp(str, "-check"))
        return check;
    if (!ft_strcmp(str, "-pubin"))
        return pubin;
    if (!ft_strcmp(str, "-pubout"))
        return pubout;
    if (!ft_strcmp(str, "-noout"))
        return noout;
    if (!ft_strcmp(str, "-text"))
        return text;
    if (!ft_strcmp(str, "-modulus"))
        return modulus;
    if (!ft_strcmp(str, "-hexdump"))
        return hexdump;
    return 0;
}

void        flags_handler(int ac, char **av, int i)
{
    e_flags flag;
 
    while (++i < ac)
    {
        // printf("arg %d: %s\n", i, av[i]);
        if (av[i][0] == '-')
        {
            flag = strToFlag(av[i]);

            // printf("flag compatible ? %d\n", flag & (ssl.dec_i_cmd.command_flags | ssl.command.command_flags | ssl.enc_o_cmd.command_flags));
            if (flag & help)
                print_command_usage(ssl.command.command);
            else if (flag & (ssl.dec_i_cmd.command_flags | ssl.command.command_flags | ssl.enc_o_cmd.command_flags))
            {
                if (flag & AVPARAM)
                    param_handler(flag, i + 1 < ac ? av[i + 1] : NULL, &i);
                ssl.flags += ssl.flags & flag ? 0 : flag;
            }
            else
                unrecognized_flag(av[i]);
        }
        else
            file_handler(NULL, av[i]);
    }
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

    // printf("stdin handler %d\n", only_one_read);
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
        // printf("%d / Hash(len=%d)= >%s<\n", only_one_read, len, msg);
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
    char base64_str[] = "base64";

    // Handle conflict between e and d flags (Set encryption by default)
    if (ssl.flags & (e | d))
    {
        if (ssl.flags & e && ssl.flags & d)
            ssl.flags -= d;
    }
    else
        ssl.flags += e;

    // Active base64 input decode / output encode in respect to encryption/decryption mode
    if (ssl.flags & a)
    {
        if (ssl.flags & d)
        {
            if (ssl.flags & decin)
            {
                ft_putstderr("Flags -a, in decryption mode, and -decin are conflicting.\n");
                freexit(EXIT_SUCCESS);
            }
            ssl.flags += decin;
            command_handler(&ssl.dec_i_cmd, base64_str, 0);
        }
        else
        {
            if (ssl.flags & encout)
            {
                ft_putstderr("Flags -a, in encryption mode, and -encout are conflicting.\n");
                freexit(EXIT_SUCCESS);
            }
            ssl.flags += encout;
            command_handler(&ssl.enc_o_cmd, base64_str, 0);
        }
    }

    if (ssl.command.command & GENRSA)
    {
        if (~ssl.flags & encout)
        {
            ssl.flags += encout;
            command_handler(&ssl.enc_o_cmd, base64_str, 0);
        }
    }
    // else if (ssl.command.command & RSA)
    // {
    //     // if (ssl.flags & pubout &&)
        
    // }
}

void    end_parse()
{
    // DES decryption input part, DES command and DES encryption output part use ssl.des_inputdata to fetch password key salt vector
    t_command   *commands[3] = {&ssl.dec_i_cmd, &ssl.command, &ssl.enc_o_cmd};
    t_des       *cmd;

    for (int i = 0; i < 3; i++)
        if (commands[i]->command_addr == des)
        {
            cmd = (t_des *)(commands[i]->command_data);
            cmd->key = ssl.des_flagsdata.key;
            cmd->salt = ssl.des_flagsdata.salt;
            cmd->vector = ssl.des_flagsdata.vector;
            cmd->pbkdf2_iter = ssl.des_flagsdata.pbkdf2_iter;
        }

    if (commands[0]->command_addr == des)
        ((t_des *)(commands[0]->command_data))->password = ssl.passin ? ssl.passin : ssl.des_flagsdata.password;
    if (commands[1]->command_addr == des)
        ((t_des *)(commands[1]->command_data))->password = ssl.des_flagsdata.password;
    if (commands[2]->command_addr == des)
        ((t_des *)(commands[2]->command_data))->password = ssl.passout ? ssl.passout : ssl.des_flagsdata.password;

    // printf("ssl.des_flagsdata.key: %lu\n", ssl.des_flagsdata.key);
    // printf("ssl.des_flagsdata.salt: %lu\n", ssl.des_flagsdata.salt);
    // printf("ssl.des_flagsdata.vector: %lu\n", ssl.des_flagsdata.vector);
    // printf("ssl.des_flagsdata.password: %lu\n", ssl.des_flagsdata.password);
    // printf("ssl.des_flagsdata.pbkdf2_iter: %u\n", ssl.des_flagsdata.pbkdf2_iter);
}

int     parsing(int ac, char **av)
{
    char    *cmd;
    int     cmd_len;
    int     i = 1;

    // Fetch command OR ask it
    if (ac == 1)
    {
        i = 0;
        stdin_handler(&cmd, &cmd_len, "Command> ", 1);
        if (cmd[cmd_len - 1] == '\n')
            cmd[cmd_len-- - 1] = '\0';      // To remove '\n' at the end from user validation ('enter' key) in command line
    }
    else
        cmd = ft_strdup(av[1]);

    command_handler(&ssl.command, cmd, 0);
    // printf("ssl.command.command_title: %s\n", ssl.command.command_title);
    // printf("ssl.command.command_data: %p\n", ssl.command.command_data);
    free(cmd);
    flags_handler(ac, av, i);

    // Only if command needs an input
    // Read on stdin if no hash found or p flags is provided
    if (ssl.command.command & THASHNEED_COMMANDS &&\
        (ssl.flags & p || !ssl.hash))
        add_thash_from_stdin();

    flags_conflicts();
    end_parse();
    return 0;
}
