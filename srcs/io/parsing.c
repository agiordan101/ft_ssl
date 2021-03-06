#include "ft_ssl.h"

t_hash          *add_thash_front()
{
    t_hash *tmp;

    tmp = ssl.hash;
    if (!(ssl.hash = (t_hash *)malloc(sizeof(t_hash))))
		malloc_failed("Unable to malloc new t_hash in parsing add_thash_front() function\n");
    init_t_hash(ssl.hash);
    ssl.hash->next = tmp;
    return ssl.hash;
}

static t_hash   *add_thash_back()
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

static int      get_file_len(char *file)
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

static int      file_handler(char *file, char **content, int *len)
{
    int fd;

    if ((fd = open(file, O_RDONLY)) == -1)
        return FILENOTFOUND;
    else
    {
        *len = get_file_len(file);
        *content = ft_memnew(*len);

        if (read(fd, *content, *len) == -1)
            read_failed("parsing failed: file_handler(): \n", fd);
        close(fd);
    }
    return 0;
}

static void     file_handler_node(t_hash *node, char *file)
{
    if (!node)
        node = add_thash_back();
    node->name = ft_strdup(file);
    node->error = file_handler(file, &node->msg, &node->len);
}

static void     string_handler(t_hash *node, char *av_next)
{
    if (!node)
        node = add_thash_back();
    node->msg = ft_strdup(av_next);
    node->len = ft_strlen(node->msg);
    node->name = ft_stradd_quote(node->msg, node->len);
}

static Key_64bits   parse_keys_des(char *av_next)
{
    Key_64bits  key = ft_strtoHex(av_next);
    int         str_zero_count = 0;
    int         hex_zero_count = 0;

    // Zeros at the beginning of -k parameter have to stay here
    while (av_next[str_zero_count] == '0') str_zero_count++;

    // Count missing half-byte left to remove them (Same as padding zero bytes to length, right)
    while (hex_zero_count < 16 && !(key & (0xf000000000000000 >> (hex_zero_count * 4)))) hex_zero_count++;

    // No padding if the right number of zero bytes left is here
    if (hex_zero_count > str_zero_count)
    {
        ft_putstderr("hex string is too short, padding with zero bytes to length\n");
        key <<= (hex_zero_count - str_zero_count) * 4;
    }
    return key;
}

void            command_handler(t_command *command, char *cmd, e_command mask)
{
    /*
        Initialize a t_command with command string past
        There are 3 consecutive t_command in ft_ssl
        A mask can be pass to avoid commands
    */
    static char         *cmd_names[N_COMMANDS] = {
        "md5", "sha256", "base64", "des-ecb", "des-cbc", "pbkdf2",
        "genprime", "isprime", "genrsa", "rsa", "rsautl",
    };
    static e_command    commands[N_COMMANDS] = {
        MD5, SHA256, BASE64, DESECB, DESCBC, PBKDF2,
        GENPRIME, ISPRIME, GENRSA, RSA, RSAUTL
    };
    static void         *cmd_wrappers[N_COMMANDS] = {
        cmd_wrapper_md5, cmd_wrapper_sha256, cmd_wrapper_base64, cmd_wrapper_des,
        cmd_wrapper_des, cmd_wrapper_pbkdf2, cmd_wrapper_genprime, cmd_wrapper_isprime,
        cmd_wrapper_genrsa, cmd_wrapper_rsa, cmd_wrapper_rsautl
    };
    static char         *cmd_titles[N_COMMANDS] = {
        "MD5", "SHA256", "BASE64", "DESECB", "DESCBC", "PBKDF2",
        "Generating prime number ", "Primality test",
        "Generating RSA keys", "RSA keys visualization", "RSA utilisation"
    };
    static unsigned long cmd_dataSz[N_COMMANDS] = {
        0, 0, 0, sizeof(t_des), sizeof(t_des), sizeof(t_des), sizeof(t_genprime),
        sizeof(t_isprime), sizeof(t_rsa), sizeof(t_rsa), sizeof(t_rsa)
    };
    static e_command_flags  cmd_flags[N_COMMANDS] = {
        MD_flags, MD_flags, BASE64_flags, DES_flags, DES_flags, PBKDF2_flags,
        GENPRIME_flags, ISPRIME_flags, GENRSA_flags, RSA_flags, RSAUTL_flags
    };
    int                 cmd_i = -1;

    if (!ft_strcmp(cmd, "help"))
    {
        free(cmd);
        print_commands();
    }

    if (!ft_strcmp(cmd, "des"))
        cmd_i = 4;
    else
    {
        while (++cmd_i < N_COMMANDS)
            if ((!mask || commands[cmd_i] & mask) &&\
                !ft_strcmp(cmd, cmd_names[cmd_i]))
                break ;
        if (cmd_i == N_COMMANDS)
            invalid_command(cmd);
    }
    command->command = commands[cmd_i];
    command->command_wrapper = cmd_wrappers[cmd_i];
    command->command_title = cmd_titles[cmd_i];
    command->command_flags = cmd_flags[cmd_i];
    if (cmd_dataSz[cmd_i])
        command->command_data = ft_memnew(cmd_dataSz[cmd_i]);

    if (commands[cmd_i] & DESECB)
        ((t_des *)(command->command_data))->mode = DESECB;
    if (commands[cmd_i] & DESCBC)
        ((t_des *)(command->command_data))->mode = DESCBC;
}

static void     param_handler(e_flags flag, char *av_next, int *i)
{
    if (flag & i_ && (ssl.command.command & ~EXECONES_COMMANDS || !ssl.hash))
        file_handler_node(NULL, av_next);
    else if (flag & o)
        ssl.output_file = av_next;
    else if (flag & decin)
        command_handler(&ssl.dec_i_cmd, ft_lower(av_next), HASHING_COMMANDS);
    else if (flag & encout)
        command_handler(&ssl.enc_o_cmd, ft_lower(av_next), HASHING_COMMANDS);
    else if (flag & s)
        string_handler(NULL, av_next);
    else if (flag & salt)
        ssl.des_flagsdata.salt = parse_keys_des(av_next);
    else if (flag & k)
        ssl.des_flagsdata.key = parse_keys_des(av_next);
    else if (flag & v)
        ssl.des_flagsdata.vector = parse_keys_des(av_next);
    else if (flag & pass)
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
    else if (flag & inkey)
        if (file_handler(
            av_next,\
            (char **)&((t_rsa *)ssl.command.command_data)->keyfile_data,\
            &((t_rsa *)ssl.command.command_data)->keyfile_byteSz)
        )
            open_failed("-inkey file is invalid.\n", av_next);
    (*i)++;
}

static e_flags  strToFlag(char *str)
{
    static char     *flags_str[N_FLAGS - 4] = {
        "-help", "-i", "-o", "-a", "-A", "-decin", "-encout",
        "-q", "-r", "-d", "-e", "-passin", "-passout",
        "-P", "-k", "-v", "-nopad", "-iter",
        "-prob", "-min", "-max", "-rand",
        "-inform", "-outform", "-check", "-pubin", "-pubout", "-noout", "-text", "-modulus", "-inkey"
    };
    static e_flags  flags[N_FLAGS - 4] = {
        help, i_, o, a, A, decin, encout,
        q, r, d, e, passin, passout,
        P, k, v, nopad, pbkdf2_iter,
        prob, min, max, rand_path,
        inform, outform, check, pubin, pubout, noout, text, modulus, inkey
    };

    for (int i = 0; i < N_FLAGS - 4; i++)
    {
        if (!ft_strcmp(str, "-s"))
            return DESDATA_NEED_COMMANDS & (ssl.dec_i_cmd.command | ssl.command.command | ssl.enc_o_cmd.command) ? salt : s;
        if (!ft_strcmp(str, "-p"))
            return DESDATA_NEED_COMMANDS & (ssl.dec_i_cmd.command | ssl.command.command | ssl.enc_o_cmd.command) ? pass : p;   
        if (!ft_strcmp(str, flags_str[i]))
            return flags[i];
    }
    return 0;
}

static void     flags_handler(int ac, char **av, int i)
{
    e_flags flag;
 
    while (++i < ac)
    {
        if (av[i][0] == '-')
        {
            flag = strToFlag(av[i]);

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

        // Limit to 1 node if command is an exec ones command.
        else if (ssl.command.command & ~EXECONES_COMMANDS || !ssl.hash)
            file_handler_node(NULL, av[i]);
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

    ft_bzero(buff, BUFF_SIZE);
    while (ret && !(only_one_read && len != 0))                 // Work for echo
    {
        if ((ret = read(STDIN, buff, BUFF_SIZE)) == -1)
            read_failed("parsing failed: stdin_handler(): Unable to read stdin.\n", STDIN);

        tmp = msg;
        msg = ft_memjoin(tmp, len, buff, ret);
        if (tmp)
            free(tmp);
        len += ret;
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

    if (node->len)
    {
        // Pre-computing for output part
        node->stdin = 1;
        if (ssl.flags & p)
        {
            tmp = ft_strdup(node->msg);
            if (tmp[node->len - 1] == '\n')
                tmp[node->len - 1] = '\0'; // Remove '\n' for name displaying

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
    else
    {
        ft_putstderr("[PARSING WARNING] No data fetch from STDIN.\n");
        ssl.hash = node->next;
        t_hash_free(node);
    }
}

static void     flags_conflicts()
{
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
                flags_conflicting_error("-a, in decryption mode,", "-decin", NULL);
            ssl.flags += decin;
            command_handler(&ssl.dec_i_cmd, "base64", 0);
        }
        else
        {
            if (ssl.flags & encout)
                flags_conflicting_error("-a, in encryption mode,", "-encout", NULL);
            ssl.flags += encout;
            command_handler(&ssl.enc_o_cmd, "base64", 0);
        }
    }

    // RSA -> Init PEM | DER forms and Private or Public key type
    if (ssl.command.command & RSA_CMDS)
    {
        e_rsa_form  *inform = &((t_rsa *)ssl.command.command_data)->inform;
        e_rsa_form  *outform = &((t_rsa *)ssl.command.command_data)->outform;

        if (!*inform)
            *inform = ssl.command.command & GENRSA ? DER : PEM; //GENRSA generate DER format by default
        if (!*outform)
            *outform = PEM;

        if (*inform == PEM && ssl.flags & decin)
            flags_conflicting_error("-inform, with PEM format,", "-decin", "Please use DER format as input with -decin.");

        if (ssl.flags & pubin && ~ssl.flags & pubout)
            ssl.flags += pubout;    // pubout option is automatically set if the input is a public key, otherwise, both are private
    }
}

static void     end_parse()
{
    // DES decryption input part, DES command and DES encryption output part use ssl.des_inputdata to fetch password key salt vector
    t_command   *commands[3] = {&ssl.dec_i_cmd, &ssl.command, &ssl.enc_o_cmd};
    t_des       *cmd;

    for (int i = 0; i < 3; i++)
        if (commands[i]->command & DESDATA_NEED_COMMANDS)
        {
            cmd = (t_des *)(commands[i]->command_data);
            cmd->key = ssl.des_flagsdata.key;
            cmd->salt = ssl.des_flagsdata.salt;
            cmd->vector = ssl.des_flagsdata.vector;
            cmd->pbkdf2_iter = ssl.des_flagsdata.pbkdf2_iter;
        }

    if (commands[0]->command & DESDATA_NEED_COMMANDS)
        ((t_des *)(commands[0]->command_data))->password = ssl.passin ? ssl.passin : ssl.des_flagsdata.password;
    if (commands[1]->command & DESDATA_NEED_COMMANDS)
        ((t_des *)(commands[1]->command_data))->password = ssl.des_flagsdata.password;
    if (commands[2]->command & DESDATA_NEED_COMMANDS)
        ((t_des *)(commands[2]->command_data))->password = ssl.passout ? ssl.passout : ssl.des_flagsdata.password;
}

void     parsing(int ac, char **av)
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

    command_handler(&ssl.command, ft_lower(cmd), 0);
    free(cmd);
    flags_handler(ac, av, i);

    // Only if command needs an input
    // Read on stdin if no hash found or p flags is provided
    if (ssl.command.command & THASHNEED_COMMANDS &&\
        (ssl.flags & p || !ssl.hash))
        add_thash_from_stdin();

    flags_conflicts();
    end_parse();
}
