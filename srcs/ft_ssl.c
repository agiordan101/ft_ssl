#include "ft_ssl.h"

/*
    ft_ssl_md5 -> Pas de prérequis pour corriger
    ft_ssl_des -> Avoir commencé ft_ssl_md5
    ft_ssl_rsa -> Avoir fini ft_ssl_des

    To do :

        AJOUUTER LES ... et tout changer ahahh..ah...
        Merge rsa_DER_keys_parsing and rsa_PEM_keys_parsing

        RSA nsm les keys juste concat
        Remettre passin et decin pour rsa

        base64 + -p output cheum ???????

        Renommer les "way" en un truc plus pertinant pour la command en question

        //Leaks ft_stradd_quote ?
        inline keywords pour les prime peut etre et le dossier calculations
        INTMAXLESS1 enlever le pow
        Enlever les protection useless dans le parsing
        Gerer les \n dans l'output (pas dans les ft hash)
        Boucler pour les flags parsing pt sur ft
        -nosalt             Do not use salt in the KDF

    Crashs :


*/

t_ssl    ssl;

char        *ask_password(t_command *cmd)
{
    char *firstmsg_1 = "enter ";
    char *password;

    if (ssl.flags & e)
    {
        char *secondmsg_1 = "Verifying - enter ";
        char *msg_2 = " encryption password:";
        char *firstmsg = ft_strinsert(firstmsg_1, cmd->command_title, msg_2);
        char *secondmsg = ft_strinsert(secondmsg_1, cmd->command_title, msg_2);

        char *password2 = ft_strdup(getpass(firstmsg));
        password = getpass(secondmsg);

        free(firstmsg);
        free(secondmsg);
        if (ft_strcmp(password, password2))
        {
            ft_putstderr("\nVerify failure.\nbad password read.\n");
            free(password2);
            freexit(EXIT_SUCCESS);
        }
        free(password2);
    }
    else
    {
        char *msg_2 = " decryption password:";
        char *msg = ft_strinsert(firstmsg_1, ssl.command.command_title, msg_2);   
        password = getpass(msg);
        free(msg);
    }
    return password;
}

static void    t_command_free(t_command *cmd)
{
    if (cmd->command_addr == des && ((t_des *)cmd->command_data)->password)
        free(((t_des *)cmd->command_data)->password);
    if (cmd->command_data)
        free(cmd->command_data);
}

static void    ssl_free()
{
    t_command_free(&ssl.dec_i_cmd);
    t_command_free(&ssl.command);
    t_command_free(&ssl.enc_o_cmd);

    t_hash_list_free(ssl.hash);

    free(ssl.ulrandom_path);
    if (ssl.ulrandom_fd > 0)
        close(ssl.ulrandom_fd);

    if (ssl.flags & o)
        close(ssl.fd_out);
}

void          freexit(int exit_state)
{
    ssl_free();
    exit(exit_state);
}

static void    t_ssl_init(t_ssl *ssl)
{
    srand(time(NULL));
    ft_bzero(ssl, sizeof(t_ssl));
    ssl->fd_out = 1;
    ssl->ulrandom_path = ft_strdup("/dev/urandom");
    ssl->ulrandom_fd = -2;      // Arbitrary value, no random file is open
}

int     main(int ac, char **av)
{
    int     ret;

    t_ssl_init(&ssl);
    if ((ret = parsing(ac, av)))
        freexit(ret);

    // Set output file descriptor (STDOUT as default)
    if (ssl.flags & o)
        if ((ssl.fd_out = open(ssl.output_file, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
            open_failed(" in ft_ssl main() function\n", ssl.output_file);

    // Decode input
    if (ssl.flags & decin)
        t_hash_decode_inputs(ssl.hash);

    t_hash_hashing(ssl.hash);

    // Encode output
    if (ssl.flags & encout)
        t_hash_encode_output(ssl.hash);
    // Base64 encode output (Do not encode if command_familly is already base64 in encryption mode)
    // if (ssl.flags & ao && !(ssl.command.command_addr == base64 && ssl.flags & e))

    t_hash_output(ssl.hash);

    ssl_free();
    return 0;
}
