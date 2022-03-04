#include "ft_ssl.h"

/*
    ft_ssl_md5 -> Pas de prérequis pour corriger
    ft_ssl_des -> Avoir commencé ft_ssl_md5
    ft_ssl_rsa -> Avoir fini ft_ssl_des

    To do :

        Tester rsautl et genrsa avec encout et decin
        
        pbkdf2 unitest 
        Créer un test/comparaison openssl -P pour des

        Essayer plusieurs input avec toutes les commandes
        
        //Leaks ft_stradd_quote ?
        Gerer les \n dans l'output (pas dans les ft hash)
        Selectionner la sortie du dernier \n en fonction des commandes

*/

t_ssl    ssl;

char        *ask_password(char *cmd_name, e_flags flags)
{
    char *firstmsg_1 = "enter ";
    char *password;

    if (flags & e)
    {
        char *secondmsg_1 = "Verifying - enter ";
        char *msg_2 = " encryption password:";
        char *firstmsg = ft_strinsert(firstmsg_1, cmd_name, msg_2);
        char *secondmsg = ft_strinsert(secondmsg_1, cmd_name, msg_2);

        char *password2 = ft_strdup(getpass(firstmsg));
        password = getpass(secondmsg);

        free(firstmsg);
        free(secondmsg);
        if (ft_strcmp(password, password2))
        {
            free(password2);
            ft_ssl_error("Password catching error.\nVerify failure.\nbad password read.\n");
        }
        free(password2);
    }
    else
    {
        char *msg_2 = " decryption password:";
        char *msg = ft_strinsert(firstmsg_1, cmd_name, msg_2);   
        password = getpass(msg);
        free(msg);
    }
    return password;
}

static void    t_command_free(t_command *cmd)
{
    if (cmd->command & DES && ((t_des *)cmd->command_data)->password)
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
    t_ssl_init(&ssl);
    parsing(ac, av);

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

    t_hash_output(ssl.hash);

    ssl_free();
    return 0;
}
