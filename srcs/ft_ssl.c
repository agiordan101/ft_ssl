#include "ft_ssl.h"

/*
    ft_ssl_md5 -> Pas de prérequis pour corriger
    ft_ssl_des -> Avoir commencé ft_ssl_md5
    ft_ssl_rsa -> Avoir fini ft_ssl_des

    To do :

        INTMAXLESS1 enlever le pow
        Faire la différence entre les command_familly et les commands (On peut pas comparer les adresses car plusieurs fonctions existe pour la meme commande)
        Enlever les protection useless dans le parsing
        Gerer les \n dans l'output (pas dans les ft hash)
        Afficher l'usage de la command_familly passé
        Boucler pour les flags parsing pt sur ft
        -nosalt             Do not use salt in the KDF

*/

t_ssl    ssl;

char    *ask_password()
{
    char *firstmsg_1 = "enter ";
    char *password;

    if (ssl.flags & e)
    {
        char *secondmsg_1 = "Verifying - enter ";
        char *msg_2 = " encryption password:";
        char *firstmsg = ft_strinsert(firstmsg_1, ssl.command_title, msg_2);
        char *secondmsg = ft_strinsert(secondmsg_1, ssl.command_title, msg_2);

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
        char *msg = ft_strinsert(firstmsg_1, ssl.command_title, msg_2);   
        password = getpass(msg);
        free(msg);
    }
    return password;
}

void    ssl_free()
{
    if (ssl.command_data)
    {
        if (ssl.command_addr == des && ((t_des *)ssl.command_data)->password)
            free(((t_des *)ssl.command_data)->password);
        free(ssl.command_data);
    }

    t_hash_free(ssl.hash);

    if (ssl.flags & o)
        close(ssl.fd_out);
}

void    freexit(int exit_state)
{
    ssl_free();
    exit(exit_state);
}

int     main(int ac, char **av)
{
    int     ret;

    srand(time(NULL));
    ssl.fd_out = 1;
    if ((ret = parsing(ac, av)))
        freexit(ret);

    if (ssl.flags & help)
        print_usage_exit();

    // Set output file descriptor (STDOUT as default)
    if (ssl.flags & o)
        if ((ssl.fd_out = open(ssl.output_file, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
            open_failed(" in ft_ssl main() function\n", ssl.output_file);

    // Base64 decode input
    if (ssl.flags & ai)
        t_hash_base64_decode_inputs(ssl.hash);

    t_hash_hashing(ssl.hash);

    // Base64 encode output (Do not encode if command_familly is already base64 in encryption mode)
    if (ssl.flags & ao && !(ssl.command_addr == base64 && ssl.flags & e))
        t_hash_base64_encode_output(ssl.hash);

    t_hash_output(ssl.hash);

    ssl_free();
    return 0;
}
