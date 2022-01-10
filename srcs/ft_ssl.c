#include "ft_ssl.h"

/*
    Message digest :
        Ne pas reverse le stdin avec -r
        MD5 au debut sauf en reverse ou stdin
        -p -q -r alors print STDIN + \n + hash pour la premiere ligne
        .. -q -r = .. -q car -r s'annule en présence de -q

    To do :
        -nosalt             Do not use salt in the KDF

    Attention -a et -a -A ne sortent pas la meme chose (Seulement un \n qui difere)

    REMETTRE LES FLAGS DE COMPILATION DANS LE MAKEFILE PTN

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
        char *firstmsg = ft_strinsert(firstmsg_1, ssl.hash_func, msg_2);
        char *secondmsg = ft_strinsert(secondmsg_1, ssl.hash_func, msg_2);

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
        char *msg = ft_strinsert(firstmsg_1, ssl.hash_func, msg_2);   
        password = getpass(msg);
        free(msg);
    }
    return password;
}

void    ssl_free()
{
    t_des    *des = &ssl.des;

    if (des->password)
        free(des->password);

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

    // Base64 encode output (Do not encode if command is already base64 in encryption mode)
    if (ssl.flags & ao && !(ssl.hash_func_addr == base64 && ssl.flags & e))
        t_hash_base64_encode_output(ssl.hash);

    t_hash_output(ssl.hash);

    ssl_free();
    return 0;
}
