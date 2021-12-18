#include "ft_ssl.h"

/*
    Message digest :
        Ne pas reverse le stdin avec -r
        MD5 au debut sauf en reverse ou stdin
        -p -q -r alors print STDIN + \n + hash pour la premiere ligne
        .. -q -r = .. -q car -r s'annule en présence de -q

    To do :
        -nosalt to make
        add -q to usage
        add -P to usage
        shuffle usage right order
        des seg fault sans -k
*/

t_ssl    ssl;

void    ssl_free()
{
    t_hash      *tmp;
    t_hash      *hash = ssl.hash;
    t_des    *des = &ssl.des;

    if (des->password)
        free(des->password);

    t_hash_free(ssl.hash);

    if (ssl.flags & O)
        close(ssl.fd_out);
}

void    freexit(int exit_state)
{
    ssl_free();
    exit(exit_state);
}

void    malloc_failed(char *errormsg)
{
    ft_putstr("[MALLOC FAILED] ");
    ft_putstr(errormsg);
    freexit(EXIT_FAILURE);
}

void    open_failed(char *errormsg, char *file)
{
    ft_putstdout("[OPEN FAILED] Unable to open file=");
    ft_putstdout(file);
    ft_putstdout(errormsg);
    freexit(EXIT_FAILURE);
}

int     main(int ac, char **av)
{
    int     ret;

    ssl.fd_out = 1;
    if ((ret = parsing(ac, av)))
        freexit(ret);

    // Set output file descriptor (STDOUT as default)
    if (ssl.flags & O)
        if ((ssl.fd_out = open(ssl.output_file, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
            open_failed(" in ft_ssl main() function\n", ssl.output_file);

    // Base64 decode input
    if (ssl.flags & AI)
        t_hash_base64_decode_inputs(ssl.hash);

    t_hash_hashing(ssl.hash);

    // Base64 encode output
    if (ssl.flags & AO && !(ssl.hash_func_addr == base64 && ssl.flags & E))
        t_hash_base64_encode_output(ssl.hash);

    t_hash_output(ssl.hash);

    ssl_free();
    return 0;
}
