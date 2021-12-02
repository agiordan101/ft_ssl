#include "ft_ssl.h"

/*
    Ne pas reverse le stdin avec -r
    MD5 au debut sauf en reverse ou stdin
    -p -q -r alors print STDIN + \n + hash pour la premiere ligne
    .. -q -r = .. -q car -r s'annule en présence de -q


    DES("12345678") = DES("12345678\n") Wtf ???

*/

t_ssl    ssl;

void    ssl_free()
{
    t_hash      *tmp;
    t_hash      *hash = ssl.hash;
    t_des    *des = &ssl.des;

    // if (des->key)
    //     free(des->key);
    // if (des->salt)
    //     free(des->salt);
    // if (des->vector)
    //     free(des->vector);
    if (des->password)
        free(des->password);

    while (hash)
    {
        if (hash->name)
            free(hash->name);
        if (hash->msg)
            free(hash->msg);
        if (hash->hash_32bits)
            free(hash->hash_32bits);
        tmp = hash;
        hash = hash->next;
        free(tmp);
    }

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

    t_hash *hash = ssl.hash;
    while (hash)
    {
        // printf("hash->msg: >%s<\n", hash->msg);
        // printf("hash->name: >%s<\n", hash->name);
        ssl.hash_func_addr(hash);
        output(hash);
        hash = hash->next;
    }

    ssl_free();
    return 0;
}
