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



    Success ->

        - DES-ECB encryption ascii output:
            ./ft_ssl des-ecb -k 0123456789abcdef -i Makefile -q | openssl des-ecb -K 0123456789abcdef -out Makefile_encdec -d && diff Makefile Makefile_encdec

        - DES-ECB encryption base64 output:
            ./ft_ssl des-ecb -k 0123456789abcdef -i Makefile -q -a | openssl des-ecb -K 0123456789abcdef -out Makefile_encdec -a -d && diff Makefile Makefile_encdec


        - DES-ECB encryption/decryption ascii:
            ./ft_ssl des-ecb -k 0123456789abcdef -i Makefile -q | ./ft_ssl des-ecb -k 0123456789abcdef -o Makefile_encdec -d && diff Makefile Makefile_encdec

        - DES-ECB encryption/decryption base64:
            ./ft_ssl des-ecb -k 0123456789abcdef -i Makefile -q -a -A | ./ft_ssl des-ecb -k 0123456789abcdef -o Makefile_encdec -a -A -d && diff Makefile Makefile_encdec

    Failed ->

        - DES-ECB decryption ascii input:
            openssl des-ecb -K 0123456789abcdef -in Makefile | ./ft_ssl des-ecb -k 0123456789abcdef -d -o Makefile_encdec && diff Makefile Makefile_encdec

        - DES-ECB decryption base64 input:
            openssl des-ecb -K 0123456789abcdef -in Makefile -a | ./ft_ssl des-ecb -k 0123456789abcdef -a -d -o Makefile_encdec && diff Makefile Makefile_encdec

        - DES-ECB encryption/decryption base64:
            ./ft_ssl des-ecb -k 0123456789abcdef -i Makefile -q -a | ./ft_ssl des-ecb -k 0123456789abcdef -o Makefile_encdec -a -d && diff Makefile Makefile_encdec



    Probleme : dans le parsing le read bloque à 8192 bytes du stdin de temps en temps, pk ??

        openssl des-ecb -K 0123456789abcdef -in srcs/des.c -a -A | ./ft_ssl des-ecb -k 0123456789abcdef -a -A -d -o unitests_out && diff srcs/des.c unitests_out



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
    perror(NULL);
    freexit(EXIT_FAILURE);
}

void    open_failed(char *errormsg, char *file)
{
    ft_putstdout("[OPEN FAILED] Unable to open file=");
    ft_putstdout(file);
    ft_putstdout(errormsg);
    perror(NULL);
    freexit(EXIT_FAILURE);
}

void    write_failed(char *errormsg)
{
    ft_putstdout("[WRITE FAILED] fd= ");
    ft_putnbr(1, ssl.fd_out);
    ft_putstdout("\n");
    ft_putstdout(errormsg);
    perror(NULL);
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
    if (ssl.flags & ai)
        t_hash_base64_decode_inputs(ssl.hash);

    t_hash_hashing(ssl.hash);

    // Base64 encode output
    if (ssl.flags & ao && !(ssl.hash_func_addr == base64 && ssl.flags & E))
        t_hash_base64_encode_output(ssl.hash);

    t_hash_output(ssl.hash);

    ssl_free();
    return 0;
}
