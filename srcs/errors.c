#include "ft_ssl.h"

// Extern errors

void    malloc_failed(char *errormsg)
{
    ft_putstderr("[MALLOC FAILED] ");
    ft_putstderr(errormsg);
    perror(NULL);
    freexit(EXIT_FAILURE);
}

void    open_failed(char *errormsg, char *file)
{
    ft_putstderr("[OPEN FAILED] Unable to open file: ");
    ft_putstderr(file);
    ft_putstderr(errormsg);
    perror(NULL);
    freexit(EXIT_FAILURE);
}

void    write_failed(char *errormsg, int fd)
{
    ft_putstderr("[WRITE FAILED] fd= ");
    ft_putnbr(STDERR, fd);
    ft_putstderr("\n");
    ft_putstderr(errormsg);
    perror(NULL);
    freexit(EXIT_FAILURE);
}

// ft_ssl errors

void    pbkdf2_iter_error()
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.hash_func);
    ft_putstderr(": Non-positive number \"");
    ft_putnbr(STDERR, ssl.pbkdf2_iter);
    ft_putstderr("\" for -iter\n");
    freexit(EXIT_SUCCESS);
}

void    file_not_found(char *file)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.hash_func);
    ft_putstderr(": ");
    ft_putstderr(file);
    ft_putstderr(": No such file or directory\n");
    freexit(EXIT_SUCCESS);
}
