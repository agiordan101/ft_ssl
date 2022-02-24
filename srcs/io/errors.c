#include "ft_ssl.h"

// Extern errors

void    open_failed(char *errormsg, char *file)
{
    ft_putstderr("[OPEN FAILED] Unable to open file: ");
    ft_putstderr(file);
    ft_putstderr(errormsg);
    perror(NULL);
    freexit(EXIT_FAILURE);
}

void    read_failed(char *errormsg, int fd)
{
    ft_putstderr("[READ FAILED] fd= ");
    ft_putnbr(STDERR, fd);
    ft_putstderr("\n");
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

void    malloc_failed(char *errormsg)
{
    ft_putstderr("[MALLOC FAILED] ");
    ft_putstderr(errormsg);
    perror(NULL);
    freexit(EXIT_FAILURE);
}

// ft_ssl errors

void    unrecognized_flag(char *flag)
{
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": Unrecognized flag ");
    ft_putstderr(flag);
    ft_putstderr("\n");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": Use -help for summary.\n");
    freexit(EXIT_SUCCESS);
}

void    flags_conflicting_error(char *flag1, char *flag2, char *errormsg)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": Flags ");
    ft_putstderr(flag1);
    ft_putstderr(" and ");
    ft_putstderr(flag2);
    ft_putstderr(" are conflicting");
    if (errormsg)
    {
        ft_putstderr(": ");
        ft_putstderr(errormsg);
    }
    else
        ft_putstderr(".");
    ft_putstderr("\n");
    freexit(EXIT_SUCCESS);
}

void    flag_error(char *flag, char *errormsg)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": Flag ");
    ft_putstderr(flag);
    ft_putstderr(" failed");
    if (errormsg)
    {
        ft_putstderr(": ");
        ft_putstderr(errormsg);
    }
    else
        ft_putstderr(".");
    ft_putstderr("\n");
    freexit(EXIT_SUCCESS);
}

void    pbkdf2_iter_error(int p)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": Non-positive number \"");
    ft_putnbr(STDERR, p);
    ft_putstderr("\" for -iter\n");
    freexit(EXIT_SUCCESS);
}

void    isprime_prob_error(int p)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": flag -prob argument \"");
    ft_putnbr(STDERR, p);
    ft_putstderr("\" does not respect probabilities conditions: 0 < p <= 100\n");
    freexit(EXIT_SUCCESS);
}

void    file_not_found(char *file)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": ");
    ft_putstderr(file);
    ft_putstderr(": No such file or directory\n");
    freexit(EXIT_SUCCESS);
}

void    rsa_format_error(char *form)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": Invalid format \"");
    ft_putstderr(form);
    ft_putstderr("\" for [-inform PEM | DER] or [-outform PEM | DER] flags.\n");
    freexit(EXIT_SUCCESS);
}

void    rsa_keys_integer_size_error(int byteSz)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(": Cannot read ");
    ft_putnbr(STDERR, byteSz * 8);
    ft_putstderr(" bits integers (64 bits maximum)\n");
    freexit(EXIT_SUCCESS);
}

void    rsa_parsing_keys_error(e_flags privpubin, e_flags inform, char *errormsg, int value)
{
    ft_putstderr("ft_ssl: ");
    ft_putstderr(ssl.command.command_title);
    ft_putstderr(privpubin & pubin ? ": Unable to load PUBLIC key " : ": Unable to load PRIVATE key ");
    ft_putstderr(inform & PEM ? "in PEM format: " : "in DER format: ");
    ft_putstderr(errormsg);
    if (value >= 0)
        ft_putnbr(STDERR, value);
    ft_putstderr("\n");
    freexit(EXIT_SUCCESS);
}
