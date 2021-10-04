
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <fcntl.h>

# define BUFF_SIZE 420

typedef enum flags {
    P=1, Q=2, R=4, S=8
}            e_flags;

typedef struct  s_tohash
{
    char            *type;      // stdin / file name / -s string arg
    char            *msg;       // Content to hash
    size_t          len;        // Length of content
    struct s_tohash *next;
}               t_tohash;

// typedef struct  s_flags
// {
//     char        p;
//     char        q;
//     char        r;
//     char        s;
// };

typedef struct  s_ssl
{
    void        (*hash_func)();
    e_flags     flags;
    t_tohash    *tohash;
}               t_ssl;

extern t_ssl    ssl;

int     parsing(int ac, char **av);

void    md5();
void    sha256();

int     ft_atoi(const char *str);
int     ft_strcmp(const char *s1, const char *s2);
void	ft_putstr(char *s);
int		ft_strlen(char *p);
// float   ft_abs(float x);
// void	*ft_memcpy(void *dest, const void *src, size_t n);

void    print_usage();
