
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <fcntl.h>

# define BUFF_SIZE 42
# define FILENOTFOUND 1

typedef enum flags {
    P=1, Q=2, R=4, S=8
}            e_flags;

typedef struct  s_hash
{
    char            stdin;      // stdin or not
    char            *name;      // stdin / file name / -s string arg
    char            *msg;       // Content to hash
    size_t          len;        // Length of content
    char            *hash;       // Content to hash
    int             error;
    struct s_hash *next;
}               t_hash;

typedef struct  s_ssl
{
    char        *hash_func;
    void        (*hash_func_addr)();
    e_flags     flags;
    t_hash      *hash;
}               t_ssl;

extern t_ssl    ssl;

int     parsing(int ac, char **av);

void    sha256(t_hash *hash);
void    md5(t_hash *hash);

// int     ft_atoi(const char *str);
char	*ft_strnew(char *src);
int     ft_strcmp(const char *s1, const char *s2);
void	ft_putstr(char *s);
int		ft_strlen(char *p);
void	*ft_memcpy(void *dest, const void *src, size_t n);
char    *ft_stradd_quote(char *str, int len);
// float   ft_abs(float x);

void    print_hash(t_hash *hash);

void    print_usage();
