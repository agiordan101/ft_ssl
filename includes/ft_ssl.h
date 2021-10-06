
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <fcntl.h>

// ft_ssl Data -----------------------------

# define BUFF_SIZE 42
# define FILENOTFOUND 1

typedef enum flags {
    P=1, Q=2, R=4, S=8
}            e_flags;

typedef struct  s_hash
{
    char            stdin;      // stdin or not
    char            *name;      // stdin / file name / -s string arg // Malloc
    char            *msg;       // Content to hash // Malloc
    size_t          len;        // Length of content
    char            *hash;       // hash result // Malloc
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

// int     ft_atoi(const char *str);
char	*ft_strnew(char *src);
int     ft_strcmp(const char *s1, const char *s2);
void	ft_putstr(char *s);
int		ft_strlen(char *p);
void	ft_bzero(void *s, size_t n);
void	*ft_memcpy(void *dest, const void *src, size_t n);
char    *ft_stradd_quote(char *str, int len);
// float   ft_abs(float x);

void    print_hash(t_hash *hash);
void    print_usage();



// MD5 Data --------------------------------

typedef unsigned char Mem_8bits;
typedef unsigned long Len_64bits;

// sizeof(Mem_8bits) = 1
# define WORD_ByteSz    4 * sizeof(Mem_8bits)      // 4 bytes or 32 bits
# define LEN_ByteSz     sizeof(Len_64bits)          // 8 bytes or 64 bits
# define HASH_ByteSz    16 * sizeof(Mem_8bits)     // 16 bytes or 128 bits
# define CHUNK_ByteSz   64 * sizeof(Mem_8bits)    // 64 bytes or 512 bits

typedef struct  s_md5
{
    Mem_8bits   chunk[CHUNK_ByteSz];
}               t_md5;


void         md5(t_hash *hash);
void         md5_failure(char *error_msg);
Mem_8bits    *padding(Mem_8bits **data, Len_64bits nBytes);



// SHA256 Data -----------------------------

void    sha256(t_hash *hash);
