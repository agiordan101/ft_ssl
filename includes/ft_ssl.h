
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <fcntl.h>
# include <limits.h>
# include <math.h>

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
    int             len;        // Length of content
    // char            *hash;       // hash result // Malloc
    // Word_32bits     hash[4];
    unsigned int    hash[4];    // Hash result, made by algorithm
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

void    freexit(int failure);
int     parsing(int ac, char **av);

// int     ft_atoi(const char *str);
char	*ft_strnew(char *src);
int     ft_strcmp(const char *s1, const char *s2);
void	ft_putstr(char *s);
int		ft_strlen(char *p);
void	ft_bzero(void *s, size_t n);
void	ft_fill(void *s, size_t n, char c);
void	*ft_memcpy(void *dest, const void *src, size_t n);
char    *ft_stradd_quote(char *str, int len);
int     ft_abs(int x);
double   ft_fabs(double x);

void    output(t_hash *hash);
void    print_usage();



// MD5 Data --------------------------------

typedef unsigned char   Mem_8bits;
typedef unsigned long   Long_64bits;
typedef unsigned int    Word_32bits;

// sizeof(Mem_8bits) = 1

# define WORD_ByteSz    sizeof(Word_32bits)      // 4 bytes or 32 bits
# define LONG64_ByteSz  sizeof(Long_64bits)          // 8 bytes or 64 bits
# define HASH_ByteSz    (16 * sizeof(Mem_8bits))     // 16 bytes or 128 bits
# define CHUNK_ByteSz   (16 * sizeof(Word_32bits))    // 64 bytes or 512 bits

# define BIGENDIAN      0
# define LITTLEENDIAN   1

# define ENDMSG         0b10000000
# define UINTMAX       (unsigned int)pow(2, 32)

typedef struct  s_md5
{
    Mem_8bits   *chunks;
    Long_64bits chunksSz;
    Word_32bits sinus[64];
    Word_32bits constants[64];
    Word_32bits hash[4];
    Word_32bits h0;
    Word_32bits h1;
    Word_32bits h2;
    Word_32bits h3;
}               t_md5;

void        md5(t_hash *hash);
void        md5_failure(char *error_msg);

void        padding(Mem_8bits **data, Long_64bits *byteSz);
Mem_8bits   endianReverseByte(Mem_8bits byte);
void        endianReverse(Mem_8bits *mem, Long_64bits byteSz);
Word_32bits leftRotate(Word_32bits x, Word_32bits r);

void        printHash(Word_32bits hash_p[4]);
// void        printBits(Mem_8bits *b, Long_64bits size, char endianness);
// void        printHex(Mem_8bits *b, Long_64bits size);
// void        printHex(Mem_8bits *b, Long_64bits size, char endianness);
void    printByte(char byte);
void    printBits(void *p, int size);
void    printHex(void *p, int size);
void    ft_printHex(Word_32bits n);



// SHA256 Data -----------------------------

void    sha256(t_hash *hash);
