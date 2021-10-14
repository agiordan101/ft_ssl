
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <fcntl.h>
# include <limits.h>
# include <math.h>

/*
    ft_ssl Data --------------------------------------
*/

typedef unsigned char   Mem_8bits;
typedef unsigned long   Long_64bits;
typedef unsigned int    Word_32bits;

# define WORD_ByteSz    sizeof(Word_32bits)      // 4 bytes or 32 bits
# define LONG64_ByteSz  sizeof(Long_64bits)          // 8 bytes or 64 bits
# define HASH_ByteSz    (16 * sizeof(Mem_8bits))     // 16 bytes or 128 bits
# define CHUNK_ByteSz   (16 * sizeof(Word_32bits))    // 64 bytes or 512 bits

# define BUFF_SIZE      42
# define FILENOTFOUND   1

# define BIGENDIAN      0
# define LITTLEENDIAN   1

# define ENDMSG         0b10000000
# define INTMAXLESS1    (Word_32bits)pow(2, 32) - 1

typedef enum flags {
    // Message Digest
    P_md=1, Q=2, R=4, S_md=8,
    // Cypher
    D=16, E=32, I=64, O=128,
    //   Only des
    A=256, K=512, P_cipher=1024, S_cipher=2048, V=4096
}            e_flags;
# define AVFLAGS        (P_md + Q + R + D + E + A)
# define AVPARAM        (S_md + I + O + K + P_cipher + S_cipher + V)

typedef enum    command {
    MD=1, CIPHER=2, STANDARD=4
}               e_command;

typedef struct  s_hash
{
    char            stdin;      // stdin or not
    char            *name;      // stdin / file name / -s string arg // Malloc
    char            *msg;       // Content to hash // Malloc
    int             len;        // Length of content
    // unsigned int    hash[8];    // Hash result, made by commands
    void           *hash;
    int             hashlen;
    int             error;      // FILENOTFOUND or 0
    struct s_hash *next;
}               t_hash;

int     parsing(int ac, char **av);
void    padding(Mem_8bits **data, Long_64bits *byteSz, char reverseByteSz);
void    freexit(int failure);

void	ft_bzero(void *s, size_t n);
void	*ft_memcpy(void *dest, const void *src, size_t n);
char	*ft_strnew(char *src);
int		ft_strlen(char *p);
int     ft_strcmp(const char *s1, const char *s2);
char    *ft_stradd_quote(char *str, int len);
char	*ft_lower(char *str);
void	ft_putstr(char *s);
void    ft_printHex(Word_32bits n);

void    output(t_hash *hash);
void    print_usage();



/*
    Bitwise operations --------------------------------
*/

Mem_8bits   endianReverseByte(Mem_8bits byte);
void        endianReverse(Mem_8bits *mem, Long_64bits byteSz);
Word_32bits rotL(Word_32bits x, Word_32bits r);
Word_32bits rotR(Word_32bits x, Word_32bits r);

// Debug function, not used in this project
void        printByte(char byte);
void        printBits(void *p, int size);
void        printHex(void *p, int size);



/*
    MD5 Data -----------------------------------------
*/

typedef struct  s_md5
{
    Mem_8bits   *chunks;
    Long_64bits chunksSz;
    Word_32bits sinus[64];
    Word_32bits constants[64];
    Word_32bits hash[4];
}               t_md5;

void    md5(t_hash *hash);



/*
    SHA256 Data --------------------------------------
*/

typedef struct  s_sha
{
    Mem_8bits   *chunks;
    Long_64bits chunksSz;
    Word_32bits k[64];
    Word_32bits hash[8];
}               t_sha;

void    sha256(t_hash *hash);

/*
    ----------------------------------------------------
    CIPHERS
    ----------------------------------------------------
*/

typedef struct  s_cipher
{
    char        *key;    // No malloc
    char        *password;  // No malloc
    char        *salt;      // No malloc
    char        *vector;    // No malloc
}               t_cipher;

/*
    BASE64 Data --------------------------------------
*/

void        base64(t_hash *hash);



/*
    DES Data --------------------------------------
*/

// typedef struct  s_des
// {
// }               t_des;

// void        des(t_hash *hash);



/*
    MAIN structure ----------------------------------
*/

typedef struct  s_ssl
{
    char        *hash_func;
    void        (*hash_func_addr)();
    e_command   command;
    t_cipher    cipher;

    e_flags     flags;
    t_hash      *hash;

    char        *output_file;
}               t_ssl;

extern t_ssl    ssl;
