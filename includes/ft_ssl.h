# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <fcntl.h>
# include <limits.h>
# include <math.h>
# include <time.h>

/*
    ft_ssl Data --------------------------------------
*/

typedef unsigned char   Mem_8bits;
typedef unsigned int    Word_32bits;
typedef unsigned long   Long_64bits;

# define MEM8_ByteSz    sizeof(Mem_8bits)        // 1 byte  or 8  bits
# define WORD32_ByteSz  sizeof(Word_32bits)      // 4 bytes or 32 bits
# define LONG64_ByteSz  sizeof(Long_64bits)      // 8 bytes or 64 bits

# define BUFF_SIZE      42
# define FILENOTFOUND   1

# define BIGENDIAN      0
# define LITTLEENDIAN   1

# define ENDMSG         0b10000000
# define INTMAXLESS1    (Word_32bits)pow(2, 32) - 1
# define HEXABASE       "0123456789abcdef"

typedef enum flags {
    I=64, O=128, a=256, ai=8192, ao=16384, A=32768,
    // Message Digest
    P_md=1, Q=2, R=4, S_md=8,
    // Cypher
    D=16, E=32,
    // Only des
    K=512, P_cipher=1024, S_cipher=2048, V=4096
}            e_flags;
# define AVFLAGS        (P_md + Q + R + D + E + A + AI + AO)
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
    
    Mem_8bits       *hash;      // Hashed bytecode
    int             hashByteSz; // Byte size

    int             error;      // FILENOTFOUND or 0
    struct s_hash *next;
}               t_hash;

Mem_8bits   *parse_key(char *str);
int         parsing(int ac, char **av);
void        freexit(int failure);
void        malloc_failed(char *errormsg);
void        open_failed(char *errormsg, char *file);
void        write_failed(char *errormsg);

void	    ft_bzero(void *s, size_t n);
void	    *ft_memcpy(void *dest, const void *src, size_t n);
Mem_8bits   *ft_memnew(int byteSz);
Mem_8bits   *ft_memdup(Mem_8bits *mem, int byteSz);

char        *ft_strnew(int len);
char	    *ft_strdup(char *src);
char    	*ft_strinsert(char *str1, char *toinsert, char *str2);
int		    ft_strlen(char *p);
int         ft_strcmp(const char *s1, const char *s2);
char        *ft_stradd_quote(char *str, int len);
char	    *ft_lower(char *str);

Long_64bits ft_strtoHex(char *str);
char        *ft_hextoStr(Long_64bits nbr);
char        *ft_hexToBin(Long_64bits n, int byteSz);

void	    ft_putstr(char *s);
void    	ft_putstdout(char *s);
void    	ft_putnbr(int fd, int n);
void        ft_printHex(Long_64bits n, int byteSz);
Mem_8bits   *ft_strHexToBin(Mem_8bits *str, int byteSz);


void        output(t_hash *hash);
void        key_output(Mem_8bits *p);
void        md_hash_output(t_hash *p);      // Temporally
void        print_usage();


/*
    Bitwise operations --------------------------------
*/

Mem_8bits       *padXbits(Mem_8bits **mem, int byteSz, int newSz);

Mem_8bits       endianReverseByte(Mem_8bits byte);
void            endianReverse(Mem_8bits *mem, Long_64bits byteSz);
Word_32bits     rotL(Word_32bits x, Word_32bits r);
Word_32bits     rotR(Word_32bits x, Word_32bits r);
Long_64bits     key_discarding(Mem_8bits *p);
Long_64bits     _bits_permutations(Long_64bits mem, char *ptable, int bitLen);
Long_64bits     bits_permutations(Long_64bits mem, char *ptable, int bitLen);


// Debug function, not used in this project
void        printByte(char byte);
void        printBits(void *p, int size);
void        printHex(void *p, int size);
void        printWord(Word_32bits word);
void        printLong(Long_64bits l);



/*
    ----------------------------------------------------
    MD
    ----------------------------------------------------
*/

# define CHUNK_ByteSz   (16 * sizeof(Word_32bits))    // 64 bytes or 512 bits

void        md_padding(Mem_8bits **data, Long_64bits *byteSz, char reverseByteSz);

/*
    MD5 Data -----------------------------------------
*/

# define    MD5_WordSz  4
# define    MD5_byteSz  MD5_WordSz * WORD32_ByteSz     // 16 bytes / 128 bits  

typedef struct  s_md5
{
    Mem_8bits   *chunks;
    Long_64bits chunksSz;
    Word_32bits sinus[64];
    Word_32bits constants[64];
    Word_32bits hash[MD5_WordSz];
}               t_md5;

// Mem_8bits   *md5(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
Mem_8bits   *md5(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
void        md5_t_hash(t_hash *hash);


/*
    SHA256 Data --------------------------------------
*/

# define    SHA256_WordSz  8
# define    SHA256_byteSz  SHA256_WordSz * WORD32_ByteSz     // 8 * 4 = 32 bytes / 256 bits  

typedef struct  s_sha
{
    Mem_8bits   *chunks;
    Long_64bits chunksSz;
    Word_32bits k[64];
    Word_32bits hash[SHA256_WordSz];
}               t_sha;

// void        sha256(t_hash *hash);
// void        sha256_msg(Mem_8bits **msg, int byteSz, Mem_8bits *dest);
// void        sha256_mod256(Mem_8bits **msg, int *len);
// void        sha256_xor_32bits(Word_32bits *sha1, Word_32bits *sha2, Word_32bits **result);

Mem_8bits   *sha256(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
void        sha256_t_hash(t_hash *hash);
void        sha256_xor_8bits(Mem_8bits *sha1, Mem_8bits *sha2, Mem_8bits **result);


/*
    ----------------------------------------------------
    CIPHERS
    ----------------------------------------------------
*/

typedef unsigned long   Key_64bits;

# define KEY_byteSz         sizeof(Key_64bits)      // 8 bytes / 64 bits
# define KEY_bitSz          KEY_byteSz * 8
# define KEYDISCARD_byteSz  KEY_byteSz - 1

Mem_8bits     *pbkdf2_sha256(Mem_8bits *pwd, Mem_8bits *salt, int c);

/*
    BASE64 Data --------------------------------------
*/

# define    BASE64  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

Mem_8bits   *base64(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
void        t_hash_base64_decode_inputs(t_hash *hash);


/*
    DES Data --------------------------------------
*/

typedef enum    desmode {
    DESECB=1, DESCBC=2
}               e_desmode;

typedef struct  s_des
{
    e_desmode   mode;
    Mem_8bits   *password;  // malloc
    Key_64bits  key;
    Key_64bits  salt;
    Key_64bits  vector;
    Key_64bits  subkeys[16];
    char        ipt[KEY_bitSz];     // Initial permutation table
    char        fpt[KEY_bitSz];     // Final   permutation table
}               t_des;

// void        des(t_hash *hash);
Mem_8bits   *des(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
Long_64bits des_padding(Mem_8bits *bloc);
void        des_unpadding(Long_64bits *lastbloc, int *ptSz);



/*
    MAIN structure ----------------------------------
*/

typedef struct  s_ssl
{
    char        *hash_func;
    Mem_8bits   *(*hash_func_addr)(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
    e_command   command;
    t_des       des;

    e_flags     flags;
    t_hash      *hash;

    char        *output_file;
    int         fd_out;
}               t_ssl;

extern t_ssl    ssl;

void    init_t_hash(t_hash *hash);
void    t_hash_free(t_hash *hash);
void    t_hash_base64_decode_inputs(t_hash *hash);
void    t_hash_base64_encode_output(t_hash *hash);
void    t_hash_hashing(t_hash *hash);
void    t_hash_output(t_hash *hash);
