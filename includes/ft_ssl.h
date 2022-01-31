# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <fcntl.h>
# include <limits.h>
# include <math.h>
# include <time.h>

# define    STDIN   0
# define    STDOUT  1
# define    STDERR  2

# define    BIGENDIAN      0
# define    LITTLEENDIAN   1

/*
    ft_ssl Data --------------------------------------
*/

typedef unsigned char   Mem_8bits;
typedef unsigned int    Word_32bits;
typedef unsigned long   Long_64bits;

# define MEM8_byteSz    sizeof(Mem_8bits)        // 1 byte  or 8  bits
# define WORD32_byteSz  sizeof(Word_32bits)      // 4 bytes or 32 bits
# define LONG64_byteSz  sizeof(Long_64bits)      // 8 bytes or 64 bits

# define INTMAXLESS1    (Word_32bits)pow(2, 32) - 1
// # define BIG_LONG64     ((Long_64bits)1 << 63) - 1

# define BUFF_SIZE      420

# define ENDMSG         0b10000000
# define HEXABASE       "0123456789abcdef"

typedef enum    error {
    FILENOTFOUND = 1 << 1,
    DONOTHASH = 1 << 2
}               e_error;

typedef enum    flags {
    i_=1<<1, o=1<<2, q=1<<3, a=1<<4, ai=1<<5, ao=1<<6, A=1<<7, help=1<<19,

    // Only Message Digest
    p_md=1<<8, r=1<<9, s_md=1<<10,

    // Only Cypher
    d=1<<11, e=1<<12,
        // Only des
        k_des=1<<13, p_des=1<<14, s_des=1<<15, v_des=1<<16, P_des=1<<17, nopad=1<<18,
    // Only PBKDF2
    pbkdf2_iter=1<<20,
}               e_flags;
# define AVFLAGS        (p_md + q + r + d + e + A + ai + ao + P_des + nopad + help)
# define AVPARAM        (s_md + i_ + o + k_des + p_des + s_des + v_des + pbkdf2_iter)

typedef enum    command {
    MD=1, CIPHER=2, STANDARD=4
}               e_command;

typedef struct  s_hash
{
    char            stdin;      // stdin or not
    char            *name;      // stdin / file name / -s string arg // Malloc
    char            *msg;       // Content to hash // Malloc
    int             len;        // Length of plaintext
    
    Mem_8bits       *hash;      // Hashed bytecode
    int             hashByteSz; // Byte size

    e_error         error;      // Others behavior
    struct s_hash *next;
}               t_hash;

int         parsing(int ac, char **av);
void        freexit(int failure);
char        *ask_password();

void        malloc_failed(char *errormsg);
void        open_failed(char *errormsg, char *file);
void        write_failed(char *errormsg, int fd);
void        file_not_found(char *file);
void        pbkdf2_iter_error();

void        output(t_hash *hash);
void        print_usage_exit();


/*
    Libft functions ---------------------------------
*/

void	    ft_bzero(void *s, size_t n);
void	    *ft_memcpy(void *dest, const void *src, size_t n);
Mem_8bits   *ft_memnew(int byteSz);
Mem_8bits   *ft_memdup(void *mem, int byteSz);
void        *ft_memjoin(void *mem1, int byteSz1, void *mem2, int byteSz2);

int     	ft_atoi(const char *str);
char	    *ft_strdup(char *src);
char    	*ft_strinsert(char *str1, char *toinsert, char *str2);
int		    ft_strlen(char *p);
int         ft_strcmp(const char *s1, const char *s2);
char        *ft_stradd_quote(char *str, int len);
char	    *ft_lower(char *str);

void	    ft_putstr(char *s);
void    	ft_putstrfd(int fd, char *s);
void    	ft_putstderr(char *s);
void    	ft_putnbr(int fd, int n);

void        ft_printHex(Long_64bits n, int byteSz);
Long_64bits ft_strtoHex(char *str);
char        *ft_hextoStr(Long_64bits nbr);


/*
    Bitwise operations --------------------------------
*/

Mem_8bits       endianReverseByte(Mem_8bits byte);
void            endianReverse(Mem_8bits *mem, Long_64bits byteSz);
Mem_8bits       *padXbits(Mem_8bits **mem, int byteSz, int newSz);
Word_32bits     rotL(Word_32bits x, Word_32bits r);
Word_32bits     rotR(Word_32bits x, Word_32bits r);
Long_64bits     key_discarding(Mem_8bits *p);
Long_64bits     _bits_permutations(Long_64bits mem, char *ptable, int bitLen);
Long_64bits     bits_permutations(Long_64bits mem, char *ptable, int bitLen);


/*
    Maths ---------------------------------------------
*/

Long_64bits ft_pow(Long_64bits a, int pow);
Long_64bits modular_exp(Long_64bits a, Long_64bits b, Long_64bits m);
Long_64bits modular_mult(Long_64bits a, Long_64bits b, Long_64bits mod);


/*
    Debug function, not used in this project -----------
*/

void        printByte(char byte);
void        printBits(void *p, int size);
void        printMemHex(void *p, int size, char *msg);
void        printWord(Word_32bits word);
void        printLong(Long_64bits l);



/*
    ----------------------------------------------------
    MD
    ----------------------------------------------------
*/

# define CHUNK_byteSz   (16 * sizeof(Word_32bits))    // 64 bytes or 512 bits

void        md_padding(Mem_8bits **data, Long_64bits *byteSz, char reverseByteSz);


/*
    MD5 Data -----------------------------------------
*/

# define    MD5_wordSz  4
# define    MD5_byteSz  MD5_wordSz * WORD32_byteSz     // 16 bytes / 128 bits  

typedef struct  s_md5
{
    Mem_8bits   *chunks;
    Long_64bits chunksSz;
    Word_32bits sinus[64];
    Word_32bits constants[64];
    Word_32bits hash[MD5_wordSz];
}               t_md5;

Mem_8bits   *md5(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
void        md5_t_hash(t_hash *hash);


/*
    SHA256 Data --------------------------------------
*/

# define    SHA256_bitSz    256
# define    SHA256_byteSz   SHA256_bitSz / 8
# define    SHA256_wordSz   SHA256_byteSz / WORD32_byteSz

typedef struct  s_sha
{
    Mem_8bits   *chunks;
    Long_64bits chunksSz;
    Word_32bits k[64];
    Word_32bits hash[SHA256_wordSz];
}               t_sha;

Mem_8bits   *sha256(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
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


/*
    BASE64 Data --------------------------------------
*/

# define    BASE64  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

Mem_8bits   *base64(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);


/*
    DES Data --------------------------------------
*/

# define PBKDF2_iter        10000
# define MAGICNUMBER        "Salted__"
# define MAGICNUMBER_byteSz sizeof(MAGICNUMBER) - 1
# define MAGICHEADER_byteSz (MAGICNUMBER_byteSz + KEY_byteSz)

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

Key_64bits  pbkdf2_sha256(Mem_8bits *pwd, Key_64bits salt, int c);
Mem_8bits   *pbkdf2_sha256_hmac(Mem_8bits *key, int keyByteSz, Mem_8bits *msg, int msgByteSz);

Mem_8bits   *des(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
Long_64bits des_padding(Mem_8bits *bloc);
void        des_unpadding(Long_64bits *lastbloc, int *ptSz);



/*
    ----------------------------------------------------
    STANDARD
    ----------------------------------------------------
*/

/*
    RSA Data --------------------------------------
*/

# define    ABS(x)          (x >= 0 ? x : -x)
# define    ISPRIMEMEMSZ    10

int         is_prime(Long_64bits n, float p);
Mem_8bits   *rsa(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);



/*
    ----------------------------------------------------
    MAIN structure
    ----------------------------------------------------
*/

typedef struct  s_ssl
{
    char        *hash_func;
    Mem_8bits   *(*hash_func_addr)(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way);
    e_command   command;
    e_flags     flags;

    t_des       des;
    int         pbkdf2_iter;

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

