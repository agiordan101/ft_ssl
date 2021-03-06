#ifndef FT_SSL_H
#define FT_SSL_H

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

typedef unsigned char   Mem_8bits;
typedef unsigned int    Word_32bits;
typedef unsigned long   Long_64bits;

# define MEM8_byteSz    sizeof(Mem_8bits)        // 1 byte  or 8  bits
# define WORD32_byteSz  sizeof(Word_32bits)      // 4 bytes or 32 bits
# define LONG64_byteSz  sizeof(Long_64bits)      // 8 bytes or 64 bits

# define BIG_LONG64     ((Long_64bits)1 << 63) - 1

# define ABS(x)         (x >= 0 ? x : -x)
# define HEXABASE_low   "0123456789abcdef"
# define HEXABASE_upp   "0123456789ABCDEF"
# define BUFF_SIZE      420


//  FLAGS --------------------------------------------------------

# define N_FLAGS        35

typedef enum    flags {
    // Global flags
    help=1<<1,
    i_=1<<2, o=1<<3,
    q=1<<4, r=1<<5,
    a=1<<6, A=1<<7,
    decin=1<<8, encout=1<<9,
    passin=1<<25, passout=1<<26,

    // All hashing commands
    s=1<<10, p=1<<11,
    
    // Encyption & Decryption commands
    e=1<<12, d=1<<13, 

    // Only des
    pass=1<<14, salt=1<<15, k=1<<16, v=1<<17,
    P=1<<18, nopad=1<<19, pbkdf2_iter=1<<20,

    // Only isprime
    prob=1<<21,
    // Only genprime
    min=1<<22, max=1<<23,
    
    // For commands that use randomness
    rand_path=1<<24,

    // RSA cryptosystem
    pubin=1UL<<31, pubout=1UL<<32,
    check=1<<27, text=1<<28, noout=1<<29, modulus=1<<30,
    inform=1UL<<33, outform=1UL<<34,
    inkey=1UL<<35, // rsault
}               e_flags;
# define AVFLAGS        (help + p + q + r + d + e + A + P + nopad + check + text + noout + modulus + pubin + pubout)
# define AVPARAM        (s + i_ + o + decin + encout + k + pass + salt + v + pbkdf2_iter + prob + min + max + rand_path + inform + outform + passin + passout + inkey)

# define GLOBAL_FLAGS_IN        (i_ + decin + passin)
# define GLOBAL_FLAGS_OUT       (o + encout + passout + a + A)
# define GLOBAL_FLAGS           (help + GLOBAL_FLAGS_IN + GLOBAL_FLAGS_OUT + q + r)
# define DATASTRINPUT_FLAGS     (s + p)
# define ENCDEC                 (e + d)
# define DES_FLAGS_ONLY         (k + pass + salt + v + P + nopad + pbkdf2_iter)
# define RSA_FLAGS_ONLY         (inform + outform + check + text + noout + modulus + pubin + pubout)

//  COMMAND & FLAGS relationship --------------------------------------------------------

typedef enum    command_flags {
    MD_flags=       GLOBAL_FLAGS + DATASTRINPUT_FLAGS,
    BASE64_flags=   GLOBAL_FLAGS + DATASTRINPUT_FLAGS + ENCDEC,
    DES_flags=      GLOBAL_FLAGS + DES_FLAGS_ONLY + ENCDEC,
    PBKDF2_flags=   GLOBAL_FLAGS + salt + pbkdf2_iter,
    GENPRIME_flags= GLOBAL_FLAGS_OUT + help + q + min + max + rand_path,
    ISPRIME_flags=  GLOBAL_FLAGS + DATASTRINPUT_FLAGS + prob,
    GENRSA_flags=   GLOBAL_FLAGS_OUT + help + rand_path + pubout + outform,
    RSA_flags=      GLOBAL_FLAGS_IN + help + o + encout + passout + RSA_FLAGS_ONLY,
    RSAUTL_flags=   GLOBAL_FLAGS + DATASTRINPUT_FLAGS + ENCDEC + inkey + inform + pubin,
}               e_command_flags;


//  COMMANDS --------------------------------------------------------

# define N_COMMANDS 11

typedef enum    command {
    MD5=1<<1, SHA256=1<<2, BASE64=1<<3,
    DESECB=1<<4, DESCBC=1<<5, PBKDF2=1<<6,
    GENPRIME=1<<7, ISPRIME=1<<8,
    GENRSA=1<<9, RSA=1<<10, RSAUTL=1<<11
}               e_command;
# define MD                     (MD5 + SHA256)
# define DES                    (DESECB + DESCBC)
# define RSA_CMDS               (GENRSA + RSA + RSAUTL)

# define DESDATA_NEED_COMMANDS  (DES + PBKDF2)

# define HASHING_COMMANDS       (MD + BASE64 + DES + RSAUTL)
# define THASHNEED_COMMANDS     (HASHING_COMMANDS + PBKDF2 + ISPRIME + RSA)
# define EXECONES_COMMANDS      (GENPRIME + GENRSA + RSA + RSAUTL)

typedef struct  s_command {
    e_command       command;
    e_command_flags command_flags;
    char            *command_title;
    Mem_8bits       *(*command_wrapper)(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);
    void            *command_data;
}               t_command;


//  Others ft_ssl Data ----------------------------------------

typedef enum    error {
    FILENOTFOUND = 1 << 1,
    DONOTHASH = 1 << 2
}               e_error;

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

void        parsing(int ac, char **av);
void        command_handler(t_command *command, char *cmd, e_command mask);
char        *ask_password(char *cmd_name, e_flags flags);
t_hash      *add_thash_front();

void        output(t_hash *hash);

void        invalid_command(char *cmd);
void        print_commands();
void        print_command_usage(e_command cmd);
void        freexit(int failure);
void        ssl_free();


void        ft_ssl_error(char *errormsg);
void        unrecognized_flag(char *flag);
void        flags_conflicting_error(char *flag1, char *flag2, char *errormsg);
void        flag_error(char *flag, char *errormsg);
void        pbkdf2_iter_error();
void        isprime_prob_error(int p);
void        file_not_found(char *file);
void        rsa_format_error(char *form);
void        rsa_keys_integer_size_error(int byteSz);
void        rsa_parsing_keys_error(e_flags privpubin, e_flags inform, char *errormsg, int value);

void        open_failed(char *errormsg, char *file);
void        write_failed(char *errormsg, int fd);
void        read_failed(char *errormsg, int fd);
void        malloc_failed(char *errormsg);


/*
    Libft functions ---------------------------------
*/

void	    ft_bzero(void *s, size_t n);
void	    *ft_memcpy(void *dest, const void *src, size_t n);
Mem_8bits   *ft_memnew(int byteSz);
Mem_8bits   *ft_memdup(void *mem, int byteSz);
void        *ft_memjoin(void *mem1, int byteSz1, void *mem2, int byteSz2);

Long_64bits	ft_atoi(const char *str);
char    	*ft_ulltoa(Long_64bits n);
char	    *ft_strdup(char *src);
char    	*ft_strinsert(char *str1, char *toinsert, char *str2);
int		    ft_strlen(char *p);
int         ft_strcmp(const char *s1, const char *s2);
int     	ft_strncmp(const char *s1, const char *s2, size_t n);
char        *ft_stradd_quote(char *str, int len);
char	    *ft_lower(char *str);

int         ft_unbrlen(Long_64bits nbr);

void	    ft_putstr(char *s);
void    	ft_putstrfd(int fd, char *s);
void    	ft_putstderr(char *s);
void    	ft_putnbr(Long_64bits n);
void    	ft_putnbrfd(int fd, Long_64bits n);

void        ft_printHex(Long_64bits n);
void        _ft_printHex(Long_64bits n, int totalMemSz, char hexbase[], int leading_zero);
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
int             count_bytes(Long_64bits n);
int             count_bits(Long_64bits n);


/*
    Maths ---------------------------------------------
*/

# define    URANDBUFF   (100 * LONG64_byteSz)

// Long_64bits ft_pow(Long_64bits a, int pow);
Long_64bits modular_exp(Long_64bits a, Long_64bits b, Long_64bits m);
// Long_64bits modular_mult(Long_64bits a, Long_64bits b, Long_64bits mod);
long long   modular_mult(long long a, Long_64bits b, Long_64bits mod);
Long_64bits ulrandom();
Long_64bits ulrandom_range(Long_64bits min, Long_64bits max);
int         ulmult_overflow(Long_64bits a, Long_64bits b);
Long_64bits gcd(Long_64bits a, Long_64bits b);
Long_64bits mod_mult_inverse(Long_64bits a, Long_64bits b);


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
# define ENDMSG         0b10000000

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

Mem_8bits   *md5(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz);
Mem_8bits   *cmd_wrapper_md5(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);

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

Mem_8bits   *sha256(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz);
Mem_8bits   *cmd_wrapper_sha256(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);

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

Mem_8bits   *base64(Mem_8bits *input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags way);
Mem_8bits   *cmd_wrapper_base64(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);

# define    BASE64_BASE  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


/*
    DES Data --------------------------------------
*/

# define MAGICNUMBER        "Salted__"
# define MAGICNUMBER_byteSz (sizeof(MAGICNUMBER) - 1)
# define MAGICHEADER_byteSz (MAGICNUMBER_byteSz + KEY_byteSz)

typedef struct  salt
{
    e_command   mode;               // Not necessarily related to command
    Mem_8bits   *password;          // Malloced
    Key_64bits  key;
    Key_64bits  salt;
    Key_64bits  vector;
    Key_64bits  subkeys[16];
    char        ipt[KEY_bitSz];     // Initial permutation table
    char        fpt[KEY_bitSz];     // Final   permutation table
    int         pbkdf2_iter;
}               t_des;

Mem_8bits   *des(t_des *des_data, Mem_8bits *input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);
Mem_8bits   *cmd_wrapper_des(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);

Long_64bits des_padding(Mem_8bits *bloc, Long_64bits blocSz);
void        des_unpadding(Long_64bits *lastbloc, int *ptBlocSz);


/*
    PBKDF2 Data --------------------------------------
*/

# define PBKDF2_iter        10000

Key_64bits  pbkdf2_sha256(Mem_8bits *pwd, Long_64bits pwdByteSz, Key_64bits salt, int c);
Mem_8bits   *cmd_wrapper_pbkdf2(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);


/*
    ----------------------------------------------------
    STANDARD
    ----------------------------------------------------
*/

# define    LONG64_LEFTBITMASK  (1UL << 62)


/*
    isprime Data --------------------------------------
*/

# define    PROBMIN_ISPRIME 0.001
# define    ISPRIMEMEMSZ    10

typedef struct  s_isprime {
    float       prob_requested;
}               t_isprime;

Mem_8bits   *isprime(t_isprime *isprime_data, Mem_8bits *input, Long_64bits *oByteSz);
Mem_8bits   *cmd_wrapper_isprime(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);

int         miller_rabin_primality_test(Long_64bits n, float p, int verbose);


/*
    genprime Data --------------------------------------
*/

typedef struct  s_genprime {
    Long_64bits min;
    Long_64bits max;
}               t_genprime;

Mem_8bits   *genprime(t_genprime *genprime_data, Long_64bits *oByteSz);
Mem_8bits   *cmd_wrapper_genprime(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);

Long_64bits prime_generator(Long_64bits min, Long_64bits max, int verbose);


/*
    RSA Data --------------------------------------
*/

# define        RSA_PRIVATE_KEY_HEADER          "-----BEGIN RSA PRIVATE KEY-----"
# define        RSA_PRIVATE_KEY_FOOTER          "-----END RSA PRIVATE KEY-----"
# define        RSA_PRIVATE_KEY_HEADER_byteSz   (sizeof(RSA_PRIVATE_KEY_HEADER) - 1)
# define        RSA_PRIVATE_KEY_FOOTER_byteSz   (sizeof(RSA_PRIVATE_KEY_FOOTER) - 1)
# define        RSA_PRIVATE_KEY_BANDS_byteSz    (RSA_PRIVATE_KEY_HEADER_byteSz + RSA_PRIVATE_KEY_FOOTER_byteSz)

# define        RSA_PUBLIC_KEY_HEADER           "-----BEGIN PUBLIC KEY-----"
# define        RSA_PUBLIC_KEY_FOOTER           "-----END PUBLIC KEY-----"
# define        RSA_PUBLIC_KEY_HEADER_byteSz    (sizeof(RSA_PUBLIC_KEY_HEADER) - 1)
# define        RSA_PUBLIC_KEY_FOOTER_byteSz    (sizeof(RSA_PUBLIC_KEY_FOOTER) - 1)
# define        RSA_PUBLIC_KEY_BANDS_byteSz     (RSA_PUBLIC_KEY_HEADER_byteSz + RSA_PUBLIC_KEY_FOOTER_byteSz)

# define        RSA_ENC_EXP                     ((1UL << 16) + 1)    // Arbitrary prime number, high chances to be coprime with Euler / Carmichael exp, choosen in every RSA cryptosystems

typedef enum    rsa_form
{
    PEM=1<<1,   // Privacy Enhanced Mail (PEM) is a Base64 encoded Distinguished Encoding Rules(DER)
    DER=1<<2,
}               e_rsa_form;

//  RFC 3447: ASN.1 type RSAPrivateKey structure
typedef struct  s_rsa_private_key
{
    Long_64bits version;           // Two primes: 0 / Multi primes: 1
    Long_64bits modulus;           // n = p * q
    Long_64bits enc_exp;           // Public exponent e (Default as 1 << 15 + 1 for faster modular exponentiation (Only 2 bits))
    Long_64bits dec_exp;           // Private exponent d (Modular multiplicative inverse of rsa encryption exponent and Euler fonction)
    Long_64bits p;                 // prime1
    Long_64bits q;                 // prime2
    Long_64bits crt_dmp1;        // Chinese remainder theorem pre-computed exponent: d mod (p-1)
    Long_64bits crt_dmq1;        // Chinese remainder theorem pre-computed exponent: d mod (q-1)
    Long_64bits crt_iqmp;        // Chinese remainder theorem pre-computed exponent: (inverse of q) mod p
}               t_rsa_private_key;
typedef struct  s_rsa_private_key_bigint
{
    Mem_8bits   *version;           // Two primes: 0 / Multi primes: 1
    Mem_8bits   *modulus;           // n = p * q
    Mem_8bits   *enc_exp;           // Public exponent e (Default as 1 << 15 + 1 for faster modular exponentiation (Only 2 bits))
    Mem_8bits   *dec_exp;           // Private exponent d (Modular multiplicative inverse of rsa encryption exponent and Euler fonction)
    Mem_8bits   *p;                 // prime1
    Mem_8bits   *q;                 // prime2
    Mem_8bits   *crt_dmp1;        // Chinese remainder theorem pre-computed exponent: d mod (p-1)
    Mem_8bits   *crt_dmq1;        // Chinese remainder theorem pre-computed exponent: d mod (q-1)
    Mem_8bits   *crt_iqmp;        // Chinese remainder theorem pre-computed exponent: (inverse of q) mod p
}               t_rsa_private_key_bigint;
typedef struct  s_rsa_private_key_bigint_byteSz
{
    int         version_byteSz;
    int         modulus_byteSz;
    int         enc_exp_byteSz;
    int         dec_exp_byteSz;
    int         p_byteSz;
    int         q_byteSz;
    int         crt_dmp1_byteSz;
    int         crt_dmq1_byteSz;
    int         crt_iqmp_byteSz;
}               t_rsa_private_key_bigint_byteSz;
# define        RSA_PRIVATE_KEY_INTEGERS_COUNT  (sizeof(t_rsa_private_key) / LONG64_byteSz)

//  RFC 3447: ASN.1 type RSAPublicKey structure
typedef struct  s_rsa_public_key
{
    Long_64bits modulus;    // n = p * q
    Long_64bits enc_exp;    // Public exponent e (Default as 1 << 15 + 1 for faster modular exponentiation (Only 2 bits))
}               t_rsa_public_key;
typedef struct  s_rsa_public_key_bigint
{
    Mem_8bits   *modulus;    // n = p * q
    Mem_8bits   *enc_exp;    // Public exponent e (Default as 1 << 15 + 1 for faster modular exponentiation (Only 2 bits))
}               t_rsa_public_key_bigint;
# define        RSA_PUBLIC_KEY_INTEGERS_COUNT   (sizeof(t_rsa_public_key) / LONG64_byteSz)

typedef struct  s_rsa
{
    Mem_8bits               *keyfile_data;      // Keyfile content
    int                     keyfile_byteSz;
    Mem_8bits               *der_content;       // Mem malloc of der key
    int                     der_content_byteSz;
    e_rsa_form              inform;
    e_rsa_form              outform;
    t_rsa_private_key       privkey;
    t_rsa_public_key        pubkey;
    t_rsa_private_key_bigint        privkey_bigint;
    t_rsa_public_key_bigint         pubkey_bigint;
    t_rsa_private_key_bigint_byteSz privkey_bigint_byteSz;
}               t_rsa;

Mem_8bits   *genrsa(t_rsa *rsa_data, Long_64bits *oByteSz, e_flags flags);
Mem_8bits   *rsa(t_rsa *rsa_data, Mem_8bits *key, Long_64bits keyByteSz, Long_64bits *oByteSz, e_flags flags);
Mem_8bits   *rsautl(t_rsa *rsa_data, Long_64bits input, Long_64bits *oByteSz, e_flags flags);

Mem_8bits   *cmd_wrapper_genrsa(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);
Mem_8bits   *cmd_wrapper_rsa(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);
Mem_8bits   *cmd_wrapper_rsautl(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags);

void        print_component(char *msg, Long_64bits n);
void        rsa_keys_generation(t_rsa *rsa);
void        rsa_parse_key(t_rsa *rsa, e_flags flags);
Long_64bits rsa_encryption(t_rsa_public_key *pubkey, Long_64bits m);
Long_64bits rsa_decryption(t_rsa_private_key *privkey, Long_64bits ciphertext);
int         rsa_consistency_pubkey(t_rsa_public_key *pubkey);
int         rsa_consistency_privkey(t_rsa_private_key *privkey);

Mem_8bits   *DER_generate_public_key_bigint(Mem_8bits *modulus, int modulus_byteSz, Mem_8bits *enc_exp, int enc_exp_byteSz, int *hashByteSz);
Mem_8bits   *rsa_PEM_keys_parsing(t_rsa *rsa, Mem_8bits *file_content, int *fileSz, e_flags keyflags);
Mem_8bits   *rsa_DER_keys_parsing(t_rsa *rsa, Mem_8bits *file_content, int fileSz, e_flags keyflag);

/*
    DER format Data --------------------------------------
*/

// Identifier for RSA encryption for use with Public Key Cryptosystem
# define    DER_OID_SEQUENCE_bytes          "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00"
# define    DER_OID_SEQUENCE_bytes_byteSz   (sizeof(DER_OID_SEQUENCE_bytes) - 1)
# define    DER_OID_SEQUENCE_length         (sizeof(DER_OID_SEQUENCE_bytes) - 3)

typedef enum    der_tag
{
    der_integer=0x02,
    der_bitstring=0x03,
    der_null=0x05,
    der_OID=0x06,
    der_sequence=0x30,
}               e_der_tag;
# define    DER_TAGS_TO_READ    (der_bitstring + der_null + der_sequence)
# define    DER_TAGS_TO_SKIP    (der_OID)

typedef struct  s_dertag
{
    Mem_8bits   tag_number;             // Tag type
    int         length_octets_number;   // Count of length number
    int         header_length;          // Main header length
    int         content_length;
    int         total_length;
}               t_dertag;

Mem_8bits           *DER_generate_public_key(t_rsa_public_key *pubkey, int *hashByteSz);
Mem_8bits           *DER_generate_private_key(t_rsa_private_key *privkey, int *hashByteSz);


/*
    ----------------------------------------------------
    MAIN structure
    ----------------------------------------------------
*/

typedef struct  s_ssl
{
    t_command       dec_i_cmd;
    t_command       command;
    t_command       enc_o_cmd;

    t_des           des_flagsdata;
    Mem_8bits       *passin;
    Mem_8bits       *passout;

    e_flags         flags;

    t_hash      *hash;
    char        *output_file;
    int         fd_out;
    
    char        *ulrandom_path;
    int         ulrandom_fd;
}               t_ssl;

extern t_ssl    ssl;

void    init_t_hash(t_hash *hash);
void    t_hash_free(t_hash *hash);
void    t_hash_list_free(t_hash *hash);
void    t_hash_decode_inputs(t_hash *hash);
void    t_hash_encode_output(t_hash *hash);
void    t_hash_hashing(t_hash *hash);
void    t_hash_output(t_hash *hash);

#endif
