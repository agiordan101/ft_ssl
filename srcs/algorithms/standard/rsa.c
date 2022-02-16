#include "ft_ssl.h"

/*
    Key parsing ---------------------------------------
*/

static inline void  PEM_public_key(t_rsa_public_key *key, char *file_content, Long_64bits fileSz)
{
    char    data[RSA_PUBLIC_KEY_DATA_byteSz];
    ft_memcpy(
        key,\
        file_content + RSA_PUBLIC_KEY_HEADER_byteSz + 1,\
        fileSz - RSA_PUBLIC_KEY_HEADER_byteSz - RSA_PUBLIC_KEY_FOOTER_byteSz
    );
    printf("PEM_public_key: >%s<\n", data);
}

static inline void  PEM_private_key(t_rsa_public_key *key, char *file_content, Long_64bits fileSz)
{
    char    data[RSA_PRIVATE_KEY_DATA_byteSz];
    ft_memcpy(
        key,\
        file_content + RSA_PRIVATE_KEY_HEADER_byteSz + 1,\
        fileSz - RSA_PRIVATE_KEY_HEADER_byteSz - RSA_PRIVATE_KEY_FOOTER_byteSz
    );
    printf("PEM_private_key: >%s<\n", data);
}

/*
    PEM parsing ---------------------------------------
*/

static inline int   PEM_public_key_header(char *file_content, Long_64bits fileSz)
{
    return (fileSz < RSA_PUBLIC_KEY_HEADER_byteSz ||\
        ft_strncmp(file_content, RSA_PUBLIC_KEY_HEADER, RSA_PUBLIC_KEY_HEADER_byteSz)) ?\
        1 : 0;
}
static inline int   PEM_public_key_footer(char *file_content, Long_64bits fileSz)
{
    /*
        Decremente 2 times the length to get last non whitespace char (skip ending '\n')
        Search the beginning of the last line
        Compare with footer
    */
    if (fileSz-- < RSA_PUBLIC_KEY_FOOTER_byteSz)
        return 1;
    while (--fileSz >= 0 && file_content[fileSz] != '\n')
        ;
    return (fileSz < 0 || ft_strncmp(file_content + fileSz + 1, RSA_PUBLIC_KEY_FOOTER, RSA_PUBLIC_KEY_FOOTER_byteSz)) ?\
        1 : 0;
}
static inline int   PEM_private_key_header(char *file_content, Long_64bits fileSz)
{
    return (fileSz < RSA_PRIVATE_KEY_HEADER_byteSz ||\
        ft_strncmp(file_content, RSA_PRIVATE_KEY_HEADER, RSA_PRIVATE_KEY_HEADER_byteSz)) ?\
        1 : 0;
}
static inline int   PEM_private_key_footer(char *file_content, Long_64bits fileSz)
{
    if (fileSz-- < RSA_PRIVATE_KEY_FOOTER_byteSz)
        return 1;
    while (--fileSz >= 0 && file_content[fileSz] != '\n')
        ;
    return (fileSz < 0 || ft_strncmp(file_content + fileSz + 1, RSA_PRIVATE_KEY_FOOTER, RSA_PRIVATE_KEY_FOOTER_byteSz)) ?\
        1 : 0;
}
static inline void  rsa_PEM_keys_parsing(t_rsa *rsa, char *file_content, Long_64bits fileSz, e_flags flags)
{
    if (flags & pubin)
    {
        if (PEM_public_key_header(file_content, fileSz))
            printf("./ft_ssl: rsa: Unable to load PUBLIC key in PEM format: bad header\n");
        else if (PEM_public_key_footer(file_content, fileSz))
            printf("./ft_ssl: rsa: Unable to load PUBLIC key in PEM format: bad footer\n");
        else
        {
            PEM_public_key(&rsa->keys.pubkey, file_content, fileSz);
            return ;
        }
    }
    else
    {
        if (PEM_private_key_header(file_content, fileSz))
            printf("./ft_ssl: rsa: Unable to load PRIVATE key in PEM format: bad header\n");
        else if (PEM_private_key_footer(file_content, fileSz))
            printf("./ft_ssl: rsa: Unable to load PRIVATE key in PEM format: bad footer\n");
        else
            return ;
    }
    freexit(EXIT_SUCCESS);
}

/*
    RSA ----------------------------------------------
*/

Mem_8bits           *rsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags flags)
{
    /*
    to do
        check
        text
        modulus
    */
    t_rsa   *rsa_data = (t_rsa *)command_data;

    if (!rsa_data->inform)
        rsa_data->inform = PEM;
    if (!rsa_data->outform)
        rsa_data->outform = PEM;

    printf("rsa_data->check: %ld\n", check & flags);
    printf("rsa_data->inform: %d\n", rsa_data->inform);
    printf("rsa_data->outform: %d\n", rsa_data->outform);

    if (rsa_data->inform == PEM)
        rsa_PEM_keys_parsing(rsa_data, *plaintext, ptByteSz, flags);

    if (~flags & noout)
    {
        ft_putstderr("writing RSA key\n");
        ft_putstderr(*plaintext);
    }

    exit(0);
    (void)hashByteSz;
    return NULL;
}
