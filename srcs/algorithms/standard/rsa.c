#include "ft_ssl.h"

static inline int           rsa_public_key_header(char *file_content, Long_64bits fileSz)
{
    return (fileSz < RSA_PUBLIC_HEADER_byteSz ||\
        ft_strncmp(file_content, RSA_PUBLIC_HEADER, RSA_PUBLIC_HEADER_byteSz)) ?\
        1 : 0;
}
static inline int           rsa_public_key_footer(char *file_content, Long_64bits fileSz)
{
    return (fileSz < RSA_PUBLIC_FOOTER_byteSz ||\
        ft_strncmp(file_content, RSA_PUBLIC_FOOTER, RSA_PUBLIC_FOOTER_byteSz)) ?\
        1 : 0;
}

static inline int           rsa_private_key_header(char *file_content, Long_64bits fileSz)
{
    return (fileSz < RSA_PRIVATE_HEADER_byteSz ||\
        ft_strncmp(file_content, RSA_PRIVATE_HEADER, RSA_PRIVATE_HEADER_byteSz)) ?\
        1 : 0;
}
static inline int           rsa_private_key_footer(char *file_content, Long_64bits fileSz)
{
    return (fileSz < RSA_PRIVATE_FOOTER_byteSz ||\
        ft_strncmp(file_content, RSA_PRIVATE_FOOTER, RSA_PRIVATE_FOOTER_byteSz)) ?\
        1 : 0;
}

static inline Key_64bits    parse_keys_rsa(char *file_content, Long_64bits fileSz, e_flags flags)
{
    int header_error = flags & pubin ?\
        rsa_public_key_header(file_content, fileSz) :\
        rsa_private_key_header(file_content, fileSz);
    
    int footer_error = flags & pubin ?\
        rsa_public_key_footer(file_content, fileSz) :\
        rsa_private_key_footer(file_content, fileSz);

    printf("header: %d\n", header_error);
    printf("footer: %d\n", footer_error);
    return header_error + footer_error;
    // return flags & pubin ?\
    //     rsa_public_key_header(file_content, fileSz) + rsa_public_key_footer(file_content, fileSz) :\
    //     rsa_private_key_header(file_content, fileSz) + rsa_private_key_footer(file_content, fileSz);
}

Mem_8bits   *rsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    t_rsa   *rsa_data = (t_rsa *)command_data;

    if (!rsa_data->inform)
        rsa_data->inform = PEM;
    if (!rsa_data->outform)
        rsa_data->outform = PEM;

    printf("rsa_data->check: %ld\n", check & way);
    printf("rsa_data->inform: %d\n", rsa_data->inform);
    printf("rsa_data->outform: %d\n", rsa_data->outform);
    
    parse_keys_rsa(*plaintext, ptByteSz, way);

    if (~way & noout)
    {
        ft_putstderr("writing RSA key\n");
        ft_putstderr(*plaintext);
    }

    exit(0);
    (void)plaintext;
    (void)command_data;
    (void)ptByteSz;
    (void)hashByteSz;
    (void)way;
    return NULL;
}
