#include "ft_ssl.h"

/*
    PEM form parsing ---------------------------------------
*/

static inline int   PEM_public_key_header(char *file_content)
{
    return ft_strncmp(file_content, RSA_PUBLIC_KEY_HEADER, RSA_PUBLIC_KEY_HEADER_byteSz) ? 1 : 0;
}
static inline int   PEM_public_key_footer(char *file_content, int fileSz)
{
    while (--fileSz >= 0 && file_content[fileSz] <= '\n')
        ;   // Skip ending whitespace char
    while (--fileSz >= 0 && file_content[fileSz] != '\n')
        ;   // Search the beginning of the last line
    return (fileSz < 0 || ft_strncmp(file_content + fileSz + 1, RSA_PUBLIC_KEY_FOOTER, RSA_PUBLIC_KEY_FOOTER_byteSz)) ?\
        1 : 0;
}
static inline int   PEM_private_key_header(char *file_content)
{
    return ft_strncmp(file_content, RSA_PRIVATE_KEY_HEADER, RSA_PRIVATE_KEY_HEADER_byteSz) ? 1 : 0;
}
static inline int   PEM_private_key_footer(char *file_content, int fileSz)
{
    while (--fileSz >= 0 && file_content[fileSz] <= '\n')
        ;   // Skip ending whitespace char
    while (--fileSz >= 0 && file_content[fileSz] != '\n')
        ;   // Search the beginning of the last line
    return (fileSz < 0 || ft_strncmp(file_content + fileSz + 1, RSA_PRIVATE_KEY_FOOTER, RSA_PRIVATE_KEY_FOOTER_byteSz)) ?\
        1 : 0;
}

Mem_8bits           *rsa_PEM_keys_parsing(t_rsa *rsa, Mem_8bits *file_content, int *fileSz, e_flags keyflags)
{
    int     der_contentSz = *fileSz;

    if (keyflags & pubin)
    {
        if (PEM_public_key_header(file_content))
            rsa_parsing_keys_error(pubin, PEM, "bad header", -1);
        else if (PEM_public_key_footer(file_content, *fileSz))
            rsa_parsing_keys_error(pubin, PEM, "bad footer", -1);
        else
        {
            file_content += RSA_PUBLIC_KEY_HEADER_byteSz;
            der_contentSz -= RSA_PUBLIC_KEY_BANDS_byteSz;
        }
    }
    else
    {
        if (PEM_private_key_header(file_content))
            rsa_parsing_keys_error(0, PEM, "bad header", -1);
        else if (PEM_private_key_footer(file_content, *fileSz))
            rsa_parsing_keys_error(0, PEM, "bad footer", -1);
        else
        {
            file_content += RSA_PRIVATE_KEY_HEADER_byteSz;
            der_contentSz -= RSA_PRIVATE_KEY_BANDS_byteSz;
        }
    }
    Mem_8bits *der_content = base64(file_content, der_contentSz, (Long_64bits *)fileSz, d);
    rsa_DER_keys_parsing(rsa, der_content, *fileSz, keyflags);
    return der_content;
}
