#include "ft_ssl.h"

int         parse_private_key_header(char *firstline, char header[RSA_PRIVATE_HEADER_byteSz])
{

}

Key_64bits  parse_keys_rsa(t_rsa *rsa, char *content, e_flags flags)
{
    char    header[RSA_PRIVATE_HEADER_byteSz];
    char    footer[RSA_PRIVATE_HEADER_byteSz];

    if (flags & pubin)
    {
        ft_memcpy(header, RSA_PUBLIC_HEADER, RSA_PUBLIC_HEADER_byteSz);
        ft_memcpy(footer, RSA_PUBLIC_FOOTER, RSA_PUBLIC_FOOTER_byteSz);
    }
    else
    {
        ft_memcpy(header, RSA_PRIVATE_HEADER, RSA_PRIVATE_HEADER_byteSz);
        ft_memcpy(footer, RSA_PRIVATE_FOOTER, RSA_PRIVATE_FOOTER_byteSz);
    }

    // printf("header: %s\n", header);
    // printf("footer: %s\n", footer);
    return 0;
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
    
    parse_keys_rsa(rsa_data, *plaintext, way);

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
