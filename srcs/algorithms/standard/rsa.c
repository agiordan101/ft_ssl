#include "ft_ssl.h"

/*
    -inform PEM
    -outform PEM
    -passin arg // 2 passwords ?..
    -passout arg
    -text
    -noout
    -modulus
    -check
    -pubin
    -pubout
*/

Mem_8bits   *rsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    t_rsa   *rsa_data = (t_rsa *)command_data;

    if (!rsa_data->inform)
        rsa_data->inform = PEM;
    if (!rsa_data->outform)
        rsa_data->outform = PEM;
    printf("rsa_data->check: %d\n", rsa_data->check);
    printf("rsa_data->inform: %d\n", rsa_data->inform);
    printf("rsa_data->outform: %d\n", rsa_data->outform);
    exit(0);
    (void)plaintext;
    (void)command_data;
    (void)ptByteSz;
    (void)hashByteSz;
    (void)way;
    return NULL;
}
