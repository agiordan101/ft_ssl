#include "ft_ssl.h"

Mem_8bits   *genrsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    t_rsa       *rsa_data = (t_rsa *)command_data;
    Mem_8bits   *key;
    Mem_8bits   *tmp_key;

    if (!rsa_data->outform)
        rsa_data->outform = PEM;

    ft_putstderr("Generating RSA private key, 64 bit long modulus (2 primes)\n");

    rsa_keys_generation(rsa_data);

    ft_putstderr("e is ");
    ft_putnbrfd(STDERR, rsa_data->pubkey.enc_exp);
    ft_putstderr("\n");

    // fprintf(stderr, "modulus: %lu\n", rsa_data->privkey.modulus);

    if (way & pubout)
        key = DER_generate_public_key(&rsa_data->pubkey, (int *)hashByteSz);
    else
        key = DER_generate_private_key(&rsa_data->privkey, (int *)hashByteSz);
    
    // Add base64 encryption after genrsa command for PEM form
    if (rsa_data->outform == PEM && ~ssl.flags & encout)
    {
        ssl.flags += encout;
        command_handler(&ssl.enc_o_cmd, "base64", 0);
    }

    (void **)plaintext;
    (void)ptByteSz;
    (void)way;
    return key;
}
