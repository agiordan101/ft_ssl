#include "ft_ssl.h"

Mem_8bits   *genrsa(t_rsa *rsa_data, Long_64bits *oByteSz, e_flags flags)
{
    Mem_8bits   *key;
    Mem_8bits   *tmp_key;

    if (!rsa_data->outform)
        rsa_data->outform = PEM;

    ft_putstderr("Generating RSA private key, 64 bit long modulus (2 primes)\n");

    rsa_keys_generation(rsa_data);

    int fd_save = ssl.fd_out;
    ssl.fd_out = STDERR;
    print_component("e is ", rsa_data->pubkey.enc_exp);
    ssl.fd_out = fd_save;

    if (flags & pubout)
        key = DER_generate_public_key(&rsa_data->pubkey, (int *)oByteSz);
    else
        key = DER_generate_private_key(&rsa_data->privkey, (int *)oByteSz);
    
    // Add base64 encryption after genrsa command for PEM form
    if (rsa_data->outform == PEM && ~ssl.flags & encout)
    {
        ssl.flags += encout;
        command_handler(&ssl.enc_o_cmd, "base64", 0);
    }

    return key;
}

Mem_8bits   *cmd_wrapper_genrsa(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags)
{
    (void)input;
    (void)iByteSz;
    return genrsa((t_rsa *)cmd_data, oByteSz, flags);
}
