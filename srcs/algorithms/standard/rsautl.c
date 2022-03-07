# include "ft_ssl.h"

Mem_8bits           *rsautl(t_rsa *rsa_data, Long_64bits input, Long_64bits *oByteSz, e_flags flags)
{
    /*
        Nobody chain rsa encryption. Prefer encryption with AES/DES and AES/DES key encrypted with RSA
    */
    Long_64bits output;
    int         _hashByteSz;

    if (~flags & inkey)
        ft_ssl_error("No keyfile specified.\n");

    rsa_parse_key(rsa_data, flags);
    if (flags & e)
    {
        if (!rsa_consistency_pubkey(&rsa_data->pubkey))
            ft_ssl_error("encryption: RSA Public-Key provided is not valid.\n");

        output = rsa_encryption(&rsa_data->pubkey, input);
    }
    else
    {
        if (!rsa_consistency_privkey(&rsa_data->privkey))
            ft_ssl_error("decryption: RSA Private-Key provided is not valid.\n");

        output = rsa_decryption(&rsa_data->privkey, input);
    }

    _hashByteSz = count_bytes(output);
    if (oByteSz)
        *oByteSz = _hashByteSz;
    return ft_memdup(&output, _hashByteSz);
}

Mem_8bits   *cmd_wrapper_rsautl(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags)
{
    (void)iByteSz;
    return rsautl((t_rsa *)cmd_data, *((Long_64bits *)*input), oByteSz, flags);
}
