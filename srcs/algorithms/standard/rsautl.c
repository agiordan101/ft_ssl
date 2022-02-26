# include "ft_ssl.h"

Mem_8bits           *rsautl(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags flags)
{
    /*
        Nobody chain rsa encryption. Prefer encryption with AES/DES and AES/DES key encrypted with RSA
    */
    t_rsa       *rsa = (t_rsa *)command_data;
    Long_64bits ciphertext;
    int         _hashByteSz;

    rsa_parse_key(rsa, flags);
    if (flags & e)
    {
        if (!rsa_consistency_pubkey(&rsa->pubkey))
        {
            ft_putstr("./ft_ssl: RSA encryption: RSA Public-Key provided is not valid.");
            freexit(EXIT_SUCCESS);
        }
        ciphertext = rsa_encryption(&rsa->pubkey, *((Long_64bits *)*plaintext));
    }
    else
    {
        if (!rsa_consistency_privkey(&rsa->privkey))
        {
            ft_putstr("./ft_ssl: RSA decryption: RSA Private-Key provided is not valid.");
            freexit(EXIT_SUCCESS);
        }
        ciphertext = rsa_decryption(&rsa->privkey, *((Long_64bits *)*plaintext));
    }

    _hashByteSz = count_bytes(ciphertext);
    if (hashByteSz)
        *hashByteSz = _hashByteSz;
    return ft_memdup(&ciphertext, _hashByteSz);
}
