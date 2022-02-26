#include "ft_ssl.h"

/*
    Convertion between PEM and DER form ---------------------------------------
*/

// static inline void  rsa_PEM_to_DER(char *file_content, Long_64bits fileSz)
// {

// }
    
// static inline void  rsa_DER_to_PEM()
// {
    //     // Add base64 encryption after rsa command to create PEM form
    // if (~ssl.flags & encout)
    // {
    //     ssl.flags += encout;
    //     command_handler(&ssl.enc_o_cmd, "base64", 0);
    // }

// }

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

    t_rsa       *rsa_data = (t_rsa *)command_data;
    Mem_8bits   *der_content;

    //printBits(*plaintext, ptByteSz);

    if (rsa_data->inform == PEM)
        der_content = rsa_PEM_keys_parsing(rsa_data, *plaintext, (int *)&ptByteSz, flags);
    else
    {
        rsa_DER_keys_parsing(rsa_data, *plaintext, ptByteSz, flags);
        der_content = ft_memdup(*plaintext, ptByteSz);
    }

    if (~flags & pubin && flags & pubout)
    {
        rsa_data->pubkey.enc_exp = rsa_data->privkey.enc_exp;
        rsa_data->pubkey.modulus = rsa_data->privkey.modulus;
        free(der_content);
        der_content = DER_generate_public_key(&rsa_data->pubkey, &ptByteSz);
    }

    if (hashByteSz)
        *hashByteSz = ptByteSz;

    // Add base64 encryption after rsa command to create PEM form
    if (rsa_data->outform == PEM && ~ssl.flags & encout)
    {
        ssl.flags += encout;
        command_handler(&ssl.enc_o_cmd, "base64", 0);
    }

    //printBits(der_content, *hashByteSz);

    // fprintf(stderr, "rsa_data->pubkey.modulus: %lu\n", rsa_data->pubkey.modulus);
    // fprintf(stderr, "rsa_data->pubkey.enc_exp: %lu\n", rsa_data->pubkey.enc_exp);
    
    // fprintf(stderr, "rsa_data->privkey.enc_exp: %lu\n", rsa_data->privkey.enc_exp);
    // fprintf(stderr, "rsa_data->privkey.dec_exp: %lu\n", rsa_data->privkey.dec_exp);
    // fprintf(stderr, "rsa_data->privkey.p: %lu\n", rsa_data->privkey.p);
    // fprintf(stderr, "rsa_data->privkey.q: %lu\n", rsa_data->privkey.q);
    // fprintf(stderr, "rsa_data->privkey.modulus: %lu\n", rsa_data->privkey.modulus);
    // fprintf(stderr, "rsa_data->privkey.crt_exp_dp: %lu\n", rsa_data->privkey.crt_exp_dp);
    // fprintf(stderr, "rsa_data->privkey.crt_exp_dq: %lu\n", rsa_data->privkey.crt_exp_dq);
    // fprintf(stderr, "rsa_data->privkey.crt_exp_qinv: %lu\n", rsa_data->privkey.crt_exp_qinv);
    return der_content;
}
