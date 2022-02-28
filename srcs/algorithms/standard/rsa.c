#include "ft_ssl.h"

static inline void  print_component(char *msg, Long_64bits n)
{
    ft_putstr(msg);
    ft_putnbr(n);
    ft_putstr(" (0x");
    _ft_printHex(n, LONG64_byteSz, HEXABASE_low, 0);
    ft_putstr(")\n");
}

static inline void  print_pubkey_components(t_rsa_public_key *pubkey)
{
    ft_putstr("RSA Public-Key: (");
    ft_putnbr(count_bits(pubkey->modulus));
    ft_putstr(" bit)\n");
    print_component("Modulus: ", pubkey->modulus);
    print_component("Exponent: ", pubkey->enc_exp);
}     

static inline void  print_privkey_components(t_rsa_private_key *privkey)
{
    Long_64bits integers[RSA_PRIVATE_KEY_INTEGERS_COUNT - 1] = {
        privkey->modulus, privkey->enc_exp, privkey->dec_exp,
        privkey->p, privkey->q,
        privkey->crt_dmp1, privkey->crt_dmq1, privkey->crt_iqmp
    };
    char        *int_title[RSA_PRIVATE_KEY_INTEGERS_COUNT - 1] = {
        "modulus: ", "publicExponent: ", "privateExponent: ",
        "prime1: ", "prime2: ",
        "exponent1: ", "exponent2: ", "coefficient: "
    };

    ft_putstr("RSA Private-Key: (");
    ft_putnbr(count_bits(privkey->modulus));
    ft_putstr(" bit, 2 primes)\n");
    for (int i = 0; i < RSA_PRIVATE_KEY_INTEGERS_COUNT - 1; i++)
        print_component(int_title[i], integers[i]);
}     

/*
    RSA ----------------------------------------------
*/

Mem_8bits           *rsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags flags)
{
    t_rsa       *rsa_data = (t_rsa *)command_data;
    rsa_data->keyfile_data = *plaintext;
    rsa_data->keyfile_byteSz = ptByteSz;

    rsa_parse_key(rsa_data, flags);

    if (flags & pubin)
    {
        if (flags & check)
            ft_ssl_error("Only private keys can be checked.\n");
        if (flags & text)
            print_pubkey_components(&rsa_data->pubkey);
        if (flags & modulus)
        {
            ft_putstr("Modulus=");
            _ft_printHex(rsa_data->pubkey.modulus, LONG64_byteSz, HEXABASE_upp, 0);
            ft_putstr("\n");
        }
    }
    else
    {
        if (flags & text)
            print_privkey_components(&rsa_data->privkey);
        if (flags & pubout)
        {
            // Generate public key if private was provided and public is asked
            rsa_data->pubkey.enc_exp = rsa_data->privkey.enc_exp;
            rsa_data->pubkey.modulus = rsa_data->privkey.modulus;
            free(rsa_data->der_content);
            rsa_data->der_content = DER_generate_public_key(&rsa_data->pubkey, &rsa_data->keyfile_byteSz);
        }
        if (flags & modulus)
        {
            ft_putstr("Modulus=");
            _ft_printHex(rsa_data->privkey.modulus, LONG64_byteSz, HEXABASE_upp, 0);
            ft_putstr("\n");
        }
        if (flags & check && rsa_consistency_privkey(&rsa_data->privkey))
            ft_putstr("RSA key ok\n");
    }

    // Add base64 encryption after rsa command to create PEM form
    if (rsa_data->outform == PEM && ~ssl.flags & encout)
    {
        ssl.flags += encout;
        command_handler(&ssl.enc_o_cmd, "base64", 0);
    }

    //printBits(rsa_data->der_content, *hashByteSz);

    // fprintf(stderr, "rsa_data->pubkey.modulus: %lu\n", rsa_data->pubkey.modulus);
    // fprintf(stderr, "rsa_data->pubkey.enc_exp: %lu\n", rsa_data->pubkey.enc_exp);
    
    // fprintf(stderr, "rsa_data->privkey.enc_exp: %lu\n", rsa_data->privkey.enc_exp);
    // fprintf(stderr, "rsa_data->privkey.dec_exp: %lu\n", rsa_data->privkey.dec_exp);
    // fprintf(stderr, "rsa_data->privkey.p: %lu\n", rsa_data->privkey.p);
    // fprintf(stderr, "rsa_data->privkey.q: %lu\n", rsa_data->privkey.q);
    // fprintf(stderr, "rsa_data->privkey.modulus: %lu\n", rsa_data->privkey.modulus);
    // fprintf(stderr, "rsa_data->privkey.crt_dmp1: %lu\n", rsa_data->privkey.crt_dmp1);
    // fprintf(stderr, "rsa_data->privkey.crt_dmq1: %lu\n", rsa_data->privkey.crt_dmq1);
    // fprintf(stderr, "rsa_data->privkey.crt_iqmp: %lu\n", rsa_data->privkey.crt_iqmp);
    if (hashByteSz)
        *hashByteSz = rsa_data->keyfile_byteSz;
    // fprintf(stderr, "*hashByteSz: %ld\n", *hashByteSz);
    // fprintf(stderr, "ptByteSz: %ld\n", ptByteSz);
    return rsa_data->der_content;
}
