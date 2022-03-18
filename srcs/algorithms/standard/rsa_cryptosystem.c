#include "ft_ssl.h"

inline void         print_component(char *msg, Long_64bits n)
{
    ft_putstr(msg);
    ft_putnbr(n);
    ft_putstr(" (0x");
    _ft_printHex(n, LONG64_byteSz, HEXABASE_low, 0);
    ft_putstr(")\n");
}

void                rsa_keys_generation(t_rsa *rsa)
{
    /*
        For security purposes :
            - p and q should be big primes and similar in magnitude but differ in length by a few digits to make factoring harder.
                p and q should be large primes (2^9 < p < (2^31 | 2^30))
                |p - q| should be large
                e coprime to euler
    */
    rsa->privkey.version = 0;   // Two primes: 0 / Multi primes: 1

    if (!rsa->privkey.p)
        rsa->privkey.p = prime_generator(1UL<<10, 1UL<<32, 1);
    while (!rsa->privkey.q || ulmult_overflow(rsa->privkey.p, rsa->privkey.q))
        rsa->privkey.q = prime_generator(1UL<<10, 1UL<<32, 1);

    rsa->privkey.modulus = rsa->privkey.p * rsa->privkey.q;

    if (ulmult_overflow(rsa->privkey.p, rsa->privkey.q))
        ft_ssl_error("genrsa p and q primes multiplication OVERFLOW.\n");

    Long_64bits euler_f = (rsa->privkey.p - 1) * (rsa->privkey.q - 1);

    // Choose e value that satisfy conditions
    if (!rsa->privkey.enc_exp)
        rsa->privkey.enc_exp = RSA_ENC_EXP;
    while (rsa->privkey.enc_exp >= euler_f || gcd(rsa->privkey.enc_exp, euler_f) != 1)
    {
        // Only 2 bits for faster modular exponentiations
        rsa->privkey.enc_exp = rsa->privkey.enc_exp == 2 ? 1 : (rsa->privkey.enc_exp >> 1) + 1;
    }

    rsa->privkey.dec_exp = mod_mult_inverse(rsa->privkey.enc_exp, euler_f);

    // Pre compute exposants for smarter encryption and decryption (Chinese remainder theorem)
    rsa->privkey.crt_dmp1 = rsa->privkey.dec_exp % (rsa->privkey.p - 1);
    rsa->privkey.crt_dmq1 = rsa->privkey.dec_exp % (rsa->privkey.q - 1);
    rsa->privkey.crt_iqmp = mod_mult_inverse(rsa->privkey.q, rsa->privkey.p);

    // Create public key with private key data
    rsa->pubkey.modulus = rsa->privkey.modulus;
    rsa->pubkey.enc_exp = rsa->privkey.enc_exp;
}

void                rsa_parse_key(t_rsa *rsa, e_flags flags)
{
    if (rsa->keyfile_data)
    {
        rsa->der_content_byteSz = rsa->keyfile_byteSz;
        if (rsa->inform == PEM)
            rsa->der_content = rsa_PEM_keys_parsing(rsa, rsa->keyfile_data, &rsa->der_content_byteSz, flags);
        else
            rsa->der_content = ft_memdup(rsa_DER_keys_parsing(rsa, rsa->keyfile_data, rsa->keyfile_byteSz, flags), rsa->keyfile_byteSz);
    }
    else
        ft_ssl_error("RSA cryptosystem: No keyfile, parsing failed.\n");
}

inline Long_64bits  rsa_encryption(t_rsa_public_key *pubkey, Long_64bits m)
{
    if (m >= pubkey->modulus)
    {
        print_component("Plaintext: ", m);
        print_component("Modulus  : ", pubkey->modulus);
        ft_ssl_error("RSA cryptosystem: Encryption can't be made, plaintext > modulus.\n");
    }
    return modular_exp(m, pubkey->enc_exp, pubkey->modulus);
}

inline Long_64bits  rsa_decryption(t_rsa_private_key *privkey, Long_64bits c)
{
    if (c >= privkey->modulus)
    {
        print_component("Ciphertext: ", c);
        print_component("Modulus   : ", privkey->modulus);
        ft_ssl_error("RSA cryptosystem: Decryption can't be made: ciphertext > modulus.\n");
    }
    return modular_exp(c, privkey->dec_exp, privkey->modulus);
}

int                 rsa_consistency_pubkey(t_rsa_public_key *pubkey)
{
    if (!pubkey->enc_exp || !pubkey->modulus)
    {
        ft_putstr("RSA cryptosystem: a Public-Key component is equal to 0 !\n");
        return 0;
    }
    return 1;
}

int                 rsa_consistency_privkey(t_rsa_private_key *privkey)
{
    /*
        Return 1 if no error found. Same return and same test than openssl
    */
    int error = 0;

    if (!privkey->p || !privkey->q || !privkey->modulus ||\
        !privkey->enc_exp || !privkey->dec_exp ||\
        !privkey->crt_dmp1 || !privkey->crt_dmq1 || !privkey->crt_iqmp)
        ft_putstr("RSA key error: a Private-Key component is equal to 0 !\n"), error = 1;
    if (!privkey->p || !miller_rabin_primality_test(privkey->p, -1, 0))
        ft_putstr("RSA key error: p not prime\n"), error = 1;
    if (!privkey->q || !miller_rabin_primality_test(privkey->q, -1, 0))
        ft_putstr("RSA key error: q not prime\n"), error = 1;
    if (!privkey->modulus || privkey->modulus != privkey->p * privkey->q)
        ft_putstr("RSA key error: n does not equal p q\n"), error = 1;
    if (!privkey->enc_exp || !privkey->dec_exp || modular_mult(privkey->dec_exp, privkey->enc_exp, (privkey->p - 1) * (privkey->q - 1)) != 1)
        ft_putstr("RSA key error: d e not conguent to 1\n"), error = 1;    
    if (!privkey->crt_dmp1 || privkey->crt_dmp1 != privkey->dec_exp % (privkey->p - 1))
        ft_putstr("RSA key error: dmp1 not conguent to d\n"), error = 1;
    if (!privkey->crt_dmq1 || privkey->crt_dmq1 != privkey->dec_exp % (privkey->q - 1))
        ft_putstr("RSA key error: dmq1 not conguent to d\n"), error = 1;
    if (!privkey->crt_iqmp || privkey->crt_iqmp != mod_mult_inverse(privkey->q, privkey->p))
        ft_putstr("RSA key error: iqmp not inverse of q\n"), error = 1;
    return error == 0;
}   
