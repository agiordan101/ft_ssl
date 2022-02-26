#include "ft_ssl.h"

/*

    When encrypting with low encryption exponents (e.g., e = 3)
     and small values of the m (i.e., m < n1/e),
     the result of me is strictly less than the modulus n.
     In this case, ciphertexts can be decrypted easily by taking the eth root of the ciphertext over the integers.

*/

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
    if (!rsa->privkey.q)
        rsa->privkey.q = prime_generator(1UL<<10, 1UL<<31, 1);

    rsa->privkey.modulus = rsa->privkey.p * rsa->privkey.q;

    if (ulmult_overflow(rsa->privkey.p, rsa->privkey.q))
    {
        printf("genrsa p and q primes multiplication OVERFLOW\n");
        exit(0);
    }

    Long_64bits euler_f = (rsa->privkey.p - 1) * (rsa->privkey.q - 1);

    // Choose e value that satisfy conditions
    if (!rsa->privkey.enc_exp)
        rsa->privkey.enc_exp = RSA_ENC_EXP;
    while (rsa->privkey.enc_exp >= euler_f || gcd(rsa->privkey.enc_exp, euler_f) != 1)
    {
        // Only 2 bits for faster modular exponentiations
        rsa->privkey.enc_exp = rsa->privkey.enc_exp == 2 ? 1 : (rsa->privkey.enc_exp >> 1) + 1;
        // printf("RSA_ENC_EXP > euler_f or PGCD != 1, new e: %lu\n", rsa->privkey.enc_exp);
    }

    rsa->privkey.dec_exp = mod_mult_inverse(rsa->privkey.enc_exp, euler_f);

    // Pre compute exposants for smarter encryption and decryption (Chinese remainder theorem)
    rsa->privkey.crt_exp_dp = rsa->privkey.dec_exp % (rsa->privkey.p - 1);
    rsa->privkey.crt_exp_dq = rsa->privkey.dec_exp % (rsa->privkey.q - 1);
    rsa->privkey.crt_exp_qinv = mod_mult_inverse(rsa->privkey.q, rsa->privkey.p);

    // Create public key with private key data
    rsa->pubkey.modulus = rsa->privkey.modulus;
    rsa->pubkey.enc_exp = rsa->privkey.enc_exp;

    // printf("rsa->privkey.p : %lu\n", rsa->privkey.p);
    // printf("rsa->privkey.q : %lu\n", rsa->privkey.q);
    // printf("rsa->n : %lu\n", rsa->privkey.modulus);
    // printf("euler_f : %lu\n", euler_f);
    // printf("rsa->privkey.enc_exp : %lu\n", rsa->privkey.enc_exp);
    // printf("rsa->privkey.dec_exp : %lu\n\n", rsa->privkey.dec_exp);
}

inline Long_64bits  rsa_encryption(t_rsa_public_key *pubkey, Long_64bits m)
{
    if (m >= pubkey->modulus)
    {
        printf("Encryption can't be made, plaintext > modulus\n");
        return 0;
    }
    return modular_exp(m, pubkey->enc_exp, pubkey->modulus);
}

inline Long_64bits  rsa_decryption(t_rsa_private_key *privkey, Long_64bits ciphertext)
{
    return modular_exp(ciphertext, privkey->dec_exp, privkey->modulus);
}

int                 rsa_consistency(t_rsa_private_key *privkey)
{
    /*
        Return 1 if no error found. Same return and same test than openssl
    */
    int error = 0;

    if (!miller_rabin_primality_test(privkey->p, -1, 0))
        ft_putstr("RSA key error: p not prime\n"), error = 1;
    if (!miller_rabin_primality_test(privkey->q, -1, 0))
        ft_putstr("RSA key error: q not prime\n"), error = 1;
    if (privkey->modulus != privkey->p * privkey->q)
        ft_putstr("RSA key error: n does not equal p q\n"), error = 1;
    if (modular_mult(privkey->dec_exp, privkey->enc_exp, (privkey->p - 1) * (privkey->q - 1)) != 1)
        ft_putstr("RSA key error: d e not conguent to 1\n"), error = 1;    
    if (privkey->crt_exp_dp != privkey->dec_exp % (privkey->p - 1))
        ft_putstr("RSA key error: dmp1 not conguent to d\n"), error = 1;
    if (privkey->crt_exp_dq != privkey->dec_exp % (privkey->q - 1))
        ft_putstr("RSA key error: dmq1 not conguent to d\n"), error = 1;
    if (privkey->crt_exp_qinv != mod_mult_inverse(privkey->q, privkey->p))
        ft_putstr("RSA key error: iqmp not inverse of q\n"), error = 1;
    return error == 0;
}   

// Padding ?????????????????????????????????
