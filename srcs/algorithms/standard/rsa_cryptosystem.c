#include "ft_ssl.h"

/*

    When encrypting with low encryption exponents (e.g., e = 3)
     and small values of the m (i.e., m < n1/e),
     the result of me is strictly less than the modulus n.
     In this case, ciphertexts can be decrypted easily by taking the eth root of the ciphertext over the integers.

*/

void        rsa_keys_generation(t_rsa_keys *rsa)
{
    /*
        For security purposes :
            - p and q should be big primes and similar in magnitude but differ in length by a few digits to make factoring harder.
                p and q should be large primes (2^9 < p < (2^31 | 2^30))
                |p - q| should be large
                p - 1 and q - 1 should not be P-smooth
                p + 1 and q + 1 should have at least one big prime factor.
                e coprime to euler
                d > (1/3)(n ^ (1/4))
                e
    */
    if (!rsa->p)
        rsa->p = prime_generator(1UL<<10, 1UL<<32, 1);
    if (!rsa->q)
        rsa->q = prime_generator(1UL<<10, 1UL<<31, 1);

    rsa->privkey.modulus = rsa->p * rsa->q;
    rsa->pubkey.modulus = rsa->privkey.modulus;

    if (ulmult_overflow(rsa->p, rsa->q))
    {
        printf("genrsa p and q primes multiplication OVERFLOW\n");
        exit(0);
    }

    Long_64bits euler_f = (rsa->p - 1) * (rsa->q - 1);

    // Choose e value that satisfy conditions
    if (!rsa->pubkey.enc_exp)
        rsa->pubkey.enc_exp = RSA_ENC_EXP;
    while (rsa->pubkey.enc_exp >= euler_f || gcd(rsa->pubkey.enc_exp, euler_f) != 1)
    {
        // Only 2 bits for faster modular exponentiations
        rsa->pubkey.enc_exp = rsa->pubkey.enc_exp == 2 ? 1 : (rsa->pubkey.enc_exp >> 1) + 1;
        // printf("RSA_ENC_EXP > euler_f or PGCD != 1, new e: %lu\n", rsa->pubkey.enc_exp);
    }

    // porbleme from mod_mult_inverse
    rsa->privkey.dec_exp = mod_mult_inverse(rsa->pubkey.enc_exp, euler_f);
    // printf("rsa->p : %lu\n", rsa->p);
    // printf("rsa->q : %lu\n", rsa->q);
    // printf("rsa->n : %lu\n", rsa->privkey.modulus);
    // printf("euler_f : %lu\n", euler_f);
    // printf("rsa->pubkey.enc_exp : %lu\n", rsa->pubkey.enc_exp);
    // printf("rsa->privkey.dec_exp : %lu\n\n", rsa->privkey.dec_exp);
}

inline Long_64bits rsa_encryption(t_rsa_public_key *pubkey, Long_64bits m)
{
    if (m >= pubkey->modulus)
    {
        printf("Encryption can't be made, plaintext > modulus\n");
        return 0;
    }
    return modular_exp(m, pubkey->enc_exp, pubkey->modulus);
}

inline Long_64bits rsa_decryption(t_rsa_private_key *privkey, Long_64bits ciphertext)
{
    return modular_exp(ciphertext, privkey->dec_exp, privkey->modulus);
}
