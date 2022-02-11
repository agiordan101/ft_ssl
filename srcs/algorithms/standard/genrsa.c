#include "ft_ssl.h"

/*

    When encrypting with low encryption exponents (e.g., e = 3)
     and small values of the m (i.e., m < n1/e),
     the result of me is strictly less than the modulus n.
     In this case, ciphertexts can be decrypted easily by taking the eth root of the ciphertext over the integers.

*/

void        rsa_keys_generation(t_rsa *rsa)
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

Long_64bits rsa_encryption(t_rsa_public_key *pubkey, Long_64bits m)
{
    if (m >= pubkey->modulus)
    {
        printf("Encryption can't be made, plaintext > modulus\n");
        return 0;
    }
    return modular_exp(m, pubkey->enc_exp, pubkey->modulus);
}

Long_64bits rsa_decryption(t_rsa_private_key *privkey, Long_64bits ciphertext)
{
    return modular_exp(ciphertext, privkey->dec_exp, privkey->modulus);
}

static inline void  rsa_test()
{
    t_rsa       rsa;
    int         ntests = 3;
    Long_64bits ms[3] = {
        ulrandom_range(0, 1UL<<50),
        ulrandom_range(0, 1UL<<60),
        1456625892599655,
    };
    Long_64bits m;
    Long_64bits ciphertext;
    Long_64bits pt;
    int c = 0;
    int c_save;
    int tot = 10;

    for (int i = 0; i < tot; i++)
    {
        ft_bzero(&rsa, sizeof(t_rsa));
        rsa_keys_generation(&rsa);

        c_save = c;
        // m = 111111111111111111;
        for (int k = 0; k < ntests; k++)
        {
            m = ms[k];
            if (rsa.privkey.modulus % m == 0)
            {
                printf("rsa.privkey.modulus %% %lu == 0\n", m);
                exit(0);
            }
            // printf("rsa.privkey.modulus %% %lu = %lu\n", m, rsa.privkey.modulus % m);

            ciphertext = rsa_encryption(&rsa.pubkey, m);
            
            pt = rsa_decryption(&rsa.privkey, ciphertext);
            if (pt == 0)
            {
                c = c_save + ntests;
                break ;
            }
            else if (m == pt)
                c++;
            else
            {
                printf("Plaintext in : %lu\n", m);
                printf("Ciphertext   : %lu\n", ciphertext);
                printf("Plaintext out: %lu\n\n", pt);
                printBits(&m, LONG64_byteSz);
                printBits(&pt, LONG64_byteSz);
            }
            // printf("%lu^%lu mod %lu = %lu\n", m, rsa.pubkey.enc_exp, rsa.pubkey.modulus, ciphertext);
            // printf("%lu^%lu mod %lu = %lu\n", ciphertext, rsa.privkey.dec_exp, rsa.privkey.modulus, pt);
        }
        if (c - c_save == ntests)
        {
            printf("RSA encrypt/decrypt %d/%d sucess\n", i, ntests);
            c = c_save + 1;
        }
        else
        {
            printf("RSA encrypt/decrypt %d/%d failed\n", i, ntests);
            c = c_save;
        }
    }

    printf("\nRSA eval: %.1f%%\n", ((float)c / tot) * 100);
    // ciphertext = (Long_64bits)pow(m, rsa.pubkey.enc_exp) % rsa.pubkey.modulus;
    // pt = (Long_64bits)pow(ciphertext, rsa.privkey.dec_exp) % rsa.privkey.modulus;
    // printf("\n%lu^%lu mod %lu = %lu\n", m, rsa.pubkey.enc_exp, rsa.pubkey.modulus, ciphertext);
    // printf("%lu^%lu mod %lu = %lu\n", ciphertext, rsa.privkey.dec_exp, rsa.privkey.modulus, pt);


    exit(0);
}

Mem_8bits   *genrsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    t_rsa   rsa;
    ft_bzero(&rsa, sizeof(t_rsa));

    ft_putstderr("Generating RSA private key, 64-bits long modulus (2 primes)\n");

    rsa_keys_generation(&rsa);
    *hashByteSz = LONG64_byteSz;

    ft_putstderr("e is ");
    ft_putstderr(" (0x)\n")

    (void)plaintext;
    (void)ptByteSz;
    (void)way;
    return ft_memdup(&rsa.privkey.dec_exp, LONG64_byteSz);
}
