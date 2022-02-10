#include "ft_ssl.h"

void        rsa_generation(t_rsa *rsa, t_rsa_private_key *privkey, t_rsa_public_key *pubkey)
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
    rsa->p = prime_generator(1UL<<10, 1UL<<32);
    rsa->q = prime_generator(1UL<<10, 1UL<<31);
    // rsa->p = 1947594133;
    // rsa->q = 1515364031;
    
    // rsa->p = 3144460003;
    // rsa->q = 991189081;
    
    // rsa->p = 3;
    // rsa->q = 11;
    

    rsa->privkey.modulus = rsa->p * rsa->q;
    rsa->pubkey.modulus = rsa->privkey.modulus;

    if (ulmult_overflow(rsa->p, rsa->q))
    {
        printf("genrsa OVERFLOW\n");
        exit(0);
    }

    Long_64bits euler_f = (rsa->p - 1) * (rsa->q - 1);
    
    // Choose e value that satisfy conditions
    rsa->pubkey.enc_exp = RSA_ENC_EXP;
    while (rsa->pubkey.enc_exp >= euler_f || gcd(rsa->pubkey.enc_exp, euler_f) != 1)
    {
        // Only 2 bits for faster modular exponentiations
        rsa->pubkey.enc_exp = rsa->pubkey.enc_exp == 2 ? 1 : (rsa->pubkey.enc_exp >> 1) + 1;
        printf("RSA_ENC_EXP > euler_f or PGCD != 1, new e: %lu\n", rsa->pubkey.enc_exp);
    }

    // porbleme from mod_mult_inverse
    rsa->privkey.dec_exp = mod_mult_inverse(rsa->pubkey.enc_exp, euler_f);
    printf("rsa->p : %lu\n", rsa->p);
    printf("rsa->q : %lu\n", rsa->q);
    printf("rsa->n : %lu\n", rsa->privkey.modulus);
    printf("euler_f : %lu\n", euler_f);
    printf("rsa->pubkey.enc_exp : %lu\n", rsa->pubkey.enc_exp);
    printf("rsa->privkey.dec_exp : %lu\n", rsa->privkey.dec_exp);
}

Mem_8bits   *genrsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    t_rsa       rsa;
    Long_64bits m;
    Long_64bits ciphertext;
    Long_64bits pt;

    int c = 0;
    int tot = 100;
    for (int i = 0; i < tot; i++)
    {
        rsa_generation(&rsa, &rsa.privkey, &rsa.pubkey);

        // m = ulrandom();
        m = 12345;
        
        if (rsa.privkey.modulus % m == 0)
        {
            printf("rsa.privkey.modulus %% %lu == 0\n", m);
            exit(0);
        }
        // printf("rsa.privkey.modulus %% %lu = %lu\n", m, rsa.privkey.modulus % m);
        
        ciphertext = modular_exp(m, rsa.pubkey.enc_exp, rsa.pubkey.modulus);
        pt = modular_exp(ciphertext, rsa.privkey.dec_exp, rsa.privkey.modulus);
        // printf("%lu^%lu mod %lu = %lu\n", m, rsa.pubkey.enc_exp, rsa.pubkey.modulus, ciphertext);
        // printf("%lu^%lu mod %lu = %lu\n", ciphertext, rsa.privkey.dec_exp, rsa.privkey.modulus, pt);
        printf("Plaintext in : %lu\n", m);
        printf("Ciphertext   : %lu\n", ciphertext);
        printf("Plaintext out: %lu\n\n", pt);
        if (m == pt)
            c++;
    }

    printf("\nRSA eval: %.1f%%\n", ((float)c / tot) * 100);
    // ciphertext = (Long_64bits)pow(m, rsa.pubkey.enc_exp) % rsa.pubkey.modulus;
    // pt = (Long_64bits)pow(ciphertext, rsa.privkey.dec_exp) % rsa.privkey.modulus;
    // printf("\n%lu^%lu mod %lu = %lu\n", m, rsa.pubkey.enc_exp, rsa.pubkey.modulus, ciphertext);
    // printf("%lu^%lu mod %lu = %lu\n", ciphertext, rsa.privkey.dec_exp, rsa.privkey.modulus, pt);

    // printBits(&m, LONG64_byteSz);
    // printBits(&pt, LONG64_byteSz);

    exit(0);
    return NULL;
}
