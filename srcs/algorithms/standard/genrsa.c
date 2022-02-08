#include "ft_ssl.h"

void        rsa_generation(t_rsa *rsa, t_rsa_private_key *privkey, t_rsa_public_key *pubkey)
{
    /*
        For security purposes :
            - p and q should be big primes and similar in magnitude but differ in length by a few digits to make factoring harder.
                p and q should be large primes
                |p - q| should be large
                p - 1 and q - 1 should not be P-smooth
                p + 1 and q + 1 should have at least one big prime factor.
    */
    // int     plen = 32 + (ulrandom() % 21);

    rsa->p = prime_generator(1UL<<10, 1UL<<32);
    rsa->q = prime_generator(1UL<<10, 1UL<<31);
    printf("BIGLONG: %lu\n", BIG_LONG64);
    printf("rsa->p : %lu\n", rsa->p);
    printf("rsa->q : %lu\n", rsa->q);
    // printf("plen      : %d\n", plen);
    // while (ulmult_overflow(rsa->p, rsa->q))
    // {
    //     rsa->q = prime_generator(1UL<<10, 1UL<<53);
    //     printf("rsa->q: %lu\n", rsa->q);
    // }
    // if (ulmult_overflow(rsa->p, rsa->q))
    // {
    //     printf("genrsa OVERFLOW\n");
    //     exit(0);
    // }

    rsa->modulus = rsa->p * rsa->q;
    printf("rsa->n : %lu\n", rsa->modulus);
}

Mem_8bits   *genrsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{

    t_rsa   rsa;

    rsa_generation(&rsa, &rsa.privkey, &rsa.pubkey);


    // printf("BIG_LONG64: %lu\n", BIG_LONG64);
    // Long_64bits p = BIG_LONG64;
    // printBits(&p, LONG64_byteSz);
    exit(0);
    return NULL;
}
