#include "ft_ssl.h"
/*
static inline void  rsa_test()
{
    t_rsa_keys       rsa;
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
        ft_bzero(&rsa, sizeof(t_rsa_keys));
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
*/

Mem_8bits   *genrsa(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    t_rsa   rsa;
    ft_bzero(&rsa, sizeof(t_rsa));

    // rsa_test();
    ft_putstderr("Generating RSA private key, 64 bit long modulus (2 primes)\n");

    rsa_keys_generation(&rsa);
    *hashByteSz = LONG64_byteSz;

    ft_putstderr("e is ");
    ft_putnbr(STDERR, rsa.pubkey.enc_exp);
    ft_putstderr("\n");

    Mem_8bits *der_privkey = DER_generate_public_key(&rsa.pubkey, hashByteSz);
    printf("der_privkey: %s\n", der_privkey);

    (void)command_data;
    (void)plaintext;
    (void)ptByteSz;
    (void)way;
    return der_privkey;
}
