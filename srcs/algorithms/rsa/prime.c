#include "ft_ssl.h"

static int     miller_rabin_witness(Long_64bits n, Long_64bits a)
{
    // printf("miller_rabin_witness n=%ld\ta=%ld\n", n, a);

    return 0;
}

int     is_prime(Long_64bits n, float p)
{
    /*
        Miller-Rabin algorithm ->
            Test witness value a, like 1 < a < n - 1,
            until the desired probability p is reached
    */
    float       prime_prob = 1;
    Long_64bits a;
    Long_64bits a_save[ISPRIMEMEMSZ];
    int         i_a_save = 0;
    int         is_valid_a = 1;
    int         i_tmp;

    // Handle obvious not prime number: Even number (except 2) | 1
    if ((n % 2 == 0 && n != 2) || n == 1)
        return 0;

    // Handle case where all possible a values were tested (i_a_save = n - 3 -> No more witness)
    while (prime_prob > p && i_a_save < (int)n - 3)
    {
        // Generate random number until get one witch is never seen
        is_valid_a = 0;
        while (!is_valid_a)
        {
            a = rand() % (n - 3) + 2; // 1 < a < n - 1

            // Check in memory if a is already seen
            i_tmp = 0;
            while (i_tmp < i_a_save && i_tmp < ISPRIMEMEMSZ && a_save[i_tmp] != a)
            {
                // printf("a_save[i_tmp]=%lu\n", a_save[i_tmp]);
                i_tmp++;
            }

            // If we reach end of memory -> New a value is found
            is_valid_a = (i_tmp == i_a_save) || (i_tmp == ISPRIMEMEMSZ);
            printf("a=%lu\ti_tmp=%d\ti_a_save=%d\tvalid: %d\n", a, i_tmp, i_a_save, is_valid_a);
        }
        a_save[(i_a_save++) % ISPRIMEMEMSZ] = a;

        // Test of the witness/a
        if (miller_rabin_witness(n, a))
            return 0;
        prime_prob *= 0.25;
        // printf("prime_prob=%f\n", prime_prob);
    }
    return 1;
}

Mem_8bits   *rsa(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    float   p = 0.00005;

    // printf("is_prime(%lu, %f) -> %d\n\n\n", (Long_64bits)1<<34, p, is_prime(((Long_64bits)1)<<34, p));
    for (int i = 1; i < 25; i++)
        printf("is_prime(%d, %f) -> %d\n\n\n", i, p, is_prime(i, p));
    exit(0);
}
