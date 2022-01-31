#include "ft_ssl.h"

static void fermat_test_solver(Long_64bits n, Long_64bits *d, int *s)
{
    /*
        With n > 2 and n odd, d odd, s > 0, find s and d like :

            n - 1 = 2^s * d
                
            With 2^s = 1 << s
                => n - 1 = d << s   (represent by d concat with s-zeros in memory)
                => d = (n-1) >> s

        n - 1 is odd: there are always
        a right part with s zeros and
        a left part with the truth d value
    */
    *d = n - 1;
    for (*s = 0; !(*d & 1); (*s)++)
        *d >>= 1;

    // printf("fermat_test_solver | %ld - 1 = 2^%d * %ld\n", n, *s, *d);
}

static int  miller_rabin_witness_test(Long_64bits n, Long_64bits a, Long_64bits d, int s)
{
    // printf("miller_rabin_witness n=%ld\ta=%ld\ts=%d\n", n, a, s);

    Long_64bits x = modular_exp(a, d, n);

    if (x == 1 || x == n - 1)
        return 0;

    for (int i = 0; i < s - 1; i++)
    {
        x = modular_mult(x, x, n);
        if (x == n - 1)
            return 0;
    }
    return 1;
}

int         miller_rabin_primality_test(Long_64bits n, float p)
{
    /*
        http://defeo.lu/in420/DM3%20-%20Test%20de%20Miller-Rabin
        https://fr.wikipedia.org/wiki/Test_de_primalit%C3%A9_de_Miller-Rabin

        Miller-Rabin algorithm ->
            Test witness value a, like 1 < a < n - 1,
            until the desired probability p is reached
    */
    float       prime_prob = 1;

    Long_64bits a;
    Long_64bits a_save[ISPRIMEMEMSZ];
    int         i_a_save = 0;
    
    int         is_valid_rand = 1;
    int         i_tmp;

    Long_64bits d;
    int         s;

    // Handle obvious not prime number: Even number (except 2) | 1
    if ((n != 2 && n % 2 == 0) || n == 1)
        return 0;

    fermat_test_solver(n, &d, &s); // n has to be odd

    // Handle case where all possible a values were tested (i_a_save = n - 3 -> No more random witness)
    while (prime_prob > p && i_a_save < n - 3)
    {
        // Generate random number until get one witch is never seen
        is_valid_rand = 0;
        while (!is_valid_rand)
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
            is_valid_rand = (i_tmp == i_a_save) || (i_tmp == ISPRIMEMEMSZ);
            // printf("a=%lu\ti_tmp=%d\ti_a_save=%d\tvalid: %d\n", a, i_tmp, i_a_save, is_valid_rand);
        }
        a_save[(i_a_save++) % ISPRIMEMEMSZ] = a;

        // Test of the witness/a
        if (miller_rabin_witness_test(n, a, d, s))
            return 0;
        prime_prob *= 0.25;
        // printf("prime_prob=%f\n", prime_prob);
    }
    return 1;
}

Mem_8bits   *isprime(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    float       p = 0.00001;
    Long_64bits n = ft_atoi(*plaintext);

    Mem_8bits *result;
    if (miller_rabin_primality_test(n, p))
    {
        result = "True\n";
        *hashByteSz = 5;
    }
    else
    {
        result = "False\n";
        *hashByteSz = 6;
    }
    return ft_memdup(result, *hashByteSz);
}
