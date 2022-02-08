#include "ft_ssl.h"

/*
    Miller-Rabin probabilistics primally test
*/

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
            Apply miller_rabin_witness_test() on a values (1 < a < n - 1) to know if n is composed.
            If the desired probability p is reached, n is considered to be prime
    */
    float       error_prob = 1;

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
    while (error_prob > p && i_a_save < n - 3)
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
        error_prob *= 0.25;
        // printf("error_prob=%f\n", error_prob);
    }
    return 1;
}

Mem_8bits   *isprime(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    /*
        "Wrapper" for miller_rabin_primality_test() function to compute isprime command"
    */
    Mem_8bits   *result;
    Long_64bits n = ft_atoi(*plaintext);

    if (miller_rabin_primality_test(
            n,
            command_data && ((t_isprime *)command_data)->prob_requested ?\
                ((t_isprime *)command_data)->prob_requested :\
                PROBMIN_ISPRIME
        )
    )
    {
        result = "True";
        *hashByteSz = 4;
    }
    else
    {
        result = "False";
        *hashByteSz = 5;
    }
    return ft_memdup(result, *hashByteSz);
}


/*
    Prime number generator
*/

static int  first_primes_multiple(Long_64bits p)
{
    static int firstprimes[200] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
        179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
        353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
        419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
        467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
        547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
        607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
        661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
        739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
        811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
        877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
        947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
        1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
        1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
        1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223
    };
    for (int i = 0; i < 200; i++)
        if (p % firstprimes[i] == 0)
            return 1;
    return 0;
}

Long_64bits prime_generator(Long_64bits min, Long_64bits max)
{
    /*
        Generate 64-bits random prime number.
    */
    Long_64bits p = ulrandom_range(min, max);
    int         i = 1;

    while (i++ < max / 2 &&\
            (first_primes_multiple(p) ||\
            !miller_rabin_primality_test(p, PROBMIN_ISPRIME)))
        p = ulrandom_range(min, max);
    return p;
}

Mem_8bits   *genprime(void *command_data, Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    /*
        "Wrapper" for prime_generator() function to compute genprime command
    */
    t_genprime  *genprime_data = (t_genprime *)command_data;
    Long_64bits p = prime_generator(genprime_data->min, genprime_data->max ? genprime_data->max : BIG_LONG64);
    // printf("p = %lu\t(len=%d)\n", p, ft_unbrlen(p));

    Mem_8bits   *prime = ft_ulltoa(p);
    // printf("prime = %s\n", prime);

    *hashByteSz = ft_strlen(prime);
    (void)command_data; // No data pass in needed
    (void)plaintext;
    (void)ptByteSz;
    (void)way;
    return prime;
}

