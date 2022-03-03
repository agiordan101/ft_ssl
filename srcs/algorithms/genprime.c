#include "ft_ssl.h"

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

Long_64bits prime_generator(Long_64bits min, Long_64bits max, int verbose)
{
    /*
        Generate 64-bits random prime number.
    */
    Long_64bits p = 42;
    int         i = 1;
    int         is_prime = 0;

    while (i++ < max / 2 && !is_prime)
    {
        p = ulrandom_range(min, max);

        if (first_primes_multiple(p))
            continue ;

        //OpenSSL '.' symbol, mean that the number has passed an initial sieve test
        if (verbose)
            ft_putstderr(".");

        is_prime = miller_rabin_primality_test(p, PROBMIN_ISPRIME, verbose);
    }
    if (verbose)
        ft_putstderr("\n"); // OpenSSL '\n' symbol, mean that the number has passed all the prime tests 
    return p;
}

Mem_8bits   *genprime(t_genprime *genprime_data, Long_64bits *oByteSz)
{
    Long_64bits p = prime_generator(
        genprime_data->min,
        genprime_data->max ?\
            genprime_data->max :\
            BIG_LONG64,
        1
    );
    Mem_8bits   *prime = ft_ulltoa(p);

    if (oByteSz)
        *oByteSz = ft_strlen(prime);
    return prime;
}

Mem_8bits   *cmd_wrapper_genprime(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags)
{
    (void)input;
    (void)iByteSz;
    (void)flags;
    return genprime((t_genprime *)cmd_data, oByteSz);
}
