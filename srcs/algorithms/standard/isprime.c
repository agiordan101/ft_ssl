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

static Long_64bits  miller_rabin_witness_generator(Long_64bits n, Long_64bits *rand_save, int save_sz)
{
    int         i_tmp = 42;
    Long_64bits witness;
    int         is_valid_w = 0;

    // Generate random number until get one witch is never seen
    while (!is_valid_w)
    {
        witness = ulrandom_range(2, n - 1);   // 2 <= a < n - 1

        // printf("n = %lu / witness: %lu\n", n, witness);
        // Check in memory if a is already seen
        i_tmp = 0;
        while (i_tmp < save_sz &&\
            i_tmp < ISPRIMEMEMSZ &&\
            rand_save[i_tmp] != witness)
            i_tmp++;

        // If we reach end of memory -> New a value is found
        is_valid_w = (i_tmp == save_sz) || (i_tmp == ISPRIMEMEMSZ);
    }
    return witness;
}

int         miller_rabin_primality_test(Long_64bits n, float p, int verbose)
{
    /*
        http://defeo.lu/in420/DM3%20-%20Test%20de%20Miller-Rabin
        https://fr.wikipedia.org/wiki/Test_de_primalit%C3%A9_de_Miller-Rabin

        Miller-Rabin algorithm ->
            Apply miller_rabin_witness_test() on a values (1 < a < n - 1) to know if n is composed.
            If the desired probability p is reached, n is considered to be prime
    */
    float       error_prob = 1;

    Long_64bits witness;
    Long_64bits witness_save[ISPRIMEMEMSZ];
    int         save_sz = 0;

    Long_64bits d;
    int         s;

    // Handle obvious numbers: 0, 1 and even numbers (except 2) are not prime
    if (n % 2 == 0 || n < 3)
        return n == 2;

    fermat_test_solver(n, &d, &s); // n has to be odd

    if (p < 0)
        p = PROBMIN_ISPRIME;
    // Handle case where all possible a values were tested (save_sz = n - 3 -> No more random witness)
    while (error_prob > p && save_sz < n - 3)
    {
        //OpenSSL '\n' symbol, means a number has passed a single round of the Miller-Rabin primality test
        if (verbose)
            ft_putstderr("+");

        witness = miller_rabin_witness_generator(n, witness_save, save_sz);
        witness_save[save_sz++ % ISPRIMEMEMSZ] = witness;

        // printf("n = %lu / witness: %lu\n", n, witness);
        // Test of the witness
        if (miller_rabin_witness_test(n, witness, d, s))
            return 0;
        error_prob *= 0.25;
    }
    return 1;
}

Mem_8bits   *isprime(t_isprime *isprime_data, Mem_8bits *number, Long_64bits *oByteSz)
{
    Mem_8bits   *result;
    Long_64bits n = ft_atoi(number);

    if (miller_rabin_primality_test(
            n,
            isprime_data->prob_requested ?\
                isprime_data->prob_requested :\
                PROBMIN_ISPRIME,
            0
        )
    )
    {
        result = "True";
        *oByteSz = 4;
    }
    else
    {
        result = "False";
        *oByteSz = 5;
    }
    return ft_memdup(result, *oByteSz);
}

Mem_8bits   *cmd_wrapper_isprime(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags)
{
    (void)iByteSz;
    (void)flags;
    return isprime((t_isprime *)cmd_data, *input, oByteSz);
}
