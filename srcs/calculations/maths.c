# include "ft_ssl.h"

// Long_64bits ft_pow(Long_64bits a, int pow)
// {
//     if (pow == 0)
//         return 1;

//     Long_64bits a_pow = a;

//     for (int i = 1; i < pow; i++)
//         a_pow *= a;
//     return a_pow;
// }

inline long long modular_mult(long long a, Long_64bits b, Long_64bits mod)
{
    Long_64bits res = 0;
 
    a %= mod;
    while (b)
    {
        if (b & 1)
            res = (res + a) % mod;

        a = (2 * a) % mod;
        b >>= 1;
    }
    return res;
}

inline Long_64bits modular_exp(Long_64bits a, Long_64bits b, Long_64bits mod)
{
    Long_64bits res = 1;

    a %= mod;
    while (b > 0)
    {
        if (b & 1)
            res = modular_mult(res, a, mod) % mod;

        a = modular_mult(a, a, mod) % mod;
        b >>= 1;
    }
    return res;
}

Long_64bits        ulrandom()
{
    static char buff[URANDBUFF];
    static char *buff_offset = buff;
    static int  data_left = 0;
    int         ret;
    Long_64bits ulr;

    if (ssl.ulrandom_fd == -2)
        ssl.ulrandom_fd = open(ssl.ulrandom_path, O_RDONLY);
    if (ssl.ulrandom_fd == -1)
        open_failed("ulrandom() failed: Cannot open random data file in O_RDONLY mode", ssl.ulrandom_path);

    if (data_left < LONG64_byteSz)
    {
        // printf("read / data_left=%d / ssl.ulrandom_fd=%d\n", data_left, ssl.ulrandom_fd);
        if ((ret = read(ssl.ulrandom_fd, buff, URANDBUFF)) == -1)
            read_failed("ulrandom() failed: Cannot read file '/dev/urandom' or -rand file pass in arg", ssl.ulrandom_fd);
        data_left = ret;
        buff_offset = buff;
    }
    ulr = *((Long_64bits *)buff_offset);
    data_left -= LONG64_byteSz;
    buff_offset += LONG64_byteSz;
    return ulr;
}

inline Long_64bits  ulrandom_range(Long_64bits min, Long_64bits max)
{
    /*
        min <= ulrand < max
    */
    return min + ulrandom() % (max - min);
}

inline int          ulmult_overflow(Long_64bits a, Long_64bits b)
{
    Long_64bits c = BIG_LONG64;
    // printf("%lu\n/\n%lu\n<\n%lu ?\n", c, b, a);
    c /= b;
    // printf("%lu\n<\n%lu ? %d\n", c, a, c < a);
    // b = b ? BIG_LONG64 / b : BIG_LONG64;
    return c < a;
}

inline Long_64bits  gcd(Long_64bits a, Long_64bits b)
{
    /*
        Euclidean algorithm
            - a = a % b
            - Swap a and b
    */
    while (b)
    {
        a %= b;
        a ^= b;
        b ^= a;
        a ^= b;
    }
    // printf("GCD = %lu\n", a);
    return a;
}

Long_64bits         extended_euclide_algo(Long_64bits a, Long_64bits b, long long *u, long long *v)
/*
    Compute PGCD(a, b) and return it
    Save value of one Bézout coefficents couple: (u, v) (Signed numbers)

    fonction euclide-étendu(a, b)
    si b = 0 alors
          retourner (a, 1, 0)
    sinon
          (d', u', v') := euclide-étendu(b, a mod b)
          retourner (d', v', u' - (a÷b)v')
*/
{
    long long u1;
    long long v1;

    if (a == 0)
    {
        *u = 0;
        *v = 1;
        return b;
    }
    Long_64bits gcd = extended_euclide_algo(b % a, a, &u1, &v1);
    *u = v1 - (b / a) * u1;
    *v = u1;
    return gcd;
}

inline Long_64bits  mod_mult_inverse(Long_64bits a, Long_64bits b)
/*
    Thanks to extended Euclidean algorithm,
    we can compute natural number PGCD(a, b) and relative integers u and v like:
        au + bv = PGCD(a, b)

    a and b are coprime so:
        a * u + b * v = 1
        a * u = 1 - b * v
        a * u = 1 mod b
        u is the modular multiplicative inverse of a and b
*/
{
    long long u;
    long long v;
    Long_64bits g = extended_euclide_algo(a, b, &u, &v);

    // printf("\n[Modular multiplicative inverse of a and b]\n");
    // printf("%lu * %lld + %lu * %lld = %lld (Real gcd()=%lu)\n", a, u, b, v, a*u+b*v, gcd(a, b));
    if (g != gcd(a, b))
    {
        printf("a * u + b * v != PGCD(a, b) (real pgcd=1 fail)\n");
        exit(0);
    }
    // printf("a * u + b * v = PGCD(a, b)\n");

    // Handle negative case: 1 mod b = 1 + kb with k relative integer (When u < 0, k = -1)
    if (u < 0)
        u += b;

    long long mm = modular_mult(u, a, b);
    // printf("%lu * %lld = %lld mod %lu\n", a, u, mm, b);

    // if (mm != 1 && mm != -b - 1)
    if (mm != 1)
    {
        printf("a * u != 1 mod b\n");
        printf("(%lu * %lld) != 1 mod %lu\n", a, u, b);
        printf("(%lld * %lu) %% %lu = %lld\n", u, a, b, mm);
        exit(0);
    }
    // printf("a * u = 1 mod b\n");
    return u;
}
