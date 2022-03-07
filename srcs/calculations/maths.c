# include "ft_ssl.h"

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
    c /= b;
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
    Modular multiplicative inverse is written as x = e^(-1) mod N.
    x is any integer that satisfies x.e ≡ 1 (mod N).

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

    // Handle negative case: 1 mod b = 1 + kb with k relative integer (When u < 0, k = -1)
    if (u < 0)
        u += b;
    long long mm = modular_mult(u, a, b);
    return u;
}
