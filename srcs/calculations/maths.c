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

Long_64bits modular_mult(Long_64bits a, Long_64bits b, Long_64bits mod)
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

Long_64bits modular_exp(Long_64bits a, Long_64bits b, Long_64bits mod)
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
