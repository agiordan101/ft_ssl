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

inline Long_64bits modular_mult(Long_64bits a, Long_64bits b, Long_64bits mod)
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

inline Long_64bits ulrandom()
{
    static int  fd = -2;
    static char buff[URANDBUFF];
    static char *buff_offset = buff;
    static int  data_left = 0;
    int         ret;

    if (fd == -2)
        fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
        open_failed("urandom() failed: Cannot open file '/dev/urandom' in O_RDONLY mode", "/dev/urandom");

    if (data_left < LONG64_byteSz)
    {
        // printf("read / data_left=%d / fd=%d\n", data_left, fd);
        if ((ret = read(fd, buff, URANDBUFF)) == -1)
            read_failed("urandom() failed: Cannot read file '/dev/urandom'", fd);
        data_left += ret;
        buff_offset = buff;
    }
    data_left -= LONG64_byteSz;
    buff_offset += LONG64_byteSz;
    return *((Long_64bits *)buff_offset);
}
