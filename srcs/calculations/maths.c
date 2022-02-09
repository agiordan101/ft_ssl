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

Long_64bits        ulrandom()
{
    static int  fd = -2;
    static char buff[URANDBUFF];
    static char *buff_offset = buff;
    static int  data_left = 0;
    int         ret;
    Long_64bits ulr;

    if (fd == -2)
        fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
        open_failed("urandom() failed: Cannot open file '/dev/urandom' in O_RDONLY mode", "/dev/urandom");

    if (data_left < LONG64_byteSz)
    {
        // printf("read / data_left=%d / fd=%d\n", data_left, fd);
        if ((ret = read(fd, buff, URANDBUFF)) == -1)
            read_failed("urandom() failed: Cannot read file '/dev/urandom'", fd);
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
    printf("GCD = %lu\n", a);
    return a;
}

Long_64bits         extended_euclide_algo(Long_64bits a, Long_64bits b, Long_64bits *u, Long_64bits *v)
/*
    Compute PGCD(a, b) and return it
    Save value of one Bézout coefficents couple: (u, v)

    fonction euclide-étendu(a, b)
    si b = 0 alors
          retourner (a, 1, 0)
    sinon
          (d', u', v') := euclide-étendu(b, a mod b)
          retourner (d', v', u' - (a÷b)v')
*/
{
    if (a == 0)
    {
        *u = 0;
        *v = 1;
        return b;
    }
  
    Long_64bits u1, v1;
    Long_64bits gcd = extended_euclide_algo(b % a, a, &u1, &v1);

    *v = u1;
    // if (ulmult_overflow(b / a, u1))
    // {
    //     printf("OVERFLOW\n");
    //     exit(0);
    // }
    *u = v1 - (b / a) * u1;
    // *u = v1 - modular_mult(b / a, u1, BIG_LONG64);
    return gcd;
}

inline Long_64bits  mod_mult_inverse(Long_64bits a, Long_64bits b)
/*
    Compute PGCD(a, b), u and v like:
    au + bv = PGCD(a, b)

    With a and b primes, u is the modular multiplicative inverse of a and b
*/
{
    Long_64bits u;
    Long_64bits v;
    Long_64bits g = extended_euclide_algo(a, b, &u, &v);
    printf("a * u + b * v = PGCD(a, b)\n");
    printf("%lu * %lu + %lu * %lu = %lu\n", a, u, b, v, g);
    // Handle negative case
    if (u < 0)
    {
        printf("NEGATIVE CASE MOD MULT INVERSE\n");
        u = (u % b + b) % b;
    }
    if (g != gcd(a, b))
    {
        printf("pgcd fail\n");
        exit(0);
    }
    return u;
}

// int lpf(int n){
// 	int Max = -1;
// 	while(n % 2 == 0){
// 		Max = 2;
// 		n = n / 2;
// 	}
// 	for(int i = 3; i * i <= n; i += 2){
// 		while(n % i == 0){
// 			Max = i;
// 			n = n / i;
// 		}
// 	}
// 	if(n > 2 && n > Max)
// 		Max = n;
// 	return Max;
// }
 
// bool psmooth(int n, int p){
// 	if(lpf(n) <= p)
// 		return true;
// 	return false;
// }
