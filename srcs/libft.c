#include "ft_ssl.h"

inline void	ft_bzero(void *s, size_t n)
{
	size_t  i;
    char    *cast = (char *)s;

	i = 0;
	while (i < n)
		cast[i++] = '\0';
}

inline void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	char	*castsrc;
	char	*castdest;
	size_t	i;

	castsrc = (char *)src;
	castdest = (char *)dest;
	i = 0;
	while (i < n)
	{
		castdest[i] = castsrc[i];
		i++;
	}
	return (castdest);
}

inline char	*ft_strnew(char *src)
{
	char	*str;
	int 	len = ft_strlen(src);

	if (!(str = (char *)malloc(sizeof(char) * (len + 1))))
		malloc_failed("Unable to malloc string in ft_strnew() function\n");
	ft_memcpy(str, src, len);
	str[len] = '\0';
	return (str);
}

inline int	ft_strlen(char *p)
{
    unsigned long long *str = (unsigned long long *)p;
	int	count = 0;

    if (str)
        while (1)
            if ((++count && !(*str & 0x00000000000000FF)) ||\
                (++count && !(*str & 0x000000000000FF00)) ||\
                (++count && !(*str & 0x0000000000FF0000)) ||\
                (++count && !(*str & 0x00000000FF000000)) ||\
                (++count && !(*str & 0x000000FF00000000)) ||\
                (++count && !(*str & 0x0000FF0000000000)) ||\
                (++count && !(*str & 0x00FF000000000000)) ||\
                (++count && !(*str++ & 0xFF00000000000000)))
                return (count - 1);
    return 0;
}

inline int	ft_strcmp(const char *s1, const char *s2)
{
	while (*s1 == *s2 && *s1 && *s2)
	{
		s1++;
		s2++;
	}
	return ((unsigned char)(*s1) - (unsigned char)(*s2));
}

inline char	*ft_stradd_quote(char *str, int len)
{
    char *newstr;

    if (!(newstr = (char *)malloc(sizeof(char) * (len + 3))))
		malloc_failed("Unable to malloc string in ft_stradd_quote() function\n");
    newstr[0] = '\"';
    ft_memcpy(newstr + 1, str, len);
    ft_memcpy(newstr + len + 1, "\"\0", 2);
    return newstr;
}

inline char	*ft_lower(char *str)
{
	for (int i = 0; i < ft_strlen(str); i++)
		str[i] = ('A' <= str[i] && str[i] <= 'Z') ? str[i] + ('a' - 'A') : str[i];
	return str;
}

inline void	ft_putstr(char *s)
{
    int ret = write(ssl.fd_out, s, ft_strlen(s));
    if (ret < 0)
    {
        char c = '\n';
        ret = write(1, "write() failed in ft_putstr(), fd=", 35);
        ft_putnbr(1, ssl.fd_out);
        ret = write(1, &c, 1);
        freexit(EXIT_FAILURE);
    }
}

void    	ft_putnbr(int fd, int n)
{
	if (n > 9)
	{
		ft_putnbr(fd, n / 10);
		ft_putnbr(fd, n % 10);
	}
	if (n >= 0 && n <= 9)
    {
        char c = n + '0';
        c = write(fd, &c, 1);
    }
}

inline Long_64bits ft_strtoHex(char *str)
{
	Long_64bits nbr = 0;

    str = ft_lower(str);
	for (int i = 0; i < ft_strlen(str); i++)
        if ('0' <= str[i] && str[i] <= '9')
		    nbr = nbr * 16 + (str[i] - '0');
        else if ('a' <= str[i] && str[i] <= 'e')
		    nbr = nbr * 16 + 10 + (str[i] - 'a');
	return nbr;
}

char    *ft_hexToBin(Long_64bits n, int byteSz)
{
    char          *bin;
    unsigned char hex[16] = "0123456789abcdef";
    unsigned char *num = (unsigned char *)&n;

    if (!(bin = (char *)malloc(sizeof(char) * (byteSz * 2 + 1))))
        malloc_failed("Unable to malloc string in libft ft_hexToBin function\n");
    bin[byteSz * 2] = '\0';
    // for (int i = byteSz; i >= 0; i--)
    for (int i = 0; i < byteSz; i++)
    {
        bin[byteSz - i * 2] = hex[num[i] / 16];
        if (i + 1 < byteSz)
            bin[byteSz - i * 2 + 1] = hex[num[i] % 16];
    }
    return bin;
}

Mem_8bits        *ft_strHexToBin(Mem_8bits *str, int byteSz)
{
    Key_64bits tmp = ft_strtoHex(str);
    // printBits(&tmp, KEY_byteSz);
    // ft_printHex(tmp);
    // printf("tmp: %lx\n", tmp);

    int         bin_i = 0;
    Mem_8bits   *bin = (Mem_8bits *)&tmp;
    endianReverse(bin, KEY_byteSz);
    // printBits(bin, KEY_byteSz);

    int         out_i = 0;
    Mem_8bits   out[KEY_byteSz];
    ft_bzero(out, KEY_byteSz);

    // Skip zero bytes at the beginning
    while (!bin[bin_i] && bin_i < KEY_byteSz) bin_i++;
    // printf("After zero bytes skipped, bin_i=%d\n", bin_i);

    // Is first non-null byte upper than 0x0f ? (To remove zero of byte left-side)
    if (bin[bin_i] & 0b11110000)
    {
        while (bin_i < KEY_byteSz)
        {
            out[out_i++] = bin[bin_i++];
            // printf("out[out_i++]=%x\n", out[out_i - 1]);
        }
    }
    else
    {
        out[out_i++] = bin[bin_i++] << 4;
        // printf("out[0]=%x\n", out[0]);
        // printf("out_i=%d\n", out_i-1);
        // printf("bin_i=%d\n\n", bin_i);
        while (bin_i < KEY_byteSz)
        {
            out[(int)(out_i / 2)] += out_i % 2 ? bin[bin_i] >> 4 : bin[bin_i] & 0b00001111;
            // printf("out[%d]=%x\n", (int)(out_i / 2), out[(int)(out_i / 2)]);
            // printf("out_i=%d\n", out_i);
            // printf("bin_i=%d\n\n", bin_i);
            out_i++;

            out[(int)(out_i / 2)] += out_i % 2 ? bin[bin_i++] & 0b11110000 : bin[bin_i++] << 4;
            // printf("out[%d]=%x\n", (int)(out_i / 2), out[(int)(out_i / 2)]);
            // printf("out_i=%d\n", out_i);
            // printf("bin_i=%d\n\n", bin_i);
            out_i++;
        }
        out_i = out_i % 2 ? (out_i - out_i % 2) / 2 + 1 : out_i / 2;
    }
    // printBits(out, out_i);
    // exit(0);

    if (!(bin = (Mem_8bits *)malloc(sizeof(Mem_8bits) * (out_i + 1))))
        malloc_failed("Unable to malloc string in libft ft_hexToBin function\n");
    ft_bzero(bin, out_i + 1);
    ft_memcpy(bin, out, out_i);
    return bin;
}

void    	ft_printHex(Word_32bits n)
{
    unsigned char hex[16] = "0123456789abcdef";
    unsigned char *word = (unsigned char *)&n;
    unsigned char c_16e0;
    unsigned char c_16e1;

    for (int i = 0; i < WORD_ByteSz; i++)
    {
        c_16e0 = hex[word[i] % 16];
        c_16e1 = hex[word[i] / 16];
        if (write(ssl.fd_out, &c_16e1, 1) == -1 ||\
            write(ssl.fd_out, &c_16e0, 1) == -1)
        {
            int ret = write(1, "ft_printHex() has failed.\n", 27);
            (void)ret;
            freexit(EXIT_FAILURE);
        }
    }
}
