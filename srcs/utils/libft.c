#include "ft_ssl.h"

// About memory (void *) ------------------------------------------------------------------

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
	char	*castsrc = (char *)src;
	char	*castdest = (char *)dest;
	size_t	i = -1;

	while (++i < n)
		castdest[i] = castsrc[i];
	return castdest;
}

inline Mem_8bits *ft_memnew(int byteSz)
{
    Mem_8bits   *mem;

    if (!(mem = (Mem_8bits *)malloc(sizeof(Mem_8bits) * (byteSz + 1))))
        malloc_failed("Unable to malloc new memory space in ft_memnew() function\n");
    ft_bzero(mem, byteSz + 1);
    return mem;
}

inline Mem_8bits *ft_memdup(void *mem, int byteSz)
{
    Mem_8bits   *dup = ft_memnew(byteSz);

    ft_memcpy(dup, mem, byteSz);
    return dup;
}

inline void     *ft_memjoin(void *mem1, int byteSz1, void *mem2, int byteSz2)
{
    Mem_8bits   *memjoin = ft_memnew(byteSz1 + byteSz2);
    ft_memcpy(memjoin, mem1, byteSz1);
    ft_memcpy(memjoin + byteSz1, mem2, byteSz2);
    return memjoin;
}


// About string (char *) ------------------------------------------------------------------

inline Long_64bits	ft_atoi(const char *str)
{
	long	nb;
	Long_64bits		sign;
	Long_64bits		i;

	i = 0;
	nb = 0;
	sign = 1;
	while ((str[i] >= 9 && str[i] <= 13) || str[i] == ' ')
		i++;
	if (str[i] == '+')
		i++;
	else if (str[i] == '-')
	{
		sign = -1;
		i++;
	}
	while (str[i] >= '0' && str[i] <= '9')
		nb = nb * 10 + str[i++] - '0';
	return ((Long_64bits)(nb * sign));
}

char	*ft_ulltoa(Long_64bits n)
{
	int		len = ft_unbrlen(n);
	char	*str = ft_memnew(len);

	while (n)
	{
		str[--len] = n % 10 + '0';
		n /= 10;
	}
	return str;
}

inline int   ft_strlen(char *str)
{
	char	*save = str;
	while (*str++)
		;
	return (str - save - 1);
}

inline char *ft_strdup(char *src)
{
    return (char *)ft_memdup(src, ft_strlen(src));
}

inline char *ft_strinsert(char *str1, char *toinsert, char *str2)
{
    int     str1len = ft_strlen(str1);
    int     toinsertlen = ft_strlen(toinsert);
    int     str2len = ft_strlen(str2);
    char    *concat = (char *)ft_memnew(str1len + toinsertlen + str2len);

    ft_memcpy(concat, str1, str1len);
    ft_memcpy(concat + str1len, toinsert, toinsertlen);
    ft_memcpy(concat + str1len + toinsertlen, str2, str2len);
    return concat;
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

inline int	ft_strncmp(const char *s1, const char *s2, size_t n)
{
    size_t  i = -1;

	while (++i < n && *s1 == *s2 && *s1 && *s2)
	{
		s1++;
		s2++;
	}
    if (i == n)
        return 0;
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

// Long_64bits about functions ------------------------------------------------------------------

int         ft_unbrlen(Long_64bits nbr)
{
	int count = 1;

    for (Long_64bits p = 10; p <= nbr; p *= 10)
        count++;
	return count;
}

// Display functions ------------------------------------------------------------------

inline void	ft_putstderr(char *s)
{
    int ret = write(STDERR, s, ft_strlen(s));
    if (ret < 0)
        ft_ssl_error("ft_putstderr() function failed.\n");
}

inline void	ft_putstrfd(int fd, char *s)
{
	if (s)
	{
		int ret = write(fd, s, ft_strlen(s));
		if (ret < 0)
			write_failed("write() failed in ft_putstrfd()", fd);
	}
}

inline void	ft_putstr(char *s)
{
    ft_putstrfd(ssl.fd_out, s);
}

void    	ft_putnbrfd(int fd, Long_64bits n)
{
	if (n > 9)
	{
		ft_putnbrfd(fd, n / 10);
		ft_putnbrfd(fd, n % 10);
	}
	else
    {
        char c = n + '0';
        c = write(fd, &c, 1);
    }
}

inline void ft_putnbr(Long_64bits n)
{
    ft_putnbrfd(ssl.fd_out, n);
}


// About hexadecinmal conversions ------------------------------------------------------------------

inline Long_64bits  ft_strtoHex(char *str)
{
	Long_64bits nbr = 0;
    int         i = -1;

    str = ft_lower(str);
    while (++i < ft_strlen(str) && i < LONG64_byteSz * 2)
        if ('0' <= str[i] && str[i] <= '9')
		    nbr = nbr * 0x10 + (str[i] - '0');
        else if ('a' <= str[i] && str[i] <= 'f')
		    nbr = nbr * 0x10 + 10 + (str[i] - 'a');
	return nbr;
}

inline char         *ft_hextoStr(Long_64bits nbr)
{
	char    *str = (char *)ft_memnew(LONG64_byteSz);

	for (int i = 0; i < LONG64_byteSz; i++)
        str[i] = (nbr >> (i * 8)) & 0xff;
	return str;
}

void    	        _ft_printHex(Long_64bits n, int totalMemSz, char hexbase[], int leading_zero)
{
    unsigned char   *mem = (unsigned char *)&n;

    if (n)
        for (int i = totalMemSz - 1; i >= 0; i--)
        {
            if (!leading_zero && (mem[i] / 16))
                leading_zero = 1;
            if (leading_zero)
                if (write(ssl.fd_out, hexbase + (mem[i] / 16), 1) == -1)
                    write_failed("write() failed in ft_printHex()", ssl.fd_out);

            if (!leading_zero && (mem[i] % 16))
                leading_zero = 1;
            if (leading_zero)
                if (write(ssl.fd_out, hexbase + (mem[i] % 16), 1) == -1)
                    write_failed("write() failed in ft_printHex()", ssl.fd_out);
        }
    else
        if (write(ssl.fd_out, hexbase, 1) == -1)
            write_failed("write() failed in ft_printHex()", ssl.fd_out);
}

inline void	        ft_printHex(Long_64bits n)
{
    _ft_printHex(n, LONG64_byteSz, HEXABASE_low, 0);
}
