#include "ft_ssl.h"

int   ft_abs(int x)
{
	return x < 0 ? -x : x;
}

float   ft_fabs(float x)
{
	return x < 0 ? -x : x;
}

int     ft_atoi(const char *str)
{
	long	nb;
	int		sign;
	int		i;

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
	return ((int)(nb * sign));
}

void	ft_fill(void *s, size_t n, char c)
{
	size_t  i;
    char    *cast = (char *)s;

	i = 0;
	while (i < n)
		cast[i++] = c;
}

void	ft_bzero(void *s, size_t n)
{
	size_t  i;
    char    *cast = (char *)s;

	i = 0;
	while (i < n)
		cast[i++] = '\0';
}

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	char	*castsrc;
	char	*castdest;
	// size_t	len1;
	size_t	i;

	castsrc = (char *)src;
	castdest = (char *)dest;
	// len1 = ft_strlen(castsrc);
    // printf("castsrc[i]: >%s<\n", castsrc);
    // printf("castdest: >%s<\n", castdest);
    // printf("len1=%d\n\n", len1);
    // printf("n=%d\n\n", n);
	i = 0;
	// while (i < n && i < len1)
	while (i < n)
	{
		castdest[i] = castsrc[i];
		i++;
	}
	return (castdest);
}

char	*ft_strnew(char *src)
{
	char	*str;
	int 	len = ft_strlen(src);

	if (!(str = (char *)malloc(sizeof(char) * (len + 1))))
		return (NULL);
	ft_memcpy(str, src, len);
	return (str);
}

int     ft_strcmp(const char *s1, const char *s2)
{
	while (*s1 == *s2 && *s1 && *s2)
	{
		s1++;
		s2++;
	}
	return ((unsigned char)(*s1) - (unsigned char)(*s2));
}

int		ft_strlen(char *p)
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

char    *ft_stradd_quote(char *str, int len)
{
    char *newstr;

    if (!(newstr = (char *)malloc(sizeof(char) * (len + 3))))
        return NULL;
    newstr[0] = '\"';
    ft_memcpy(newstr + 1, str, len);
    ft_memcpy(newstr + len + 1, "\"\0", 2);
    return newstr;
}

void	ft_putstr(char *s)
{
    int ret = write(1, s, ft_strlen(s));
    if (ret < 0)
    {
        ret = write(1, "write() failed.", 16);
        exit(EXIT_FAILURE);
    }
}
