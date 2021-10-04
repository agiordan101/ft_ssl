#include "ft_ssl.h"

float   ft_abs(float x)
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

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	char	*castsrc;
	char	*castdest;
	size_t	len1;
	size_t	i;

	castsrc = (char *)src;
	castdest = (char *)dest;
	len1 = ft_strlen(castsrc);
	i = 0;
	while (i < n && i < len1)
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
	int 	i;

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

void	ft_putstr(char *s)
{
    int ret = write(1, s, ft_strlen(s));
    if (ret < 0)
    {
        ret = write(1, "write() failed.", 16);
        exit(EXIT_FAILURE);
    }
}
