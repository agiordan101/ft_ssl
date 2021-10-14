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
		return (NULL);
	ft_memcpy(str, src, len);
	str[len] = '\0';
	return (str);
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

inline char	*ft_stradd_quote(char *str, int len)
{
    char *newstr;

    if (!(newstr = (char *)malloc(sizeof(char) * (len + 3))))
        return NULL;
    newstr[0] = '\"';
    ft_memcpy(newstr + 1, str, len);
    ft_memcpy(newstr + len + 1, "\"\0", 2);
    return newstr;
}

inline void	ft_putstr(char *s)
{
    int ret = write(1, s, ft_strlen(s));
    if (ret < 0)
    {
        ret = write(1, "write() failed.", 16);
        exit(EXIT_FAILURE);
    }
}

void    	ft_printHex(Word_32bits n)
{
    unsigned char hex[16] = "0123456789abcdef";
    unsigned char *word = (unsigned char *)&n;
    unsigned char c_16e0;
    unsigned char c_16e1;

    for (int i = 0; i < 4; i++)
    {
        c_16e0 = hex[word[i] % 16];
        c_16e1 = hex[word[i] / 16];
        if (write(1, &c_16e1, 1) == -1 ||\
            write(1, &c_16e0, 1) == -1)
            freexit(EXIT_FAILURE);
    }
}
