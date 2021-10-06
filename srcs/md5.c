#include "ft_ssl.h"

void    md5_failure(char *error_msg)
{
    ft_putstr(error_msg);
    exit(EXIT_FAILURE);
}

void    md5(t_hash *hash)
{
    printf("sizeof(Mem_8bits): %ld bytes\n", sizeof(Mem_8bits));
    printf("sizeof(Len_64bits): %ld bytes\n", sizeof(Len_64bits));

    printf("Before memcpy msg: %s\n", hash->msg);
    printf("Before memcpy len: %ld\n", hash->len);
    printf("Before memcpy hash: %s\n", hash->hash);

    hash->hash = ft_strnew(hash->msg);
    printf("Before padding: >%s<\n\n", hash->hash);
    printf("sizeof hash: %ld\n\n", ft_strlen(hash->hash));

    padding((Mem_8bits **)&(hash->hash), (Len_64bits)hash->len);
    printf("\nAfter padding: >%s<\n", hash->hash);
    printf("sizeof hash: %ld\n\n", ft_strlen(hash->hash));
    
    // hash->hash = "262f5a26e266f5bcc9684e685a56c"; // Temporally
}
