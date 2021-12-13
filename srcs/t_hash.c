#include "ft_ssl.h"

inline void init_t_hash(t_hash *hash)
{
    *hash = (t_hash){0, NULL, NULL, 0, NULL, 0, 0, NULL};
    // *hash = (t_hash){0, NULL, NULL, 0, NULL, 0, 0, 0, NULL};
}

inline void t_hash_free(t_hash *hash)
{
    t_hash  *tmp;

    while (hash)
    {
        // printf("free: %p\n", hash->msg);
        if (hash->name)
            free(hash->name);
        if (hash->msg)
            free(hash->msg);
        if (hash->hash)
            free(hash->hash);
        tmp = hash;
        hash = hash->next;
        free(tmp);
    }
}

inline void t_hash_base64_decode_inputs(t_hash *hash)
{
    char    *tmp;

    while (hash)
    {
        tmp = hash->msg;
        hash->msg = base64((Mem_8bits **)&hash->msg, hash->len, D);
        hash->len = ft_strlen(hash->msg);
        printf("t_hash_base64_decode_inputs (len=%d): >%s<\n", hash->len, hash->msg);

        free(tmp);
        hash = hash->next;
    }
}

inline void t_hash_base64_encode_output(t_hash *hash)
{
    char    *tmp;

    while (hash)
    {
        printf("t_hash_base64_encode_output           :");
        for (int i = 0; i < 3; i++)
            printf("%lx", ((Long_64bits *)hash->hash)[i]);

        printf("\nt_hash_base64_encode_output (len=%d): >%s<\n", hash->hashByteSz, hash->hash);
        tmp = hash->hash;
        hash->hash = base64(&hash->hash, hash->hashByteSz, E);
        hash->hashByteSz = ft_strlen(hash->hash);
        printf("t_hash_base64_encode_output (len=%d): >%s<\n", hash->hashByteSz, hash->hash);

        free(tmp);
        hash = hash->next;
    }
}

inline void t_hash_hashing(t_hash *hash)
{
    while (hash)
    {
        // printf("hash->msg: >%s<\n", hash->msg);
        // printf("hash->name: >%s<\n", hash->name);

        hash->hash = ssl.hash_func_addr((Mem_8bits **)&hash->msg, hash->len, ssl.flags);
        hash->hashByteSz = ft_strlen((char *)hash->hash);
        // printf("Hash (len=%d): %p\n", hash->hashByteSz, hash);

        hash = hash->next;
    }
}

inline void t_hash_output(t_hash *hash)
{
    while (hash)
    {
        output(hash);
        hash = hash->next;
    }
}
