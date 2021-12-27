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
        // printf("\nt_hash_base64_decode_inputs (len=%d): >%s<\n", hash->len, hash->msg);
        tmp = hash->msg;
        hash->msg = base64((Mem_8bits **)&hash->msg, hash->len, (Long_64bits *)&hash->len, d);
        // hash->len = ft_strlen(hash->msg);
        // printf("t_hash_base64_decode_inputs (len=%d): >%s<\n", hash->len, hash->msg);

        free(tmp);
        hash = hash->next;
    }
}

inline void t_hash_base64_encode_output(t_hash *hash)
{
    char    *tmp;

    while (hash)
    {
        // printf("\nt_hash_base64_encode_output           :");
        // for (int i = 0; i < hash->hashByteSz / 8; i++)
        //     printf("%lx", ((Long_64bits *)hash->hash)[i]);

        // printf("\nhash->hash: %lx\n", *((Long_64bits *)hash->hash));

        // endianReverse(hash->hash, hash->hashByteSz);

        // printf("\nt_hash_base64_encode_output (len=%d): >%s<\n", hash->hashByteSz, hash->hash);
        tmp = hash->hash;
        hash->hash = base64(&hash->hash, hash->hashByteSz, (Long_64bits *)&hash->hashByteSz, e);
        // hash->hashByteSz = ft_strlen(hash->hash);
        // printf("t_hash_base64_encode_output (len=%d): >%s<\n", hash->hashByteSz, hash->hash);

        free(tmp);
        hash = hash->next;
    }
}

inline void t_hash_hashing(t_hash *hash)
{
    while (hash)
    {
        if (!hash->error)
        {
            // printf("hash->msg: >%s<\n", hash->msg);
            // printf("hash->name: >%s<\n", hash->name);
            // exit(0);
            hash->hash = ssl.hash_func_addr((Mem_8bits **)&hash->msg, hash->len, (Long_64bits *)&hash->hashByteSz, ssl.flags);
            // hash->hashByteSz = ft_strlen((char *)hash->hash);
            // printf("Hash (len=%d): %p\n", hash->hashByteSz, hash);
        }
        hash = hash->next;
    }
}

inline void t_hash_output(t_hash *hash)
{
    while (hash)
    {
        // printf("\nHASH hash->msg (len=%d): >%s<\n", hash->len, hash->msg);
        // printf("INTO hash->hash (len=%d): >%s<\n\n", hash->hashByteSz, hash->hash);
        // int ret;
        // printf("\nHASH hash->msg (len=%d): >", hash->len);
        // ret = write(ssl.fd_out, hash->msg, hash->len);
        // printf("<\nINTO hash->hash (len=%d): >", hash->hashByteSz);
        // ret = write(ssl.fd_out, hash->hash, hash->hashByteSz);
        // printf("<\n");
        output(hash);
        hash = hash->next;
    }
}
