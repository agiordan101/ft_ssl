#include "ft_ssl.h"

inline void init_t_hash(t_hash *hash)
{
    *hash = (t_hash){0, NULL, NULL, 0, NULL, 0, 0, NULL};
}

inline void t_hash_free(t_hash *hash)
{
    t_hash  *tmp;

    while (hash)
    {
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
        hash->msg = (char *)base64((Mem_8bits **)&hash->msg, hash->len, (Long_64bits *)&hash->len, d);

        free(tmp);
        hash = hash->next;
    }
}

inline void t_hash_base64_encode_output(t_hash *hash)
{
    Mem_8bits   *tmp;

    while (hash)
    {
        if (!hash->error)
        {
            tmp = hash->hash;
            hash->hash = base64(&hash->hash, hash->hashByteSz, (Long_64bits *)&hash->hashByteSz, e);
            free(tmp);
        }
        hash = hash->next;
    }
}

inline void t_hash_hashing(t_hash *hash)
{
    while (hash)
    {
        if (!hash->error)
            hash->hash = ssl.command_addr((Mem_8bits **)&hash->msg, hash->len, (Long_64bits *)&hash->hashByteSz, ssl.flags);
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
