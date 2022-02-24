#include "ft_ssl.h"

inline void init_t_hash(t_hash *hash)
{
    *hash = (t_hash){0, NULL, NULL, 0, NULL, 0, 0, NULL};
}

inline void t_hash_free(t_hash *hash)
{
    if (hash->name)
        free(hash->name);
    if (hash->msg)
        free(hash->msg);
    if (hash->hash)
        free(hash->hash);
    free(hash);
}

inline void t_hash_list_free(t_hash *hash)
{
    t_hash  *next;

    while (hash)
    {
        next = hash->next;
        t_hash_free(hash);
        hash = next;
    }
}

inline void t_hash_decode_inputs(t_hash *hash)
{
    char    *tmp;

    e_flags flags = ssl.flags & e ? ssl.flags - e + d: ssl.flags;  //ssl.flags has d OR e

    // printf("ssl.dec_i_cmd.command_title: %s\n", ssl.dec_i_cmd.command_title);
    // printf("ssl.dec_i_cmd.command_data: %p\n", ssl.dec_i_cmd.command_data);
    while (hash)
    {
        if (!hash->error)
        {
            // printf("Hash(len=%d)= >%s<\n", hash->len, hash->msg);
            tmp = hash->msg;
            // hash->msg = (char *)base64(NULL, (Mem_8bits **)&hash->msg, hash->len, (Long_64bits *)&hash->len, d);

            hash->msg = ssl.dec_i_cmd.command_addr(
                ssl.dec_i_cmd.command_data,
                (Mem_8bits **)&tmp,
                hash->len,
                (Long_64bits *)&hash->len,
                flags
            );
            free(tmp);
        }
        hash = hash->next;
    }
}

inline void t_hash_encode_output(t_hash *hash)
{
    Mem_8bits   *tmp;
    e_flags     flags = ssl.flags & d ? ssl.flags - d + e: ssl.flags;  //ssl.flags has d OR e

    // printf("ssl.enc_o_cmd.command_title: %s\n", ssl.enc_o_cmd.command_title);
    // printf("ssl.enc_o_cmd.command_data: %p\n", ssl.enc_o_cmd.command_data);
    // printf("Encode output\n");
    while (hash)
    {
        if (!hash->error)
        {
            // printf("Hash(len=%d)= >%s<\n", hash->hashByteSz, hash->hash);
            tmp = hash->hash;

            // hash->hash = base64(NULL, &hash->hash, hash->hashByteSz, (Long_64bits *)&hash->hashByteSz, e);
            hash->hash = ssl.enc_o_cmd.command_addr(
                ssl.enc_o_cmd.command_data,
                (Mem_8bits **)&tmp,
                hash->hashByteSz,
                (Long_64bits *)&hash->hashByteSz,
                flags
            );
            free(tmp);
        }
        hash = hash->next;
    }
}

inline void t_hash_hashing(t_hash *hash)
{
    // printf("ssl.command.command_title: %s\n", ssl.command.command_title);
    // printf("ssl.command.command_data: %p\n", ssl.command.command_data);
    // printf("HASH\n");
    // EXECONES_COMMANDS commands doesn't need t_hash / any data input. Only one t_hash for printing
    if (ssl.command.command & EXECONES_COMMANDS)
    {
        if (hash)
        {
            t_hash_free(hash->next);
            hash->next = NULL;
        }
        else
            hash = add_thash_front();
    }

    while (hash)
    {
        // printf("Hash(len=%d)= >%s<\n", hash->len, hash->msg);
        if (!hash->error)
            hash->hash = ssl.command.command_addr(
                ssl.command.command_data,
                (Mem_8bits **)&hash->msg,
                hash->len,
                (Long_64bits *)&hash->hashByteSz,
                ssl.flags
            );
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
