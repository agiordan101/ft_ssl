#include "ft_ssl.h"

// void        split_3bytes(Mem_8bits **group, Mem_8bits *tmp)
// {
//     Mem_8bits b1 = *tmp;
//     Mem_8bits b2 = *(tmp + 1);
//     Mem_8bits b3 = *(tmp + 2);
//     // 00101011 11000101  10101000
//     // 001010 111100 010110 101000

//     printBits(tmp, 3);
//     *group[0] = b1 >> 2;
//     *group[1] = (b1 & 0b00000011) << 4 | b2 >> 4;
//     *group[2] = (b2 & 0b00001111) << 2 | b3 >> 6;
//     *group[3] = b3 & 0b00111111;
//     printBits(*group, 4);
// }

// void        split_3bytes(Mem_8bits **group, Mem_8bits b1, Mem_8bits b2, Mem_8bits b3)
// {
// }

// char        handle_last_block(Mem_8bits *tmp)
// {
// }

static inline int   base64ToInt(char num)
{
    if ('A' <= num && num <= 'Z')
        return num - 'A';
    if ('a' <= num && num <= 'z')
        return 26 + num - 'a';
    if ('0' <= num && num <= '9')
        return 52 + num - '0';
    if (num == '+')
        return 62;
    if (num == '/')
        return 62;
    if (num == '=')
        return 420;
    return -1;
}

static inline int   get_len_encoded(int len)
{
    return (int)(len / 3) * 4 + 4;
}

static inline int   get_len_decoded(Mem_8bits *msg, int len)
{
    if (msg[len - 1] == '=')
    {
        if (msg[--len - 1] == '=')
            return (int)(--len / 4) * 3 + 1;
        return (int)(len / 4) * 3 + 2;
    }
    return (int)(len / 4) * 3;
}

static void         encode(t_hash *hash)
{
    char        base[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Mem_8bits   group[4];
    Mem_8bits   b2;
    Mem_8bits   b3;

    // printBits(hash->msg, hash->len);
    hash->hashlen = get_len_encoded(hash->len);
    if (!(hash->hash = malloc(hash->hashlen * WORD_ByteSz)))
        freexit(EXIT_FAILURE);
    char *hash_p = (char *)hash->hash;

    // printf("hash->hashlen: %d\n", hash->hashlen);
    // printf("hash->len: %d\n", hash->len);
    char *msg_24bits_blocks_end = hash->msg + (hash->len - hash->len % 3) + 3;
    for (Mem_8bits *tmp = hash->msg; (char *)tmp < msg_24bits_blocks_end; tmp += 3)
    {
        b2 = (char *)(tmp + 1) < msg_24bits_blocks_end ? *(tmp + 1) : 0b0;
        b3 = (char *)(tmp + 2) < msg_24bits_blocks_end ? *(tmp + 2) : 0b0;
        // 00101011 11000101  10101000
        // 001010 111100 010110 101000
        group[0] = *tmp >> 2;
        group[1] = (*tmp & 0b00000011) << 4 | b2 >> 4;
        group[2] = (b2 & 0b00001111) << 2 | b3 >> 6;
        group[3] = b3 & 0b00111111;

        // printf("\nBits of group[4]:\n");
        // for (int i = 0; i < 4; i++)
        //     printBits(&group[i], 1);

        for (int i = 0; i < 4; i++)
            group[i] = base[group[i]];
        
        if (!b2)
            group[2] = '=';
        if (!b3)
            group[3] = '=';

        ft_memcpy(hash_p, (char *)group, 4);
        hash_p += 4;
        // printf("tmp: %p\n", tmp);
        // printf("msg_24bits_blocks_end: %p\n", msg_24bits_blocks_end);
    }
    // printBits(hash->hash, hash->hashlen);
}

static void         clean_base64(Mem_8bits **msg, int *len)
{
    char        base[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char        newmsg[*len];

    int newlen = 0;
    for (int i = 0; i < *len; i++)
    {
        if (base64ToInt((*msg)[i]) != -1)
            newmsg[newlen++] = (*msg)[i];
    }

    free(*msg);
    if (!(*msg = (char *)malloc(sizeof(char) * (newlen + 1))))
    (*msg)[newlen] = '\0';
    ft_memcpy(*msg, newmsg, newlen);
    *len = newlen;
}

static void         decode(t_hash *hash)
{
    Mem_8bits   group[4];
    Mem_8bits   decoded[3];

    // printBits(hash->msg, hash->len);
    clean_base64((Mem_8bits **)&hash->msg, &hash->len);

    // printBits(hash->msg, hash->len);
    // printf("get_len_decoded: %d\n", get_len_decoded(hash->msg, hash->len));
    hash->hashlen = get_len_decoded(hash->msg, hash->len);
    if (!(hash->hash = malloc(hash->hashlen * WORD_ByteSz)))
        freexit(EXIT_FAILURE);
    char *hash_p = (char *)hash->hash;
   
    for (Mem_8bits *tmp = hash->msg; (char *)tmp < hash->msg + hash->len; tmp += 4)
    {
        // 001010 111100 010110 101000
        // 00101011 11000101  10101000
        
        // group[0] = base64ToInt(tmp[0]);
        // group[1] = base64ToInt(tmp[1]);
        // group[2] = tmp[2] == '=' ? 0b0 : base64ToInt(tmp[2]);
        // group[3] = tmp[3] == '=' ? 0b0 : base64ToInt(tmp[3]);
        
        for (int i = 0; i < 4; i++)
            group[i] = tmp[i] == '=' ? 0b0 : base64ToInt(tmp[i]);

        // printBits(group, 4);
        decoded[0] = group[0] << 2 | group[1] >> 4;
        decoded[1] = group[1] << 4 | group[2] >> 2;
        decoded[2] = group[2] << 6 | group[3];
        // printBits(decoded, 3);

        ft_memcpy(hash_p, (char *)decoded, 3);
        hash_p += 3;
    }
    // printBits(hash->hash, hash->hashlen);
}

void        base64(t_hash *hash)
{
    if (ssl.flags & D)
        decode(hash);
    else
        encode(hash);
}
