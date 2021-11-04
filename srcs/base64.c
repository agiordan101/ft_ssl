#include "ft_ssl.h"

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
    return (int)(len / 3) * 4 + (len % 3 ? 4 : 0);
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
    hash->hashWordSz = get_len_encoded(hash->len);
    // if (!(hash->hash = malloc(hash->hashWordSz * WORD_ByteSz)))
    //     malloc_failed("Unable to malloc hash in base64 encode() function.\n");
    hash->hash = (Word_32bits *)ft_memnew(hash->hashWordSz * WORD_ByteSz);
    char *hash_p = (char *)hash->hash;

    // Padding to the next 24bits block of memory
    char *msg_24bits_blocks_end = hash->msg + hash->len + (hash->len % 3 ? 3 - hash->len % 3 : 0);
    for (Mem_8bits *tmp = hash->msg; (char *)tmp < msg_24bits_blocks_end; tmp += 3)
    {
        b2 = (char *)(tmp + 1) < msg_24bits_blocks_end ? *(tmp + 1) : 0b0;
        b3 = (char *)(tmp + 2) < msg_24bits_blocks_end ? *(tmp + 2) : 0b0;
        // printf("\nBits begin loop:\n");
        // printBits(tmp, 1);
        // printBits(&b2, 1);
        // printBits(&b3, 1);
        // 00101011 11000101  10101000
        // 001010 111100 010110 101000
        group[0] = *tmp >> 2;
        group[1] = (*tmp & 0b00000011) << 4 | b2 >> 4;
        group[2] = (b2 & 0b00001111) << 2 | b3 >> 6;
        group[3] = b3 & 0b00111111;

        for (int i = 0; i < 4; i++)
            group[i] = (Mem_8bits)base[group[i]];
        
        if (!b2)
            group[2] = '=';
        if (!b3)
            group[3] = '=';

        // printf("Bits of group[4] end loop:\n");
        // for (int i = 0; i < 4; i++)
        //     printBits((Mem_8bits *)&group[i], 1);

        ft_memcpy(hash_p, (char *)group, 4);
        hash_p += 4;
        // printf("tmp: %p\n", tmp);
        // printf("tmp: %p\n", tmp);
        // printf("msg_24bits_blocks_end: %p\n", msg_24bits_blocks_end);
    }
    // printBits(hash->hash, hash->hashWordSz);
}

static void         clean_base64(Mem_8bits **msg, int *len)
{
    char        base[65] = BASE64;
    char        newmsg[*len];

    // printf("msg: %s\n", *msg);
    int newlen = 0;
    for (int i = 0; i < *len; i++)
    {
        if (base64ToInt((*msg)[i]) != -1)
            newmsg[newlen++] = (*msg)[i];
    }

    free(*msg);
    // if (!(*msg = (char *)malloc(sizeof(char) * (newlen + 1))))
    //     malloc_failed("Unable to malloc msg in base64 clean_base64() function\n");
    // (*msg)[newlen] = '\0';
    // ft_memcpy(*msg, newmsg, newlen);
    *msg = ft_memdup(newmsg, newlen);
    *len = newlen;
    // printf("msg clean: %s\n", *msg);
}

static void         decode(t_hash *hash)
{
    Mem_8bits   group[4];
    Mem_8bits   decoded[3];

    // printBits(hash->msg, hash->len);
    clean_base64((Mem_8bits **)&hash->msg, &hash->len);

    // printBits(hash->msg, hash->len);
    // printf("get_len_decoded: %d\n", get_len_decoded(hash->msg, hash->len));
    hash->hashWordSz = get_len_decoded(hash->msg, hash->len);
    // if (!(hash->hash = malloc(hash->hashWordSz * WORD_ByteSz)))
    //     malloc_failed("Unable to malloc hash in base64 decode() function\n");
    hash->hash = (Word_32bits *)ft_memnew(hash->hashWordSz * WORD_ByteSz);
    char *hash_p = (char *)hash->hash;
   
    for (Mem_8bits *tmp = hash->msg; (char *)tmp < hash->msg + hash->len; tmp += 4)
    {
        // 001010 111100 010110 101000
        // 00101011 11000101  10101000

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
    // printBits(hash->hash, hash->hashWordSz);
}

void                base64(t_hash *hash)
{
    // printf("hash->msg: %s\n", hash->msg);
    if (ssl.flags & D)
        decode(hash);
    else
        encode(hash);
}
