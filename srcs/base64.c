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
void        split_3bytes(Mem_8bits **group, Mem_8bits b1, Mem_8bits b2, Mem_8bits b3)
{
    // 00101011 11000101  10101000
    // 001010 111100 010110 101000
    printBits(&b1, 1);
    printBits(&b2, 1);
    printBits(&b3, 1);
    *group[0] = b1 >> 2;
    *group[1] = (b1 & 0b00000011) << 4 | b2 >> 4;
    *group[2] = (b2 & 0b00001111) << 2 | b3 >> 6;
    *group[3] = b3 & 0b00111111;
    printBits(*group, 4);
}

char        handle_last_block(Mem_8bits *tmp)
{
}

void        base64(t_hash *hash)
{
    char        base[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Mem_8bits   group[4];

    printBits(hash->msg, hash->len);

    hash->hashlen = (hash->len / 3) * 4 + 4;
    if (!(hash->hash = malloc(hash->hashlen * WORD_ByteSz)))
        freexit(EXIT_FAILURE);
    
    char *hash_p = (char *)hash->hash;
    char *msg_24bits_blocks_end = hash->msg + (hash->hashlen - hash->hashlen % 3);
    // for (int i = 0; i < hash->hashlen; i += 3)
    for (Mem_8bits *tmp = hash->msg; (char *)tmp < msg_24bits_blocks_end; tmp += 3)
    {
        // split_3bytes(&group, hash->hash[i], hash->hash[i + 1], hash->hash[i + 2]);
        split_3bytes((Mem_8bits **)&group, *tmp, *(tmp + 1), *(tmp + 2));
        
        for (int i = 0; i < 4; i++)
            group[i] = base[group[i]];

        ft_memcpy(hash_p, (char *)group, 4);
        hash_p += 4;
    }
    printBits(hash->hash, hash->hashlen);
}
