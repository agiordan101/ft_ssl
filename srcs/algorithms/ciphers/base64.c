#include "ft_ssl.h"

static inline int   base64_to_bin(char num)
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
        return 63;
    if (num == '=')
        return 420;
    return -1;
}

static inline void  bin_to_base64(Mem_8bits *bin, int byteSz)
{
    static char     base[65] = BASE64_BASE;

    for (int i = 0; i < byteSz; i++)
        bin[i] = (Mem_8bits)base[bin[i]];
}

static void         clean_base64(Mem_8bits *msg, Long_64bits *len)
{
    int         newlen = 0;

    for (int i = 0; i < *len; i++)
        if (base64_to_bin(msg[i]) != -1)
            msg[newlen++] = msg[i];

    ft_bzero(msg + newlen, *len - newlen);
    *len = newlen;
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

static inline void  split_3to4bytes(Mem_8bits b1, Mem_8bits b2, Mem_8bits b3, Mem_8bits *res)
{
    // Transform: 00101011 11000101  10101000
    // Into     : 001010 111100 010110 101000
    res[0] = b1 >> 2;
    res[1] = (b1 & 0b00000011) << 4 | b2 >> 4;
    res[2] = (b2 & 0b00001111) << 2 | b3 >> 6;
    res[3] = b3 & 0b00111111;
}

static Mem_8bits    *encode(Mem_8bits *plaintext, Long_64bits ptByteSz, Long_64bits *ctByteSz)
{
    int         hashlen = get_len_encoded(ptByteSz);
    Mem_8bits   bytecode[4];
    Mem_8bits   *hash = ft_memnew(hashlen);
    Mem_8bits   *hash_tmp = hash;

    Mem_8bits   *pt_tmp = plaintext;
    Mem_8bits   *pt_end = plaintext + ptByteSz;
    while (pt_tmp + 2 < pt_end)
    {
        split_3to4bytes(*pt_tmp, *(pt_tmp + 1), *(pt_tmp + 2), (Mem_8bits *)bytecode);

        bin_to_base64(bytecode, 4);

        ft_memcpy(hash_tmp, (char *)bytecode, 4);
        pt_tmp += 3;
        hash_tmp += 4;
    }

    if (pt_tmp < pt_end)
    {
        split_3to4bytes(
            *pt_tmp,
            pt_tmp + 1 < pt_end ? *(pt_tmp + 1) : 0,
            pt_tmp + 2 < pt_end ? *(pt_tmp + 2) : 0,
            (Mem_8bits *)bytecode
        );
        bin_to_base64(bytecode, 4);
        if (pt_tmp + 1 >= pt_end)
            bytecode[2] = '=';
        if (pt_tmp + 2 >= pt_end)
            bytecode[3] = '=';
        ft_memcpy(hash_tmp, (char *)bytecode, 4);
    }

    if (ctByteSz)
        *ctByteSz = hashlen;
    return hash;
}

static Mem_8bits    *decode(Mem_8bits *ciphertext, Long_64bits ctByteSz, Long_64bits *ptByteSz)
{
    clean_base64(ciphertext, &ctByteSz);
    int         hashlen = get_len_decoded(ciphertext, ctByteSz);
    Mem_8bits   bytecode[4];
    Mem_8bits   *hash = ft_memnew(hashlen);
    Mem_8bits   *hash_tmp = hash;

    Mem_8bits   *pt_end = ciphertext + ctByteSz;
    for (Mem_8bits *pt_tmp = ciphertext; pt_tmp < pt_end; pt_tmp += 4)
    {
        for (int i = 0; i < 4; i++)
            bytecode[i] = (pt_tmp[i] == '=') ? 0b0 : base64_to_bin(pt_tmp[i]);

        hash_tmp[0] = bytecode[0] << 2 | bytecode[1] >> 4;
        if (*(pt_tmp + 2) != '=')
            hash_tmp[1] = bytecode[1] << 4 | bytecode[2] >> 2;
        if (*(pt_tmp + 3) != '=')
            hash_tmp[2] = bytecode[2] << 6 | bytecode[3];
        hash_tmp += 3;
    }

    if (ptByteSz)
        *ptByteSz = hashlen;
    return hash;
}

Mem_8bits           *base64(Mem_8bits *input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags way)
{
    if (way & e)
        return encode(input, iByteSz, oByteSz);
    else
        return decode(input, iByteSz, oByteSz);
}

Mem_8bits           *cmd_wrapper_base64(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags)
{
    (void)cmd_data;          // No data needed
    return base64(*input, iByteSz, oByteSz, flags);
}
