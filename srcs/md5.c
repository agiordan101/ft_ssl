#include "ft_ssl.h"

static void init_md5(t_md5 *md5, Mem_8bits *chunks, Long_64bits chunksSz)
{
    md5->chunks = chunks;
    md5->chunksSz = chunksSz;
    md5->hash[0] = 0x67452301;
    md5->hash[1] = 0xEFCDAB89;
    md5->hash[2] = 0x98BADCFE;
    md5->hash[3] = 0x10325476;

    Word_32bits sinus[64] = {
        0xd76aa478,	0xe8c7b756,	0x242070db,	0xc1bdceee,	0xf57c0faf,	0x4787c62a,	0xa8304613,	0xfd469501,
        0x698098d8,	0x8b44f7af,	0xffff5bb1,	0x895cd7be,	0x6b901122,	0xfd987193,	0xa679438e,	0x49b40821,
        0xf61e2562,	0xc040b340,	0x265e5a51,	0xe9b6c7aa,	0xd62f105d,	0x02441453,	0xd8a1e681,	0xe7d3fbc8,
        0x21e1cde6,	0xc33707d6,	0xf4d50d87,	0x455a14ed,	0xa9e3e905,	0xfcefa3f8,	0x676f02d9,	0x8d2a4c8a,
        0xfffa3942,	0x8771f681,	0x6d9d6122,	0xfde5380c,	0xa4beea44,	0x4bdecfa9,	0xf6bb4b60,	0xbebfbc70,
        0x289b7ec6,	0xeaa127fa,	0xd4ef3085,	0x04881d05,	0xd9d4d039,	0xe6db99e5,	0x1fa27cf8,	0xc4ac5665,
        0xf4292244,	0x432aff97,	0xab9423a7,	0xfc93a039,	0x655b59c3,	0x8f0ccc92,	0xffeff47d,	0x85845dd1,
        0x6fa87e4f,	0xfe2ce6e0,	0xa3014314,	0x4e0811a1,	0xf7537e82,	0xbd3af235,	0x2ad7d2bb,	0xeb86d391
    };
    ft_memcpy(md5->sinus, sinus, 64 * WORD32_ByteSz);

    Word_32bits constants[64] = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };
    ft_memcpy(md5->constants, constants, 64 * WORD32_ByteSz);
}

static void hash_chunk(t_md5 *md5, Word_32bits *chunk)
{
    Word_32bits a = md5->hash[0];
    Word_32bits b = md5->hash[1];
    Word_32bits c = md5->hash[2];
    Word_32bits d = md5->hash[3];
    Word_32bits tmp;

    Word_32bits ft;         // 1 of 4 non linear fonction
    Word_32bits words[16];  // Chunk msg
    int         g;          // Word's index in chunk msg

    ft_memcpy(words, chunk, CHUNK_ByteSz);
    for (int i = 0; i < 64; i++)
    {
        if (i < 16)
        {
            ft = (b & c) | ((~b) & d);
            g = i;
        }
        else if (i < 32)
        {
            ft = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48)
        {
            ft = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        }
        else
        {
            ft = c ^ (b | (~d));
            g = (7 * i) % 16;
        }
        tmp = d;
        d = c;
        c = b;
        b += rotL((a + ft + md5->sinus[i] + words[g]), md5->constants[i]);
        a = tmp;
    }
    md5->hash[0] += a;
    md5->hash[1] += b;
    md5->hash[2] += c;
    md5->hash[3] += d;
}

Mem_8bits   *md5(Mem_8bits **plaintext, Long_64bits ptByteSz, e_flags way)
{
    t_md5   md5;

    md_padding(plaintext, &ptByteSz, 0);
    init_md5(&md5, *plaintext, ptByteSz);
    // printBits(md5.chunks, md5.chunksSz);

    Word_32bits *chunks = (Word_32bits *)md5.chunks;
    Word_32bits *chunk = chunks;
    while (chunk < chunks + md5.chunksSz / WORD32_ByteSz)
    {
        hash_chunk(&md5, chunk);
        chunk += CHUNK_ByteSz / WORD32_ByteSz;
    }

    // Restore right endianness order
    // for (int i = 0; i < ptSz; i++)
    //     endianReverse((Mem_8bits *)(ciphertext + i), LONG64_ByteSz);

    (void)way;
    return ft_memdup((Mem_8bits *)md5.hash, MD5_byteSz);
}
