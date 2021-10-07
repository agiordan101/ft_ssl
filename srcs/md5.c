#include "ft_ssl.h"

void    md5_failure(char *error_msg)
{
    ft_putstr(error_msg);
    exit(EXIT_FAILURE);
}

void    md5_load_sinus(t_md5 *md5)
{
    Word_32bits *k = md5->sinus;

    // printf("UINT_MAX: %ld\n", UINTMAX);
    for (int i = 0; i < 64; i++)
    {
        k[i] = (Word_32bits)(ft_fabs(sin(i + 1)) * UINTMAX);
        // printf("floor(abs(sin(%d + 1) * UINTMAX)) = %ld / k[%d]=%x\n", i, (Word_32bits)ft_fabs(sin(i + 1) * UINTMAX), i, k[i]);
    }
}

void    init_md5(t_md5 *md5)
{
    // md5_load_sinus(&md5);
    // for (int i = 0; i < 64; i++)
    //     printf("k[%d] = 0x%x\n", i, md5.sinus[i]);
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
    ft_memcpy(md5->sinus, sinus, 64 * WORD_ByteSz);

    Word_32bits constants[64] = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };
    ft_memcpy(md5->constants, constants, 64 * WORD_ByteSz);

    md5->hash[0] = 0x67452301;
    md5->hash[1] = 0xEFCDAB89;
    md5->hash[2] = 0x98BADCFE;
    md5->hash[3] = 0x10325476;
    printf("\n\nHASH TIME\n");
    printHash(md5->hash);
    // printHex((Mem_8bits *)md5->hash, 4 * WORD_ByteSz);
    // printBits((Mem_8bits *)md5->hash, 4 * WORD_ByteSz);
    // exit(0);
}

void    hash_chunk()
{

}

void    md5(t_hash *hash)
{
    t_md5   md5;

    md5.chunks = (Mem_8bits *)hash->msg;
    md5.chunksSz = (Long_64bits)ft_strlen(hash->msg);

    printf("sizeof(int): %ld bytes\n", sizeof(int));
    printf("sizeof(Mem_8bits): %ld bytes\n", sizeof(Mem_8bits));
    printf("sizeof(Long_64bits): %ld bytes\n", sizeof(Long_64bits));
    printf("sizeof(float): %ld bytes\n", sizeof(float));
    printf("sizeof(double): %ld bytes\n", sizeof(double));
    printf("sizeof(Word_32bits): %ld bytes\n", sizeof(Word_32bits));

    printBits(md5.chunks, md5.chunksSz);
    padding(&md5.chunks, &md5.chunksSz);
    printBits(md5.chunks, md5.chunksSz);

    init_md5(&md5);

    printf("CHUNK_ByteSz: %ld bytes\n", CHUNK_ByteSz);
    Mem_8bits *chunk = md5.chunks;
    while (chunk < md5.chunks + md5.chunksSz)
    {
        Word_32bits words[16];
        ft_memcpy(words, chunk, CHUNK_ByteSz);

        hash_chunk();
        for (int i = 0; i < 16; i++)
            printf("words[%d] = 0x%x\n", i, words[i]);

        chunk = chunk + CHUNK_ByteSz;
    }

    // for (int i = 0; i < 4; i++)
    // {
    //     // printf("md5.hash + i * WORD_ByteSz: 0x%x\n", md5.hash + i * WORD_ByteSz);
    //     // // printf("md5.hash[i]: 0x%x\n", md5.hash[i]);
    //     printf("md5.hash[%d] before: %x\n", i, md5.hash[i]);
    //     // printBits((Mem_8bits *)&md5.hash[i], WORD_ByteSz);
    //     printHex((Mem_8bits *)&md5.hash[i], WORD_ByteSz);
    //     // printf("md5.hash[i] *: %p\n", (Mem_8bits *)(md5.hash) + i * WORD_ByteSz);
    //     littleEndian((Mem_8bits *)&md5.hash[i], WORD_ByteSz);
    //     // printBits((Mem_8bits *)&md5.hash[i], WORD_ByteSz);
    //     printHex((Mem_8bits *)&md5.hash[i], WORD_ByteSz);
    //     printf("\n");
    //     // printf("md5.hash[i] after: %x\n", md5.hash[i]);
    // }
    printHash(md5.hash);

    ft_memcpy(hash->hash, md5.hash, 4 * WORD_ByteSz);
    // hash->msg = (char *)md5.chunks;
    // hash->len = (int)md5.chunksSz;
}
