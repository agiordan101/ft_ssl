#include "ft_ssl.h"

void    md5_failure(char *error_msg)
{
    ft_putstr(error_msg);
    exit(EXIT_FAILURE);
}

void    md5_load_sinus(t_md5 *md5)
{
    Word_32bits *k = md5->sinus;

    for (int i = 0; i < 64; i++)
        k[i] = (int)(ft_fabs(sin(i + 1)) * INT_MAX);
}

void    hash_chunk()
{

}

void    md5(t_hash *hash)
{
    t_md5   md5;

    md5.chunks = (Mem_8bits *)hash->msg;
    md5.chunksSz = (Long_64bits)ft_strlen(hash->msg);

    // printf("sizeof(int): %ld bytes\n", sizeof(int));
    // printf("sizeof(Mem_8bits): %ld bytes\n", sizeof(Mem_8bits));
    // printf("sizeof(Long_64bits): %ld bytes\n", sizeof(Long_64bits));
    printf("sizeof(Word_32bits): %ld bytes\n", sizeof(Word_32bits));
    printf("CHUNK_ByteSz: %ld bytes\n", CHUNK_ByteSz);
    // printf("Before memcpy msg: %s\n", chunks);
    // printf("Before memcpy len: %ld\n", chunksSz);
    // printf("Before memcpy hash: %s\n", chunks);

    printBits(md5.chunks, md5.chunksSz);
    padding(&md5.chunks, &md5.chunksSz);
    printBits(md5.chunks, md5.chunksSz);

    md5_load_sinus(&md5);
    // for (int i = 0; i < 64; i++)
    //     printf("k[%d] = 0x%lx\n", i, md5.sinus[i]);

    Word_32bits h0 = 0x67452301;
    Word_32bits h1 = 0xEFCDAB89;
    Word_32bits h2 = 0x98BADCFE;
    Word_32bits h3 = 0x10325476;

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

    hash->hash = "262f5a26e266f5bcc9684e685a56c"; // Temporally
    hash->msg = (char *)md5.chunks;
    hash->len = (int)md5.chunksSz;
}
