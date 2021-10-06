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

void    md5(t_hash *hash)
{
    t_md5   md5;

    md5.chunks = (Mem_8bits *)hash->msg;
    md5.chunksSz = (Long_64bits)ft_strlen(hash->msg);

    // printf("sizeof(int): %ld bytes\n", sizeof(int));
    // printf("sizeof(Mem_8bits): %ld bytes\n", sizeof(Mem_8bits));
    // printf("sizeof(Long_64bits): %ld bytes\n", sizeof(Long_64bits));
    // printf("Before memcpy msg: %s\n", chunks);
    // printf("Before memcpy len: %ld\n", chunksSz);
    // printf("Before memcpy hash: %s\n", chunks);

    printBits(md5.chunks, md5.chunksSz);
    padding(&md5.chunks, &md5.chunksSz);
    printBits(md5.chunks, md5.chunksSz);

    md5_load_sinus(&md5);
    // for (int i = 0; i < 64; i++)
    //     printf("k[%d] = 0x%lx\n", i, md5.sinus[i]);


    hash->hash = "262f5a26e266f5bcc9684e685a56c"; // Temporally
    hash->msg = (char *)md5.chunks;
    hash->len = (int)md5.chunksSz;
}
