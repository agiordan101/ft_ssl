#include "ft_ssl.h"

Len_64bits   extend_until_chunk_end(Mem_8bits **data, Len_64bits byteSz)
{
    Len_64bits extend_byteSz = byteSz - byteSz % CHUNK_ByteSz + CHUNK_ByteSz;
    Mem_8bits *extend;

    if (!(extend = (Mem_8bits *)malloc(sizeof(Mem_8bits) * extend_byteSz)))
        md5_failure("Malloc failed.");
    ft_bzero(extend, extend_byteSz); //bzero after data until extend_byteSz % mod == 0
    ft_memcpy(extend, *data, byteSz);
    free(*data);
    *data = extend;
    return extend_byteSz;
}

Mem_8bits    *padding(Mem_8bits **data, Len_64bits byteSz)
{
    Len_64bits extend_byteSz = extend_until_chunk_end(data, byteSz);
    // printf("data: %s\n", *data);
    printf("byteSz: %lu\n", byteSz);
    printf("extend_byteSz: %lu\n", extend_byteSz);
    (*data)[byteSz] = '-';
    (*data)[extend_byteSz - LEN_ByteSz] = byteSz;
}
