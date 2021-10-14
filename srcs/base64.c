#include "ft_ssl.h"

void        base64(t_hash *hash)
{
    hash->hash = hash->msg;
    hash->hashlen = hash->len;
}
