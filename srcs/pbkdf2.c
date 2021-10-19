#include "ft_ssl.h"

// static Word_32bits   *HMAC_sha256(Mem_8bits *pwd, Word_32bits *key)
// {

//     // return ;
// }

Long_64bits     pbkdf2_sha256(Mem_8bits *pwd, Mem_8bits *s, int c)
{
    Word_32bits *dkn = NULL;
    // Word_32bits *dkn1;
    Mem_8bits   salt[KEY_byteSz];
    // ft_bzero(salt, KEY_byteSz);

    // Mem_8bits ipad[CHUNK_ByteSz];
    // Mem_8bits opad[CHUNK_ByteSz];

    printf("salt: %s\n", s);
    printBits(&s, LONG64_ByteSz);

    ft_memcpy(salt, &s, LONG64_ByteSz);
    printBits(salt, KEY_byteSz);

    endianReverse(salt, KEY_byteSz);
    printBits(salt, KEY_byteSz);

    // for (int i = 0; i < CHUNK_ByteSz; i++)
    // {
    //     ipad[i] = 0x36;
    //     opad[i] = 0x5c;
    // }

    // Word_32bits *tmp = ;

    // for (int i = 0; i < c; i++)
    // {
    //     // Word_32bits *dkn1 = HMAC_sha256(pwd, dkn);
    //     // dkn = 
    //     sha256_msg(&pwd);
    //     sha256_xor_32bits(dkn, dkn1, &dkn);
    // }


    // printf("Key generation: %lx\n", dkn);
    return 0;
}
