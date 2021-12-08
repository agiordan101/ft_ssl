// #include "ft_ssl.h"

// Mem_8bits     *pbkdf2_sha256(Mem_8bits *pwd, Mem_8bits *salt, int c)
// /*
//     Desired output length: KEY_byteSz = 8 bytes / 64 bits

//     Algorithm:

//     key = (U1 ^ U2 ^ ... ^ Uc) & 0xffffffffffffffff

//     U1 = sha256(pwd, salt)
//     U2 = sha256(pwd, U1)
//     ...
//     Uc = sha256(pwd, Uc-1)
// */
// {
//     // printf("\nPBKDF2 START\n");

//     int         pwdlen = ft_strlen(pwd);
//     int         concatlen = pwdlen + SHA256_byteSz;
//     Mem_8bits   *concat = ft_memnew(concatlen);

//     Mem_8bits   *key = ft_memnew(SHA256_byteSz);
//     ft_memcpy(key, salt, KEY_byteSz);

//     Mem_8bits   sha_prev[SHA256_byteSz];
//     Mem_8bits   sha_curr[SHA256_byteSz];

//     // printBits(salt, KEY_byteSz);

//     for (int i = 0; i < c; i++)
//     {
//         ft_memcpy(sha_prev, key, SHA256_byteSz);

//         ft_memcpy(concat, pwd, pwdlen);
//         ft_memcpy(concat + pwdlen, sha_prev, SHA256_byteSz);

//         // printf("\nconcat: \n");
//         // printBits(concat, concatlen);

//         sha256_msg((Mem_8bits **)&concat, concatlen, (Mem_8bits *)sha_curr);
//         if (i)
//             sha256_xor_8bits(sha_prev, sha_curr, (Mem_8bits **)&key);
//         else
//             ft_memcpy(key, sha_curr, SHA256_byteSz);

//         // printf("key: \n");
//         // printBits(key, SHA256_byteSz);
//     }

//     free(concat);
//     ft_bzero(key + KEY_byteSz, SHA256_byteSz - KEY_byteSz);
//     // printBits(key, KEY_byteSz);
//     return key;
// }
