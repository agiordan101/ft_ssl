#include "ft_ssl.h"

static Mem_8bits    *hmac_init_key_SHA256_byteSz(Mem_8bits *key, int keyByteSz)
{
    Mem_8bits *tmp;

    // Create new key
    if (keyByteSz > SHA256_byteSz)
    {
        // Hash old key to have keyByteSz = SHA256_ByteSz
        tmp = ft_memdup(key, keyByteSz);    // Duplicate before sha256
        key = sha256(&tmp, keyByteSz, (Long_64bits *)&keyByteSz, e);
    }
    else
    {
        // Pad old key with zeros until keyByteSz = SHA256_ByteSz
        tmp = key;
        key = ft_memnew(SHA256_byteSz);
        ft_memcpy(key, tmp, keyByteSz);
    }
    return key;
}

Mem_8bits   *XOR_concat_hash(Mem_8bits *key, Mem_8bits *pad, Mem_8bits *to_concat, int to_concatByteSz)
{
    // key / pad length: SHA256_byteSz
    int         concatByteSz = SHA256_byteSz + to_concatByteSz;
    Mem_8bits   concat[concatByteSz];

    printf("XOR_concat_hash:\n");
    sha256_xor_8bits(key, pad, &key);
    printMemHex(key, SHA256_byteSz);

    ft_memcpy(concat, key, SHA256_byteSz);
    ft_memcpy(concat + SHA256_byteSz, to_concat, to_concatByteSz);
    printMemHex(concat, concatByteSz);

    return sha256((Mem_8bits **)&concat, concatByteSz, NULL, 0);
}

Mem_8bits   *pbkdf2_sha256_hmac(Mem_8bits *key, int keyByteSz, Mem_8bits *msg, int msgByteSz)
{
    Mem_8bits           *sha256_res;
    static Mem_8bits    ipad[SHA256_byteSz] = {
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
    };
    static Mem_8bits    opad[SHA256_byteSz] = {
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
    };

    printMemHex(key, keyByteSz);
    printMemHex(msg, msgByteSz);

    key = hmac_init_key_SHA256_byteSz(key, keyByteSz);
    printMemHex(key, SHA256_byteSz);

    sha256_res = XOR_concat_hash(key, ipad, msg, msgByteSz);
    sha256_res = XOR_concat_hash(key, ipad, sha256_res, SHA256_byteSz);

    printMemHex(sha256_res, SHA256_byteSz);
    return sha256_res;
}

Mem_8bits   *pbkdf2_sha256_prfxors(Mem_8bits *pwd, int pwdByteSz, Key_64bits salt, int c, Word_32bits bloci)
{
    Mem_8bits   *sha_curr;
    Mem_8bits   *sha_xor = ft_memnew(SHA256_byteSz);
    Mem_8bits   *sha_prev = ft_memnew(SHA256_byteSz);
    ft_memcpy(sha_prev, &salt, KEY_byteSz);
    ft_memcpy(sha_prev + KEY_byteSz, (Mem_8bits *)&bloci, WORD32_ByteSz);
    printf("First sha: salt + i:\n");
    printMemHex(sha_prev, SHA256_byteSz);

    for (int i = 0; i < c; i++)
    {
        sha_curr = pbkdf2_sha256_hmac(pwd, pwdByteSz, sha_prev, SHA256_byteSz);
        printf("\n\n\nU%d = \n", i);
        printMemHex(sha_curr, SHA256_byteSz);

        // XOR current sha with dynamic var sha_xor
        if (i)
            sha256_xor_8bits(sha_xor, sha_curr, &sha_xor);
        else
            ft_memcpy(sha_xor, sha_curr, SHA256_byteSz);

        ft_memcpy(sha_prev, sha_curr, SHA256_byteSz);
        free(sha_curr);
    }
    free(sha_prev);
    return sha_xor;
}

Key_64bits  pbkdf2_sha256(Mem_8bits *pwd, Key_64bits salt, int c)
/*

    Desired output length: KEY_byteSz = 8 bytes / 64 bits

    Algorithm:

        DK = PBKDF2(PRF, Password, Salt, c, dkLen)
        DK = T1 || T2 || ... || Tdklen/hlen

        With:
            dklen = Output key size of pbkdf2
            hlen = hash_func output hash size
            Ti = F(Password, Salt, c, i)
            Ti = U1 ^ U2 ^ ... ^ Uc

            With:
                U1 = PRF(Password, Salt || INT_32_BE(i))
                U2 = PRF(Password, U1)
                ...
                Uc = PRF(Password, Uc-1)
    
    With sha256 as pseudo random function (PRF),
    hash output length is greater than the desired key length: 256 > 64 (bits)
    Conclusion: T1 || T2 || ... || Tdklen/hlen  =>  T1 & (1 << 65 - 1)

*/
{
    // int     pwdlen = ft_strlen(pwd);

    // printf("\nPBKDF2 START\n");

    // Mem_8bits *key = pbkdf2_sha256_prfxors(pwd, salt, c, 0);
    // printf("pbkdf2_sha256:\tkey: %s\n");
    // printMemHex(key, SHA256_byteSz);
    // return *((Key_64bits *)key);
    Mem_8bits *key = pbkdf2_sha256_prfxors(pwd, ft_strlen(pwd), salt, c, 0);
    endianReverse(key, KEY_byteSz);
    return *((Key_64bits *)key);
}
