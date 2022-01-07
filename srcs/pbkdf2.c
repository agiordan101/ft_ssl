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
    // // // key / pad length: SHA256_byteSz (Not anymore)
    // key / pad length: CHUNK_byteSz
    int         pad_byteSz = CHUNK_ByteSz;
    int         concatByteSz = pad_byteSz + to_concatByteSz;
    Mem_8bits   *concat = ft_memnew(concatByteSz);   // Need to be malloc for sha256() padding.
    Mem_8bits   *hash_ret;

    // printf("\n\t[XOR_concat_hash begin]\n");
    // // printMemHex(key, SHA256_byteSz, "Key to XOR");
    // printMemHex(pad, pad_byteSz, "Padding");
    // printMemHex(to_concat, to_concatByteSz, "to_concat");
    // sha256_xor_8bits(key, pad, &key);
    // // printMemHex(key, SHA256_byteSz, "K ^ pad");
    // ft_memcpy(concat, key, SHA256_byteSz);
    // ft_memcpy(concat + SHA256_byteSz, to_concat, to_concatByteSz);
    // // printMemHex(concat, concatByteSz, "K ^ pad || concat");

    ft_memcpy(concat, pad, pad_byteSz);
    ft_memcpy(concat + pad_byteSz, to_concat, to_concatByteSz);
    // printMemHex(concat, concatByteSz, "K ^ pad || concat");

    hash_ret = sha256((Mem_8bits **)&concat, concatByteSz, NULL, 0);
    // printMemHex(hash_ret, SHA256_byteSz, "h(K ^ pad || concat)");
    // printf("\n\t[XOR_concat_hash end]\n");
    free(concat);
    (void)key;
    return hash_ret;
}

Mem_8bits   *pbkdf2_sha256_hmac(Mem_8bits *key, int keyByteSz, Mem_8bits *msg, int msgByteSz)
{
    // static Mem_8bits    ipad[SHA256_byteSz] = {
    //     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    //     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    //     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    //     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
    // };
    // static Mem_8bits    opad[SHA256_byteSz] = {
    //     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    //     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    //     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    //     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
    // };
    Mem_8bits   ipad[CHUNK_ByteSz];
    Mem_8bits   opad[CHUNK_ByteSz];
    for (int i = 0; i < CHUNK_ByteSz; i++)
    {
        ipad[i] = 0x36;
        opad[i] = 0x5C;
    }

    // printf("\n[pbkdf2_sha256_hmac begin]\n");
    // // printMemHex(key, keyByteSz, "Key");
    // // printMemHex(msg, msgByteSz, "Msg");

    key = hmac_init_key_SHA256_byteSz(key, keyByteSz);  // Malloc a key
    // printMemHex(key, SHA256_byteSz, "Init key");

    for (int i = 0; i < keyByteSz; i++)
    {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    Mem_8bits *sha256_res = XOR_concat_hash(ft_memdup(key, SHA256_byteSz), ipad, msg, msgByteSz);
    Mem_8bits *hmac_res = XOR_concat_hash(key, opad, sha256_res, SHA256_byteSz);
    // // printMemHex(sha256_res, SHA256_byteSz, "ihash");
    free(sha256_res);
    free(key);

    // printMemHex(hmac_res, SHA256_byteSz, "hmac result");
    // printf("\n[pbkdf2_sha256_hmac end]\n");
    return hmac_res;
}

Mem_8bits   *pbkdf2_sha256_prfxors(Mem_8bits *pwd, int pwdByteSz, Mem_8bits *salt, int c, Word_32bits bloci)
{
    Mem_8bits   *sha_curr;
    Mem_8bits   *sha_xor;
    Mem_8bits   *sha_prev = ft_memnew(SHA256_byteSz);

    // Set U0 = Salt || bloci_32bits_Big_Endian
    endianReverse((Mem_8bits *)&bloci, WORD32_ByteSz);
    ft_memcpy(sha_prev, salt, KEY_byteSz);
    ft_memcpy(sha_prev + KEY_byteSz, (Mem_8bits *)&bloci, WORD32_ByteSz);
    sha_xor = pbkdf2_sha256_hmac(pwd, pwdByteSz, sha_prev, KEY_byteSz + WORD32_ByteSz);

    // // printMemHex(salt, KEY_byteSz, "salt");
    // // printMemHex((Mem_8bits *)&bloci, WORD32_ByteSz, "bloci_32bits_Big_Endian");
    // printMemHex(sha_prev, SHA256_byteSz, "U0");

    for (int i = 1; i < c; i++)
    {
        sha_curr = pbkdf2_sha256_hmac(pwd, pwdByteSz, sha_prev, SHA256_byteSz);
        // // printMemHex(sha_curr, SHA256_byteSz, "sha256 hmac result");

        // XOR current sha with dynamic var sha_xor
        sha256_xor_8bits(sha_xor, sha_curr, &sha_xor);

        ft_memcpy(sha_prev, sha_curr, SHA256_byteSz);
        free(sha_curr);

        // printMemHex(sha_xor, SHA256_byteSz, "Ui");
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
    Mem_8bits *salt_bytestream = ft_memdup((Mem_8bits *)&salt, KEY_byteSz);
    endianReverse(salt_bytestream, KEY_byteSz);

    // // printMemHex(pwd, SHA256_byteSz, "pwd");
    // // printMemHex(salt_bytestream, KEY_byteSz, "salt");
    
    Mem_8bits *key = pbkdf2_sha256_prfxors(pwd, ft_strlen(pwd), salt_bytestream, c, 1);

    endianReverse(key, KEY_byteSz);
    // printMemHex(key, SHA256_byteSz, "PBKDF2 out");
    return *((Key_64bits *)key);
}
