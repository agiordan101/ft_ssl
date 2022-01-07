#include "ft_ssl.h"

static inline Mem_8bits *hmac_init_key_SHA256_byteSz(Mem_8bits *key, int keyByteSz, Mem_8bits *keypad)
{
    if (keyByteSz > SHA256_byteSz)
    {
        // Hash old key to have keyByteSz = SHA256_ByteSz
        Mem_8bits *tmp = ft_memdup(key, keyByteSz);    // Duplicate before sha256
        key = sha256(&tmp, keyByteSz, NULL, 0);
        ft_memcpy(keypad, key, SHA256_byteSz);
        free(tmp);
        free(key);
    }
    else
    {
        // Pad old key with zeros until keyByteSz = SHA256_ByteSz
        ft_bzero(keypad, SHA256_byteSz);
        ft_memcpy(keypad, key, keyByteSz);
    }
    return key;
}

static Mem_8bits    *concat_and_hash(Mem_8bits *keyxor, Mem_8bits *to_concat, int to_concatByteSz)
{
    /*
        Concat key xored with a msg and hash the result
        key / ipad / opad length: CHUNK_byteSz (Depending on PRF block size: sha256 -> chunks of 512bits)
    */
    int         concatByteSz = CHUNK_ByteSz + to_concatByteSz;
    Mem_8bits   *concat = ft_memnew(concatByteSz);   // Need to be malloc for sha256() function

    ft_memcpy(concat, keyxor, CHUNK_ByteSz);
    ft_memcpy(concat + CHUNK_ByteSz, to_concat, to_concatByteSz);
    // printMemHex(concat, concatByteSz, "K ^ pad || concat");

    Mem_8bits *hash_ret = sha256((Mem_8bits **)&concat, concatByteSz, NULL, 0);
    free(concat);
    // printMemHex(hash_ret, SHA256_byteSz, "h(K ^ pad || concat)");
    return hash_ret;
}

Mem_8bits           *pbkdf2_sha256_hmac(Mem_8bits *key, int keyByteSz, Mem_8bits *msg, int msgByteSz)
{
    Mem_8bits   keypad[CHUNK_ByteSz];
    Mem_8bits   ipad[CHUNK_ByteSz];
    Mem_8bits   opad[CHUNK_ByteSz];
    for (int i = 0; i < CHUNK_ByteSz; i++)
    {
        ipad[i] = 0x36;
        opad[i] = 0x5C;
    }

    hmac_init_key_SHA256_byteSz(key, keyByteSz, keypad);  // Malloc a key
    for (int i = 0; i < keyByteSz; i++)
    {
        ipad[i] ^= keypad[i];
        opad[i] ^= keypad[i];
    }
    // printMemHex(ipad, CHUNK_ByteSz, "K ^ ipad");
    // printMemHex(opad, CHUNK_ByteSz, "K ^ opad");

    Mem_8bits *sha256_res = concat_and_hash(ipad, msg, msgByteSz);
    Mem_8bits *hmac_res = concat_and_hash(opad, sha256_res, SHA256_byteSz);
    free(sha256_res);

    // printMemHex(hmac_res, SHA256_byteSz, "hmac result (ohash)");
    return hmac_res;
}

static Mem_8bits    *pbkdf2_sha256_prfxors(Mem_8bits *pwd, int pwdByteSz, Key_64bits salt, int c, Word_32bits bloci)
{
    Mem_8bits   sha_prev[SHA256_byteSz];
    Mem_8bits   *sha_curr;
    Mem_8bits   *sha_xor;

    // Set U0 = Salt_64bits_Big_Endian || bloci_32bits_Big_Endian
    endianReverse((Mem_8bits *)&salt, KEY_byteSz);
    endianReverse((Mem_8bits *)&bloci, WORD32_ByteSz);
    ft_memcpy(sha_prev, (Mem_8bits *)&salt, KEY_byteSz);
    ft_memcpy(sha_prev + KEY_byteSz, (Mem_8bits *)&bloci, WORD32_ByteSz);

    // U1 = PRF(password, U0)
    sha_xor = pbkdf2_sha256_hmac(pwd, pwdByteSz, sha_prev, KEY_byteSz + WORD32_ByteSz);
    ft_memcpy(sha_prev, sha_xor, SHA256_byteSz);

    for (int i = 1; i < c; i++)
    {
        // Un = PRF(password, Un-1)
        sha_curr = pbkdf2_sha256_hmac(pwd, pwdByteSz, sha_prev, SHA256_byteSz);

        // XOR current sha with dynamic var sha_xor
        sha256_xor_8bits(sha_xor, sha_curr, &sha_xor);

        ft_memcpy(sha_prev, sha_curr, SHA256_byteSz);
        free(sha_curr);
    }
    return sha_xor;
}

Key_64bits  pbkdf2_sha256(Mem_8bits *pwd, Key_64bits salt, int c)
/*

    Desired output length: KEY_byteSz = 8 bytes / 64 bits

    Algorithm:

        DK = PBKDF2(PRF, Password, Salt, c, dkLen)
        DK = T1 || T2 || ... || Tdklen/hlen             (Concatenation)

        With:
            dklen = Output key size of pbkdf2
            hlen = PRF output hash size
            Ti = F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc

            With:
                U1 = PRF(Password, 64_bits_BE(Salt) || 32_bits_BE(i))
                U2 = PRF(Password, U1)
                ...
                Uc = PRF(Password, Uc-1)
    
    With sha256 as pseudo random function (PRF),
    Hash output length is greater than the desired key length: 256 > 64 (bits)
    Conclusion: T1 || T2 || ... || Tdklen/hlen  =>  T1 & (1 << 65 - 1)

*/
{
    // T1 = F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
    Mem_8bits *key = pbkdf2_sha256_prfxors(pwd, ft_strlen(pwd), salt, c, 1);
    endianReverse(key, KEY_byteSz);

    // DK = T1 & (1 << 65 - 1)
    return *((Key_64bits *)key);
}
