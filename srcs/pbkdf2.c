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
    Mem_8bits *key_X_ipad = ft_memnew(SHA256_byteSz);
    Mem_8bits *key_X_opad = ft_memnew(SHA256_byteSz);

    int       msgConcatByteSz = SHA256_byteSz + msgByteSz;
    Mem_8bits *msgConcat = ft_memnew(msgConcatByteSz);
    // Mem_8bits msgConcat[msgConcatByteSz];           // Concatenation between key_X_ipad and msg
    // ft_bzero(msgConcat, msgConcatByteSz);

    int       kopadConcatByteSz = SHA256_byteSz * 2;
    Mem_8bits *kopadConcat = ft_memnew(kopadConcatByteSz);
    // Mem_8bits kopadConcat[kopadConcatByteSz];       // Concatenation between key_X_opad and result of sha256(msgConcat)
    // ft_bzero(kopadConcat, kopadConcatByteSz);

    printf("key (len=%d) >%s<\n", keyByteSz, key);
    for (Word_32bits *tmp = (Word_32bits *)key; tmp < (Word_32bits *)key + keyByteSz / WORD32_ByteSz; tmp += 1)
        ft_printHex(*tmp, WORD32_ByteSz);
    printf("\n");
    printf("\nmsg (len=%d) >%s<\n", msgByteSz, msg);
    for (Word_32bits *tmp = (Word_32bits *)msg; tmp < (Word_32bits *)msg + msgByteSz / WORD32_ByteSz; tmp += 1)
        ft_printHex(*tmp, WORD32_ByteSz);
    printf("\n");

    key = hmac_init_key_SHA256_byteSz(key, keyByteSz);

    // printf("\nhmac_init_key_SHA256_byteSz (len=%ld) >%s<\n", SHA256_byteSz, key);
    // for (Word_32bits *tmp = (Word_32bits *)key; tmp < (Word_32bits *)key + SHA256_byteSz / WORD32_ByteSz; tmp += 1)
    //     ft_printHex(*tmp, WORD32_ByteSz);
    // printf("\n");
    sha256_print(key);

    sha256_xor_8bits(key, (Mem_8bits *)opad, (Mem_8bits **)&key_X_opad);
    sha256_xor_8bits(key, (Mem_8bits *)ipad, (Mem_8bits **)&key_X_ipad);

    // printf("\nkey_X_ipad (len=%ld) >%s<\n", SHA256_byteSz, key_X_ipad);
    // for (Word_32bits *tmp = (Word_32bits *)key_X_ipad; tmp < (Word_32bits *)key_X_ipad + SHA256_byteSz / WORD32_ByteSz; tmp += 1)
    //     ft_printHex(*tmp, WORD32_ByteSz);
    // printf("\n");
    // printf("\nkey_X_opad (len=%ld) >%s<\n", SHA256_byteSz, key_X_opad);
    // for (Word_32bits *tmp = (Word_32bits *)key_X_opad; tmp < (Word_32bits *)key_X_opad + SHA256_byteSz / WORD32_ByteSz; tmp += 1)
    //     ft_printHex(*tmp, WORD32_ByteSz);
    // printf("\n");
    sha256_print(key_X_ipad);
    sha256_print(key_X_opad);

    // Concatenation between key_X_ipad and msg
    ft_memcpy((Mem_8bits *)msgConcat, (Mem_8bits *)key_X_ipad, SHA256_byteSz);
    ft_memcpy((Mem_8bits *)msgConcat + SHA256_byteSz, msg, msgByteSz);

    printf("\nmsgConcat (len=%d) >%s<\n", msgConcatByteSz, msgConcat);
    for (Word_32bits *tmp = (Word_32bits *)msgConcat; tmp < (Word_32bits *)msgConcat + msgConcatByteSz / WORD32_ByteSz; tmp += 1)
        ft_printHex(*tmp, WORD32_ByteSz);
    printf("\n");

    // Mem_8bits *sha256_input = ft_memdup(msgConcat, msgConcatByteSz);
    // Mem_8bits *sha256_res = sha256(&sha256_input, msgConcatByteSz, (Long_64bits *)&msgConcatByteSz, e);
    // free(sha256_input);
    sha256_res = sha256(&msgConcat, msgConcatByteSz, (Long_64bits *)&msgConcatByteSz, e);

    // Concatenation between key_X_opad and result of sha256(msgConcat)
    ft_memcpy(kopadConcat, key_X_opad, SHA256_byteSz);
    ft_memcpy(kopadConcat + SHA256_byteSz, sha256_res, SHA256_byteSz);
    free(sha256_res);
    
    printf("\nkopadConcat (len=%d) >%s<\n", kopadConcatByteSz, kopadConcat);
    for (Word_32bits *tmp = (Word_32bits *)kopadConcat; tmp < (Word_32bits *)kopadConcat + kopadConcatByteSz / WORD32_ByteSz; tmp += 1)
        ft_printHex(*tmp, WORD32_ByteSz);
    printf("\n");

    // sha256_input = ft_memdup(kopadConcat, kopadConcatByteSz);
    // Mem_8bits *ret = sha256(&sha256_input, kopadConcatByteSz, (Long_64bits *)&kopadConcat, e);
    // free(sha256_input);
    sha256_res = sha256(&kopadConcat, kopadConcatByteSz, (Long_64bits *)&kopadConcat, e);

    // printf("\nkey return (len=%ld) >%s<\n", SHA256_byteSz, sha256_res);
    // for (Word_32bits *tmp = (Word_32bits *)sha256_res; tmp < (Word_32bits *)sha256_res + SHA256_byteSz / WORD32_ByteSz; tmp += 1)
    //     ft_printHex(*tmp, WORD32_ByteSz);
    // printf("\n");
    sha256_print(sha256_res);

    free(key_X_ipad);
    free(key_X_opad);
    free(msgConcat);
    // free(kopadConcat);
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
    sha256_print(sha_prev);

    for (int i = 0; i < c; i++)
    {
        sha_curr = pbkdf2_sha256_hmac(pwd, pwdByteSz, sha_prev, SHA256_byteSz);
        printf("\n\n\nU%d = \n", i);
        sha256_print(sha_curr);

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
    // printHex(key, SHA256_byteSz);
    // return *((Key_64bits *)key);
    Mem_8bits *key = pbkdf2_sha256_prfxors(pwd, ft_strlen(pwd), salt, c, 0);
    endianReverse(key, KEY_byteSz);
    return *((Key_64bits *)key);
}
