#include "ft_ssl.h"

static void             ask_password(t_des *des)
{
    char *firstmsg_1 = "enter ";
    char *secondmsg_1 = "Verifying - enter ";
    char *msgs_2 = " encryption password:";
    char *firstmsg = ft_strinsert(firstmsg_1, ssl.hash_func, msgs_2);
    char *secondmsg = ft_strinsert(secondmsg_1, ssl.hash_func, msgs_2);

    char *password = ft_strdup(getpass(firstmsg));
    des->password = getpass(secondmsg);

    free(firstmsg);
    free(secondmsg);
    if (ft_strcmp(password, des->password))
    {
        free(password);
        ft_putstr("\nVerify failure.\nbad password read.\n");
        freexit(EXIT_SUCCESS);
    }
    else
        free(password);
}

static inline Key_64bits    generate_key()
{
    Key_64bits  key = 0;

    for (int i = 0; i < KEY_byteSz; i++)
        key = key * 0x100 + rand() % 0x100;
    return key;
}

static void             set_keys_for_decryption(t_des *des)
{
    Key_64bits tmp;

    for (int i = 0; i < 8; i++)
    {
        tmp = des->subkeys[i];
        des->subkeys[i] = des->subkeys[15 - i];
        des->subkeys[15 - i] = tmp;
        // printf("des->subkeys[%d]: %lx\n", i, des->subkeys[i]);
        // printf("des->subkeys[%d]: %lx\n", 15 - i, des->subkeys[15 - i]);
    }
}

static void             key_transformation(t_des *des)
/*
    Transform a 56-bit key into 48-bit key
*/
{
    Key_64bits  key = des->key;
    Word_32bits keymask = (1 << 28) - 1;
    static char keybitshift[16] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };
    static char bitorder[64] = {
        8, 7, 6, 5, 4, 3, 2, 1,
        16, 15, 14, 13, 12, 11, 10, 9,
        24, 23, 22, 21, 20, 19, 18, 17,
        32, 31, 30, 29, 28, 27, 26, 25,
        40, 39, 38, 37, 36, 35, 34, 33,
        48, 47, 46, 45, 44, 43, 42, 41,
        56, 55, 54, 53, 52, 51, 50, 49,
        64, 63, 62, 61, 60, 59, 58, 57,
    };
    static char pc1[56] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };
    static char pc2[48] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    printf("\nkey_transformation: %lx\n", key);

    // Permutation : 64-bits -> 56-bits (Remove each 8th-bit of each bytes)
    endianReverse((Mem_8bits *)&key, KEY_byteSz);
    key = bits_permutations(key, pc1, 56);
    endianReverse((Mem_8bits *)&key, KEY_byteSz);
    key >>= 8;
    
    printf("Permute key to 56-bits: %lx\n", key);

    Word_32bits rpart = key & keymask;
    Word_32bits lpart = key >> 28;

    printf("Split lpart / rpart : %x / %x\n", lpart, rpart);

    for (int i = 0; i < 16; i++)
    {
        // Left shift based on keybitshift (round index)
        rpart = ((rpart << keybitshift[i]) & keymask) | (rpart >> (28 - keybitshift[i]));
        lpart = ((lpart << keybitshift[i]) & keymask) | (lpart >> (28 - keybitshift[i]));

        key = (Key_64bits)lpart << 28 | rpart;

        key <<= 8;
        endianReverse((Mem_8bits *)&key, KEY_byteSz);
        
        key = bits_permutations(key, pc2, 48);

        // endianReverse((Mem_8bits *)&key, KEY_byteSz);
        // key >>= 16;
        printf("Key %d: %lx\n", i, key);
        des->subkeys[i] = key;
 
   }
    // exit(0);
}

static void             init_vars(t_des *des)
{
    printf("Init vars\n");
    srand(time(NULL));
    // Vector is only for CBC mode, ft_ssl failed if it's not provided
    if (!des->vector && des->mode == DESCBC)
    {
        ft_putstr("\nInitialization vector is undefined\n");
        freexit(EXIT_SUCCESS);
    }
    // NEED TO OUTPUT "warning: iv not used by this cipher"

    // A salt is randomly generated if it's not provided
    if (!des->salt)
        des->salt = generate_key();

    printf("Init vars 2\n");
    // A key is generated with pbkdf2 if it's not provided
    if (!des->key)
    {
        // A password is asked if it's not provided
        if (!des->password)
            ask_password(des);
        // des->key = pbkdf2_sha256(des->password, des->salt, 3);
    }

    // Key scheldule
    key_transformation(des);

    // Initial Permutation Table
    char ipt[KEY_bitSz] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    ft_memcpy(des->ipt, ipt, 64);

    // Final Permutation Table
    char fpt[KEY_bitSz] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9,  49, 17, 57, 25
    };
    ft_memcpy(des->fpt, fpt, 64);

    // Verbose here ?
    printf("\ncipher->password: %s\n", des->password);
    printf("cipher->key: %lx\n", des->key);
    printf("cipher->salt: %lx\n", des->salt);
    printf("cipher->vector: %lx\n", des->vector);
    // printf("cipher->key: %lx\n", *((Long_64bits *)des->key));
    // printf("cipher->salt: %lx\n", *((Long_64bits *)des->salt));
    // printf("cipher->vector: %lx\n", *((Long_64bits *)des->vector));
    printf("\n");
    // exit(0);
}

static Word_32bits      feistel_func(Word_32bits halfblock, Long_64bits subkey)
{
    // S-box Table
    static char S[8][4][16] = {
        {{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }},
        {{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }},
        {{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }},
        {{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }},
        {{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }},
        {{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }},
        {{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }},
        {{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
    }};
    static char bitorder[64] = {
        8, 7, 6, 5, 4, 3, 2, 1,
        16, 15, 14, 13, 12, 11, 10, 9,
        24, 23, 22, 21, 20, 19, 18, 17,
        32, 31, 30, 29, 28, 27, 26, 25,
        40, 39, 38, 37, 36, 35, 34, 33,
        48, 47, 46, 45, 44, 43, 42, 41,
        56, 55, 54, 53, 52, 51, 50, 49,
        64, 63, 62, 61, 60, 59, 58, 57,
    };
    static char rev8bits[8] = {5, 6, 7, 8, 1, 2, 3, 4};
    // Expansion D-box Table
    static char exp_d[48] = {
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1
    };
    // Straight Permutation Table
    char finalperm[32] = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };
    Long_64bits exp_halfblock = (Long_64bits)halfblock;
    Word_32bits outblock = 0;
    Word_32bits box;
    char        s0;
    char        s1;

    // printf("halfblock: %lx\n", halfblock);

    exp_halfblock = bits_permutations(halfblock, exp_d, 48);

    // printf("exp_halfblock: %lx\n", exp_halfblock);
    
    exp_halfblock ^= subkey;
    // endianReverse((Mem_8bits *)&exp_halfblock, 8);
    // exp_halfblock >> 16;
    exp_halfblock = _bits_permutations(exp_halfblock, bitorder, 48);
    // printf("exp_halfblock xor: %lx\n", exp_halfblock);
    // printLong(exp_halfblock);

    for (int i = 0; i < 8; i++)
    // for (int i = 7; i >= 0; i--)
    {
        box = exp_halfblock & 0b111111;
        box = (box >> 5) | ((box >> 3) & 0b10) | ((box >> 1) & 0b100) | ((box << 1) & 0b1000) | ((box << 3) & 0b10000) | ((box << 5) & 0b100000);
        s0 = ((box & 0b100001) >> 4) | (box & 1);
        s1 = (box & 0b011110) >> 1;
        outblock |= (S[i][s0][s1] << (i * 4));
        exp_halfblock >>= 6;
        // printf("box %x col %d row %d\toutblock: %lx\n", box, s1, s0, outblock);
    }

    // for (int i = 0; i < 8; i++)
    outblock = ((outblock >> 4) & 0x0f0f0f0f) | ((outblock << 4) & 0xf0f0f0f0);

    // printf("outblock: %lx\n", outblock);
    // printWord(outblock);

    outblock = _bits_permutations(outblock, bitorder, 32);
    // printf("outblock: %lx\n", outblock);
    // printWord(outblock);

    outblock = _bits_permutations(outblock, finalperm, 32);
    // printf("outblock: %lx\n", outblock);

    outblock = _bits_permutations(outblock, bitorder, 32);
    // printf("outblock: %lx\n", outblock);
    return outblock;
}

static Long_64bits      feistel_algorithm(Long_64bits plaintext)
{
    plaintext = bits_permutations(plaintext, ssl.des.ipt, 64);
    // printf("After ipt permutation hex: %lx\nAfter ipt permutation bin:\n", plaintext);
    // printLong(plaintext);
    // exit(0);

    Word_32bits lpart = plaintext & (((Long_64bits)1 << 32) - 1);
    Word_32bits rpart = plaintext >> 32;

    // printWord(lpart);
    // printWord(rpart);
    // printf("lpart rpart: %x %x\n", lpart, rpart);

    for (int i = 0; i < 16; i++)
    {
        lpart ^= feistel_func(rpart, ssl.des.subkeys[i]);

        rpart ^= lpart;
        lpart ^= rpart;
        rpart ^= lpart;

        // printf("lpart rpart %d: %x %x\tkey %lx\n", i, lpart, rpart, ssl.des.subkeys[i]);
    }

    plaintext = (Long_64bits)lpart << 32 | rpart;
    plaintext = bits_permutations(plaintext, ssl.des.fpt, 64);
    // printf("After fpt permutation: %lx\n", plaintext);
    // printf("After fpt permutation: %s\n", (char *)&plaintext);

    return plaintext;
}

static void             des_encryption(t_hash *hash, Mem_8bits *pt, int ptByteSz)
{
    int         ptSz = (ptByteSz + 8) / 8;
    Long_64bits ciphertext[ptSz];
    Long_64bits *plaintext = (Long_64bits *)pt;
    Long_64bits bloc;

    // printf("\n- DES ECRYPTION -\nptByteSz: %d\tptSz: %d\n", ptByteSz, ptSz);
    for (int i = 0; i < ptSz; i++)
    {
        bloc = *plaintext;
        // printf("str plaintext: >%s<\n", (Mem_8bits *)plaintext);

        // Padding with 0x06
        if (i == ptSz - 1)
            des_pad_last_bloc((Mem_8bits *)&bloc);

        // printf("\nhex vector: %lx\n", i ? ciphertext[i - 1] : ssl.des.vector);
        // printf("hex   bloc: %lx\n", bloc);

        // printf("bin vector: ");
        // printLong(i ? ciphertext[i - 1] : ssl.des.vector);
        // printf("bin   bloc: ");
        // printLong(bloc);

        if (ssl.des.mode == DESCBC)
        {
            bloc ^= i ? ciphertext[i - 1] : ssl.des.vector;
        //     printf("hex   bloc: %lx (CBC xor)\n", bloc);
        //     printf("bin   bloc: ");
        //     printLong(bloc);
        //     printf(" (CBC xor)\n");
        }

        ciphertext[i] = feistel_algorithm(bloc);
        printf("ciphertext: %lx\n", ciphertext[i]);
        
        plaintext++;
    }

    // Padd last bytes ? Already padded ?
    // Convert to base64 of course   // base64_msg((Mem_8bits **)&ciphertext, ptSz, (Mem_8bits *)hash->hash_32bits);
    
    hash->hash_64bits = (Long_64bits *)ft_memdup((Mem_8bits *)ciphertext, ptSz * LONG64_ByteSz);
    hash->hashWordSz = ptSz * 2;

    // exit(0);
}

void                    des(t_hash *hash)
{
    /*
        Actually works only for des-ecb encryption & plaintext % 64 == 0
    */
    printf("hash->msg: >%s<\n", hash->msg);

    init_vars(&ssl.des);
    if (ssl.flags & D)
        set_keys_for_decryption(&ssl.des);
    des_encryption(hash, hash->msg, hash->len);
}
