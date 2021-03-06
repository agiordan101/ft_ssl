#include "ft_ssl.h"

static void             des_P_flag_output(t_des *des_data)
{
    ssl.fd_out = STDERR; // For ft_printHex function
    ft_putstrfd(ssl.fd_out, "salt=");
    ft_printHex(des_data->salt);
    ft_putstrfd(ssl.fd_out, "\nkey=");
    ft_printHex(des_data->key);
    if (ssl.command.command == DESCBC)
    {
        ft_putstrfd(ssl.fd_out, "\niv=");
        ft_printHex(des_data->vector);
    }
    ft_putstrfd(ssl.fd_out, "\n");
    freexit(EXIT_SUCCESS);
}

static int              magic_number_in(t_des *des, Mem_8bits *plaintext, e_flags flags)
{
    /*
        Encryption:
            Create magic number if no key is provided (Create one with Salt and Password),
            or password is given (Even if a key is provided).
        Decryption:
            Magic number is always needed unless key is provide
            // Magic number is needed when salt/password are used in PBKDF2 (Even if a key is provided).
    */
    if (flags & d)
    {
        Mem_8bits   buff[MAGICNUMBER_byteSz + 1];
        ft_bzero(buff, MAGICNUMBER_byteSz + 1);
        ft_memcpy(buff, plaintext, MAGICNUMBER_byteSz);

        if (ft_strcmp(buff, MAGICNUMBER))
        {
            if (!des->key)
                ft_ssl_error("bad magic number\n");
            return 0;
        }
        else
        {
            des->salt = *(Key_64bits *)(plaintext + MAGICNUMBER_byteSz);
            endianReverse((Mem_8bits *)&des->salt, KEY_byteSz);
        }
    }
    else if (des->key && !des->password) // Only case with no magic number needed in encryption
        return 0;
    return 1;
}

static Mem_8bits        *magic_number_out(t_des *des, Mem_8bits *hash, Long_64bits *hashByteSz)
{
    // A magic number concat with salt need to be added before hash, on encryption with PBKDF2 case
    Mem_8bits   header[MAGICHEADER_byteSz];

    endianReverse((Mem_8bits *)&des->salt, KEY_byteSz);
    ft_memcpy(header, MAGICNUMBER, MAGICNUMBER_byteSz);
    ft_memcpy(header + MAGICNUMBER_byteSz, (void *)&des->salt, KEY_byteSz);

    char *header_hash = ft_memjoin(header, MAGICHEADER_byteSz, hash, *hashByteSz);
    *hashByteSz += MAGICHEADER_byteSz;

    free(hash);
    return (Mem_8bits *)header_hash;
}

static Key_64bits       generate_key()
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

    // Permutation : 64-bits -> 56-bits (Remove each 8th-bit of each bytes)
    endianReverse((Mem_8bits *)&key, KEY_byteSz);
    key = bits_permutations(key, pc1, 56);
    endianReverse((Mem_8bits *)&key, KEY_byteSz);
    key >>= 8;

    // Split key in half: lpart / rpart
    Word_32bits rpart = key & keymask;
    Word_32bits lpart = key >> 28;

    for (int i = 0; i < 16; i++)
    {
        // Left shift based on keybitshift (round index)
        rpart = ((rpart << keybitshift[i]) & keymask) | (rpart >> (28 - keybitshift[i]));
        lpart = ((lpart << keybitshift[i]) & keymask) | (lpart >> (28 - keybitshift[i]));

        key = (Key_64bits)lpart << 28 | rpart;

        key <<= 8;
        endianReverse((Mem_8bits *)&key, KEY_byteSz);
        
        key = bits_permutations(key, pc2, 48);
        des->subkeys[i] = key;
   }
}

static void             init_vars(t_des *des, Mem_8bits *plaintext, e_flags flags)
{
    if (!des->mode)
        des->mode = flags & DESECB ? DESECB : DESCBC;

    // Vector is only for CBC mode, ft_ssl failed if it's not provided
    if (des->vector)
    {
        if (des->mode != DESCBC)
            ft_putstderr("warning: iv not used by this cipher\n");
    }
    else if (des->mode == DESCBC)
        ft_ssl_error("Initialization vector is undefined\n");

    // A salt is randomly generated if it's not provided
    if (!des->salt)
        des->salt = generate_key();

    // A key is generated with pbkdf2 if it's not provided
    if (!des->key && ~flags & k)
    {
        // A password is asked if it's not provided
        if (!des->password)
            des->password = (Mem_8bits *)ask_password(des->mode == DESECB ? "DES-ECB" : "DES-CBC", flags);

        // Password-based key derivation function (PBKDF) using SHA256-HMAC function as pseudo random function (PRF)
        des->key = pbkdf2_sha256(
            des->password,
            ft_strlen(des->password),
            des->salt,
            des->pbkdf2_iter ?\
                des->pbkdf2_iter :\
                PBKDF2_iter
        );
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

    exp_halfblock = bits_permutations(halfblock, exp_d, 48);    
    exp_halfblock ^= subkey;
    exp_halfblock = _bits_permutations(exp_halfblock, bitorder, 48);

    for (int i = 0; i < 8; i++)
    {
        box = exp_halfblock & 0b111111;
        box = (box >> 5) | ((box >> 3) & 0b10) | ((box >> 1) & 0b100) | ((box << 1) & 0b1000) | ((box << 3) & 0b10000) | ((box << 5) & 0b100000);
        s0 = ((box & 0b100001) >> 4) | (box & 1);
        s1 = (box & 0b011110) >> 1;
        outblock |= (S[i][s0][s1] << (i * 4));
        exp_halfblock >>= 6;
    }

    outblock = ((outblock >> 4) & 0x0f0f0f0f) | ((outblock << 4) & 0xf0f0f0f0);
    outblock = _bits_permutations(outblock, bitorder, 32);
    outblock = _bits_permutations(outblock, finalperm, 32);
    outblock = _bits_permutations(outblock, bitorder, 32);
    return outblock;
}

static Long_64bits      feistel_algorithm(t_des *des, Long_64bits plaintext)
{
    plaintext = bits_permutations(plaintext, des->ipt, 64);

    Word_32bits lpart = plaintext & (((Long_64bits)1 << 32) - 1);
    Word_32bits rpart = plaintext >> 32;

    for (int i = 0; i < 16; i++)
    {
        lpart ^= feistel_func(rpart, des->subkeys[i]);
        rpart ^= lpart;
        lpart ^= rpart;
        rpart ^= lpart;
    }

    plaintext = (Long_64bits)lpart << 32 | rpart;
    plaintext = bits_permutations(plaintext, des->fpt, 64);

    return plaintext;
}

static Mem_8bits        *des_decryption(t_des *des, Mem_8bits *pt, Long_64bits ptByteSz, Long_64bits *hashByteSz)
{
    int         ptBlocSz = (ptByteSz + LONG64_byteSz - 1) / LONG64_byteSz; // Count of 64-bits bloc
    Long_64bits ciphertext[ptBlocSz];
    Long_64bits *plaintext = (Long_64bits *)pt + ptBlocSz - 1;
    Long_64bits bloc;
    int         outbyteSz;

    for (int i = ptBlocSz - 1; i >= 0; i--)
    {
        bloc = *plaintext;

        ciphertext[i] = feistel_algorithm(des, bloc);

        if (des->mode == DESCBC)
            ciphertext[i] = ciphertext[i] ^ (i ? *(plaintext - 1) : des->vector);
        plaintext--;
    }
    outbyteSz = ptBlocSz * LONG64_byteSz;

    des_unpadding(ciphertext + ptBlocSz - 1, &outbyteSz);

    if (hashByteSz)
        *hashByteSz = outbyteSz;
    return ft_memdup((Mem_8bits *)ciphertext, outbyteSz);
}

static Mem_8bits        *des_encryption(t_des *des, Mem_8bits *pt, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags flags)
{
    // ptBlocSz is the count of 64-bits bloc (Padding: Add one bloc if the lastest is full)
    int         ptBlocSz = (ptByteSz + (flags & nopad ? LONG64_byteSz - 1 : LONG64_byteSz)) / LONG64_byteSz;
    Long_64bits ciphertext[ptBlocSz];
    Long_64bits *plaintext = (Long_64bits *)pt;
    Long_64bits bloc;
    int         ptByteSzLeft;

    if (flags & nopad && ptByteSz % 8)
        ft_ssl_error("Data not multiple of block length (8 bytes).\n");

    for (int i = 0; i < ptBlocSz; i++)
    {
        ptByteSzLeft = ft_strlen((Mem_8bits *)plaintext);
        ft_bzero(&bloc, LONG64_byteSz);
        ft_memcpy(&bloc, plaintext, ptByteSzLeft < LONG64_byteSz ? ptByteSzLeft : LONG64_byteSz);

        // Padding with number of missing bytes
        if (i == ptBlocSz - 1)
            bloc = des_padding((Mem_8bits *)&bloc, ptByteSz % LONG64_byteSz);

        if (des->mode == DESCBC)
            bloc ^= i ? ciphertext[i - 1] : des->vector;

        ciphertext[i] = feistel_algorithm(des, bloc);
        plaintext++;
    }

    if (hashByteSz)
        *hashByteSz = ptBlocSz * LONG64_byteSz;
    return ft_memdup((Mem_8bits *)ciphertext, ptBlocSz * LONG64_byteSz);
}

Mem_8bits               *des(t_des *des_data, Mem_8bits *input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags)
{
    // Return 1 if magic number is needed (encryption) or seen (decryption)
    int         magic_number_case = magic_number_in(des_data, input, flags);

    // Parse and initialize data
    init_vars(des_data, input, flags);
    if (flags & P)
        des_P_flag_output(des_data);

    // Algorithm part
    endianReverse((Mem_8bits *)&des_data->vector, KEY_byteSz); // Do this now to print iv/vector exactly like openssl with P flag
    if (flags & e)
        return magic_number_case ?\
            magic_number_out(
                des_data,
                des_encryption(des_data, input, iByteSz, oByteSz, flags), //Merge 2 encryption calls
                oByteSz
            ) :\
            des_encryption(des_data, input, iByteSz, oByteSz, flags);
    else
    {
        set_keys_for_decryption(des_data);
        return magic_number_case ?\
            des_decryption(des_data, input + MAGICHEADER_byteSz, iByteSz - MAGICHEADER_byteSz, oByteSz) :\
            des_decryption(des_data, input, iByteSz, oByteSz);
    }
}

Mem_8bits   *cmd_wrapper_des(void *cmd_data, Mem_8bits **input, Long_64bits iByteSz, Long_64bits *oByteSz, e_flags flags)
{
    return des((t_des *)cmd_data, *input, iByteSz, oByteSz, flags);
}
