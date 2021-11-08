#include "ft_ssl.h"

static void         ask_password(t_des *des)
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

inline static Mem_8bits    *generate_key()
{
    Mem_8bits key[KEY_byteSz];

    for (int i = 0; i < KEY_byteSz; i++)
        key[i] = rand() % 0xFF;
    return ft_strdup(key);
}

static void         init_vars(t_des *des)
{
    // printf("des->vector: %s\n", des->vector);
    // printf("des->salt: %s\n", des->salt);
    // printf("des->password: %s\n", des->password);
    // printf("des->key: %s\n\n", des->key);

    srand(time(NULL));
    // Vector is only for CBC mode, ft_ssl failed if it's not provided
    if (!des->vector && !ft_strcmp(ssl.hash_func, "DES-CBC"))
    {
        ft_putstr("\nInitialization vector is undefined\n");
        freexit(EXIT_SUCCESS);
    }

    // A salt is randomly generated if it's not provided
    if (!des->salt)
        des->salt = generate_key();

    // A password is asked if it's not provided
    if (!des->password)
        ask_password(des);

    // A key is generated with pbkdf2 if it's not provided
    if (!des->key)
        des->key = pbkdf2_sha256(des->password, des->salt, 3);

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

    // Test Permutation Table
    char testpt[KEY_bitSz];
    // for (int i = 0; i < 64; i++)
    //     testpt[i] = i;
    
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            testpt[i * 8 + j] = (7 - i) * 8 + j;
    
    // for (int i = 0; i < 64; i++)
    //     printf("%d ", testpt[i]);
    // printf("\n");
    // testpt[2] = 62;
    // testpt[62] = 2;
    ft_memcpy(des->testpt, testpt, 64);

    printf("\ncipher->vector:\n");
    // if (des->vector)
    key_output(des->vector);
    printf("\ncipher->salt:\n");
    key_output(des->salt);
    printf("\ncipher->password:\n%s", des->password);
    printf("\ncipher->key:\n");
    key_output(des->key);
}

// static Mem_8bits    *key_transformation(Mem_8bits *key, int round)
// /*
//     Transform a 56-bit key into 48-bit key
// */
// {
//     Mem_8bits k0[4];
//     Mem_8bits k1[4];
// }

void                descbc(t_hash *hash)
{
    init_vars(&ssl.des);
    Mem_8bits *newkey = key_discarding(ssl.des.key);
    bits_permutations(ssl.des.key, ssl.des.ipt);
    // bits_permutations(ssl.des.key, ssl.des.testpt);

    freexit(EXIT_SUCCESS);
}
