#include "ft_ssl.h"

static void   ask_password(t_cipher *cipher)
{
    char *firstmsg_1 = "enter ";
    char *secondmsg_1 = "Verifying - enter ";
    char *msgs_2 = " encryption password:";
    char *firstmsg = ft_strinsert(firstmsg_1, ssl.hash_func, msgs_2);
    char *secondmsg = ft_strinsert(secondmsg_1, ssl.hash_func, msgs_2);

    // printf("firstmsg: >%s<\n", firstmsg);
    // printf("secondmsg: >%s<\n", secondmsg);
    char *password = ft_strnew(getpass(firstmsg));
    cipher->password = ft_strnew(getpass(secondmsg));

    // printf("password: >%s<\n", password);
    // printf("cipher->password: >%s<\n", cipher->password);
    // printBits(password, ft_strlen(password));
    // printBits(cipher->password, ft_strlen(cipher->password));
    free(firstmsg);
    free(secondmsg);
    if (ft_strcmp(password, cipher->password))
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
    return ft_strnew(key);
}

static void         init_vars(t_cipher *cipher)
{
    printf("cipher->vector: %s\n", cipher->vector);
    printf("cipher->salt: %s\n", cipher->salt);
    printf("cipher->password: %s\n", cipher->password);
    printf("cipher->key: %s\n\n", cipher->key);

    srand(time(NULL));
    // Vector is only for CBC mode, ft_ssl failed if it's not provided
    if (!cipher->vector && !ft_strcmp(ssl.hash_func, "DES-CBC"))
    {
        ft_putstr("\nInitialization vector is undefined\n");
        freexit(EXIT_SUCCESS);
    }
    printf("\ncipher->vector: \n");
    if (cipher->vector)
        key_output(cipher->vector);

    // A salt is randomly generated if it's not provided
    if (!cipher->salt)
        cipher->salt = generate_key();
    printf("\ncipher->salt: \n");
    key_output(cipher->salt);

    // A password is asked if it's not provided
    if (!cipher->password)
        ask_password(cipher);
    printf("\ncipher->password: %s\n", cipher->password);

    // A key is generated with pbkdf2 if it's not provided
    if (!cipher->key)
        cipher->key = generate_key();
        // cipher->key = pbkdf2_sha256(cipher->password, cipher->salt, 0);
    printf("\ncipher->key: \n");
    key_output(cipher->key);
}

void    descbc(t_hash *hash)
{
    init_vars(&ssl.cipher);
    exit(0);
}
