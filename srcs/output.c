#include "ft_ssl.h"

// ---------------------- VERBOSE output ---------------------------

void    print_usage()
{
    ft_putstr("usage: ft_ssl <algorithm> [flags] [file | string]\n\n");

    // ft_ssl 1st project
    ft_putstr("\nMessage Digest commands:\n\tmd5\n\tsha256\n\n");
    ft_putstr("Message Digest flags:\n");
    ft_putstr("\t-p: echo STDIN to STDOUT and append the checksum to STDOUT\n");
    ft_putstr("\t-q: quiet mode\n");
    ft_putstr("\t-r: reverse the format of the output\n");
    ft_putstr("\t-s: print the sum of the given string\n");
    ft_putstr("\t-i: input file for message\n");
    ft_putstr("\t-o: output file for hash\n");

    // ft_ssl 2nd project
    ft_putstr("\nCipher commands:\n\tbase64\n\tdes\n\tdes-ecb\n\tdes-cbc\n\n");
    ft_putstr("Cipher flags:\n");
    ft_putstr("\t-a: decode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstr("\t-d: decrypt mode\n");
    ft_putstr("\t-e: encrypt mode\n");
    ft_putstr("\t-i: input file for message\n");
    ft_putstr("\t-o: output file for hash\n");
    ft_putstr("\t-p: send password in ascii\n");
    ft_putstr("\t-s: send the salt in hex\n");
    ft_putstr("\t-v: send initialization vector in hex\n");
    // ft_putstr("\t-q: quiet mode\n");
    // ft_putstr("\t-r: reverse the format of the output\n");

    // ft_ssl 3rd project
    ft_putstr("\nStandard commands:\n\tNot yet...\n");
}

void    file_not_found(t_hash *hash)
{
    ft_putstr("ft_ssl: ");
    ft_putstr(ssl.hash_func);
    ft_putstr(": ");
    ft_putstr(hash->name);
    ft_putstr(": No such file or directory");
}

// ---------------------- DATA output ---------------------------

void    key_output(Mem_8bits *p)
{
    Word_32bits *key = (Word_32bits *)p;
    for (Word_32bits *tmp = key; tmp && tmp < key + KEY_byteSz / WORD_ByteSz; tmp += 1)
        ft_printHex(*tmp, WORD_ByteSz);
}

void    hash_64bits_output(t_hash *p)
{
    for (Long_64bits *tmp = p->hash_64bits; tmp < p->hash_64bits + p->hashWordSz / 2; tmp += 1)
        ft_printHex(*tmp, LONG64_ByteSz);
}

void    hash_32bits_output(t_hash *p)
{
    for (Word_32bits *tmp = p->hash_32bits; tmp < p->hash_32bits + p->hashWordSz; tmp += 1)
        ft_printHex(*tmp, WORD_ByteSz);
}

void    classic_output(t_hash *hash, int hashBlocByteSz)
{
    ft_putstr(ssl.hash_func);
    ft_putstr(" (");
    ft_putstr(hash->name);
    ft_putstr(") = ");
    if (hashBlocByteSz == WORD_ByteSz)
        hash_32bits_output(hash);
    else if (hashBlocByteSz == LONG64_ByteSz)
        hash_64bits_output(hash);
}

// ---------------------- MD output ---------------------------

void    md_stdin_quiet_output(t_hash *hash)
{
    ft_putstr(hash->name);
    ft_putstr("\n");
    hash_32bits_output(hash);
}

void    md_stdin_output(t_hash *hash)
{
    ft_putstr("(");
    ft_putstr(hash->name);
    ft_putstr(")= ");
    hash_32bits_output(hash);
}

void    md_quiet_output(t_hash *hash)
{
    hash_32bits_output(hash);
}

void    md_reversed_output(t_hash *hash)
{
    hash_32bits_output(hash);
    ft_putstr(" ");
    ft_putstr(hash->name);
}

void    md_output(t_hash *hash)
{
    if (hash->stdin)
    {
        if (ssl.flags & Q && ssl.flags & P_md)
            md_stdin_quiet_output(hash);
        else if (ssl.flags & Q)
            md_quiet_output(hash);
        else
            md_stdin_output(hash);
    }
    else if (ssl.flags & Q)
        md_quiet_output(hash);
    else if (ssl.flags & R)
        md_reversed_output(hash);
    else
        classic_output(hash, WORD_ByteSz);
}

// ---------------------- CIPHER output ---------------------------

void    cipher_output(t_hash *hash)
{
    if (ssl.hash_func_addr == base64)
    {
        if (((char *)hash->hash_32bits)[hash->hashWordSz - 1] == '\n')
            ((char *)hash->hash_32bits)[hash->hashWordSz - 1] = '\0'; //To remove \n, it's like 'echo -n <node->msg> | ./ft_ssl ...'
        ft_putstr((char *)hash->hash_32bits);
    }
    else if (ssl.hash_func_addr == des && ssl.flags & O)
        hash_64bits_output(hash);
    else if (ssl.hash_func_addr == des)
        classic_output(hash, LONG64_ByteSz);
}

// ---------------------- GLOBAL output ---------------------------

void    output(t_hash *hash)
{
    if (hash->error == FILENOTFOUND)
        file_not_found(hash);
    else if (ssl.command & MD)
        md_output(hash);
    else if (ssl.command & CIPHER)
        cipher_output(hash);
    else
        ;
    ft_putstr("\n");
}
