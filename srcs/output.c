#include "ft_ssl.h"

void    print_usage()
{
    ft_putstr("usage: ft_ssl <algorithm> [flags] [file | string]\n\n");

    // ft_ssl 1st project
    ft_putstr("\nMessage Digest commands:\n\tmd5\n\tsha256\n\n");
    ft_putstr("Message Digest flags:\n");
    ft_putstr("\t-p: echo STDIN to STDOUT and append the checksum to STDOUT\n");
    ft_putstr("\t-q: quiet mode\n");
    ft_putstr("\t-r: reverse the format of the output\n");
    ft_putstr("\t-s: print the sum of the given string\n\n");
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

// void    file_output(char *hash, int hashlen)
// {
//     int fd;

//     fd = open(ssl.output_file, O_CREAT | O_WRONLY, 777);
//     // if ((fd = open(ssl.output_file, O_CREAT | O_WRONLY, 777)) == -1)
//     // {
//     //     file_not_found(hash);
//     //     return ;
//     // }
//     printf("write to fd %d: >%s<\n", fd, hash);
//     if (write(fd, hash, hashlen) == -1)
//     {
//         ft_putstr("[file output error] write() in '");
//         ft_putstr(ssl.output_file);
//         ft_putstr("' has failed\n");
//         freexit(EXIT_FAILURE);
//     }
//     close(fd);
// }

void    md_hash_output(t_hash *p)
{
    for (Word_32bits *tmp = p->hash; tmp < p->hash + p->hashlen; tmp += 1)
        ft_printHex(*tmp);
}

void    stdin_quiet_output(t_hash *hash)
{
    ft_putstr(hash->name);
    ft_putstr("\n");
    md_hash_output(hash);
}

void    stdin_output(t_hash *hash)
{
    ft_putstr("(");
    ft_putstr(hash->name);
    ft_putstr(")= ");
    md_hash_output(hash);
}

void    quiet_output(t_hash *hash)
{
    md_hash_output(hash);
}

void    reversed_output(t_hash *hash)
{
    md_hash_output(hash);
    ft_putstr(" ");
    ft_putstr(hash->name);
}

void    classic_output(t_hash *hash)
{
    ft_putstr(ssl.hash_func);
    ft_putstr(" (");
    ft_putstr(hash->name);
    ft_putstr(") = ");
    md_hash_output(hash);
}

void    md_output(t_hash *hash)
{
    if (hash->error == FILENOTFOUND)
        file_not_found(hash);
    else if (hash->stdin)
    {
        if (ssl.flags & Q && ssl.flags & P_md)
            stdin_quiet_output(hash);
        else if (ssl.flags & Q)
            quiet_output(hash);
        else
            stdin_output(hash);
    }
    else if (ssl.flags & Q)
        quiet_output(hash);
    else if (ssl.flags & R)
        reversed_output(hash);
    else
        classic_output(hash);
}

void    cipher_output(t_hash *hash)
{
    // if (ssl.flags & O)
    // {
    //     // file_output((char *)hash->hash, hash->hashlen);
    //     if (write(ssl.fd_out, (char *)hash->hash, hash->hashlen) == -1)
    //     {
    //         ft_putstr("[file output error] write() in '");
    //         ft_putstr(ssl.output_file);
    //         ft_putstr("' has failed\n");
    //         freexit(EXIT_FAILURE);
    //     }
    // }
    // else
    // {
    //     if (((char *)hash->hash)[hash->hashlen - 1] == '\n')
    //         ((char *)hash->hash)[hash->hashlen - 1] = '\0'; //To remove \n, it's like 'echo -n <node->msg> | ./ft_ssl ...'
    //     ft_putstr((char *)hash->hash);
    // }
    if (((char *)hash->hash)[hash->hashlen - 1] == '\n')
        ((char *)hash->hash)[hash->hashlen - 1] = '\0'; //To remove \n, it's like 'echo -n <node->msg> | ./ft_ssl ...'
    ft_putstr((char *)hash->hash);
}

void    output(t_hash *hash)
{
    if (ssl.command & MD)
        md_output(hash);
    else if (ssl.command & CIPHER)
        cipher_output(hash);
    else
        ;
    ft_putstr("\n");
}
