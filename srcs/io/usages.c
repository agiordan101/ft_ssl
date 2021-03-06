#include "ft_ssl.h"

static void     print_flag_usage(e_flags flag)
{
    if (flag & help)
        ft_putstderr("\t-help\t\tdisplay this summary and exit\n");
    else if (flag & i_)
        ft_putstderr("\t-i\t\tinput file\n");
    else if (flag & o)
        ft_putstderr("\t-o\t\toutput file\n");
    else if (flag & a)
        ft_putstderr("\t-a\t\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    else if (flag & A)
        ft_putstderr("\t-A\t\tused with -[a | -decin base64 | -encout base64] to specify base64 buffer as a single line\n");
    else if (flag & decin)
        ft_putstderr("\t-decin\t\tdecode the input with the given hashing command (command flags can ONLY be passed after)\n");
    else if (flag & encout)
        ft_putstderr("\t-encout\t\tencode the output with the given hashing command (command flags can ONLY be passed after)\n");
    else if (flag & passin)
        ft_putstderr("\t-passin\t\tsend password for input decryption (flag -decin <cmd> needs to exist before)\n");
    else if (flag & passout)
        ft_putstderr("\t-passout\tsend password for output encryption (flag -encout <cmd> needs to exist before)\n");
    else if (flag & q)
        ft_putstderr("\t-q\t\tquiet mode\n");
    else if (flag & r)
        ft_putstderr("\t-r\t\treverse the format of the output\n");
    else if (flag & s)
        ft_putstderr("\t-s\t\tinput data as string\n");
    else if (flag & p)
        ft_putstderr("\t-p\t\tforce data reception in stdin\n");
    else if (flag & e)
        ft_putstderr("\t-e\t\tencrypt mode (default mode) (-e has priority over -d)\n");
    else if (flag & d)
        ft_putstderr("\t-d\t\tdecrypt mode\n");
    else if (flag & pass)
        ft_putstderr("\t-p\t\tsend the password in hex\t(Override the behavior of global flag -p if any des command is past)\n");
    else if (flag & salt)
        ft_putstderr("\t-s\t\tsend the salt in hex\t(Override the behavior of global flag -s if any des command is past)\n");
    else if (flag & k)
        ft_putstderr("\t-k\t\tsend the key in hex\n");
    else if (flag & v)
        ft_putstderr("\t-v\t\tsend initialization vector in hex\n");
    else if (flag & P)
        ft_putstderr("\t-P\t\tprint the vector/key and exit\n");
    else if (flag & nopad)
        ft_putstderr("\t-nopad\t\tdisable standard block padding\n");
    else if (flag & pbkdf2_iter)
        ft_putstderr("\t-iter\t\tspecify the iteration count of PBKDF2\n");
    else if (flag & prob)
        ft_putstderr("\t-prob\t\tprobability requested for Miller-Rabin primality test in percentile (0 < p <= 100)\n");
    else if (flag & min)
        ft_putstderr("\t-min\t\tlower bound for prime generation (Default as 0)\n");
    else if (flag & max)
        ft_putstderr("\t-max\t\tupper bound for prime generation (Default as 2^63 - 1)\n");
    else if (flag & pubin)
        ft_putstderr("\t-pubin\t\texpect a public key in input file (private key by default)\n");
    else if (flag & pubout)
        ft_putstderr("\t-pubout\t\toutput a public key (private key by default). This option is automatically set if the input is a public key.\n");
    else if (flag & inform)
        ft_putstderr("\t-inform\t\tinput format [PEM | DER] (Default as PEM)\n");
    else if (flag & outform)
        ft_putstderr("\t-outform\toutput format [PEM | DER] (Default as PEM)\n");
    else if (flag & text)
        ft_putstderr("\t-text\t\tprint key properties in hex\n");
    else if (flag & modulus)
        ft_putstderr("\t-modulus\tprint RSA key modulus in hex\n");
    else if (flag & check)
        ft_putstderr("\t-check\t\tverify key consistency\n");
    else if (flag & noout)
        ft_putstderr("\t-noout\t\tdon't print key out\n");
    else if (flag & rand_path)
        ft_putstderr("\t-rand\t\ta file containing random data used to seed the random number generator\n");
    else if (flag & inkey)
        ft_putstderr("\t-inkey\t\tinput key\n");
}

static void     print_command_flags(e_flags flags)
{
    for (Long_64bits i = 1, flag = 1<<1; i < N_FLAGS + 1; i++, flag <<= 1)
        if (flag & flags)
            print_flag_usage(flag);
}

static void     print_md_usage()
{
    ft_putstderr("Usage: ./ft_ssl md5 | sha256 [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(MD_flags);
}

static void     print_base64_usage()
{
    ft_putstderr("Usage: ./ft_ssl base64 [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(BASE64_flags);
}

static void     print_des_usage()
{
    ft_putstderr("Usage: ./ft_ssl des | des-ecb | des-cbc [files] [flags]\n\n");
    ft_putstderr("Using pbkdf2 for key generation.\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(DES_flags);
}

static void     print_pbkdf2_usage()
{
    ft_putstderr("Usage: ./ft_ssl pbkdf2 [pwd files] [flags]\n");
    ft_putstderr("Password-Based Key Derivation Function 2 using HMAC-SHA256\n");
    ft_putstderr("Generate 64-bit key from password. Nosalt used by default.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(PBKDF2_flags);
}

static void     print_genprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl genprime [flags]\n");
    ft_putstderr("Generate 64-bit random prime number.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(GENPRIME_flags);
}

static void     print_isprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl isprime [files] [flags]\n");
    ft_putstderr("Handle 64-bit numbers (up to ~19 digits).\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(ISPRIME_flags);
}

static void     print_genrsa_usage()
{
    ft_putstderr("Usage: ./ft_ssl genrsa [flags]\n");
    ft_putstderr("Generating RSA private key, 64 bit long modulus.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(GENRSA_flags);
}

static void     print_rsa_usage()
{
    ft_putstderr("Usage: ./ft_ssl rsa keyfile [flags]\n");
    ft_putstderr("RSA keys visualization.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(RSA_flags);
}

static void     print_rsautl_usage()
{
    ft_putstderr("Usage: ./ft_ssl rsautl file [flags]\n");
    ft_putstderr("RSA cryptosystem utilisation.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(RSAUTL_flags);
}

void    print_command_usage(e_command cmd)
{
    if (cmd & MD)
        print_md_usage();
    else if (cmd & BASE64)
        print_base64_usage();
    else if (cmd & DES)
        print_des_usage();
    else if (cmd & PBKDF2)
        print_pbkdf2_usage();
    else if (cmd & GENPRIME)
        print_genprime_usage();
    else if (cmd & ISPRIME)
        print_isprime_usage();
    else if (cmd & GENRSA)
        print_genrsa_usage();
    else if (cmd & RSA)
        print_rsa_usage();
    else if (cmd & RSAUTL)
        print_rsautl_usage();
    freexit(EXIT_SUCCESS);
}

void    print_commands()
{
    ft_putstderr("usage: ./ft_ssl <command> [files] [flags]\n");
    ft_putstderr("see './ft_ssl <command> -help' for command details.\n");
    ft_putstderr("\nMessage Digest commands:\n\tmd5\n\tsha256\n");
    ft_putstderr("\nCipher commands:\n\tbase64\n\tdes\t(Default as des-cbc)\n\tdes-ecb\n\tdes-cbc\n\tpbkdf2\t(HMAC is computing with sha256)\n");
    ft_putstderr("\nStandard commands:\n\tgenprime\n\tisprime\n\tgenrsa\n\trsa\n\trsautl\n");
    freexit(EXIT_SUCCESS);
}

void    invalid_command(char *cmd)
{
    ft_putstderr("./ft_ssl: '");
    ft_putstderr(cmd);
    ft_putstderr("' is an invalid command.\n");
    ft_putstderr("Type './ft_ssl help' for commands list.\n");
    free(cmd);
    freexit(EXIT_SUCCESS);
}
