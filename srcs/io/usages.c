#include "ft_ssl.h"

static void     print_flag_usage(e_flags flag)
{
    if (flag & help)
        ft_putstderr("\t-help\tdisplay this summary and exit\n");
    else if (flag & i_)
        ft_putstderr("\t-i\tinput data as file\n");
    else if (flag & o)
        ft_putstderr("\t-o\toutput file\n");
    else if (flag & a)
        ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    else if (flag & A)
        ft_putstderr("\t-A\tused with -[a | -decin base64 | -encout base64] to specify base64 buffer as a single line\n");
    else if (flag & decin)
        ft_putstderr("\t-decin\tdecode the input with the given hashing command (command flags can ONLY be passed after)\n");
    else if (flag & encout)
        ft_putstderr("\t-encout\tencode the output with the given hashing command (command flags can ONLY be passed after)\n");
    else if (flag & q)
        ft_putstderr("\t-q\tquiet mode\n");
    else if (flag & r)
        ft_putstderr("\t-r\treverse the format of the output\n");
    else if (flag & s)
        ft_putstderr("\t-s\tinput data as string\n");
    else if (flag & p)
        ft_putstderr("\t-p\tforce data reception in stdin\n");
    else if (flag & e)
        ft_putstderr("\t-e\tencrypt mode (default mode) (-e has priority over -d)\n");
    else if (flag & d)
        ft_putstderr("\t-d\tdecrypt mode\n");
    else if (flag & passin)
        ft_putstderr("\t-passin\tsend password for input decryption (flag -decin <cmd> needs to exist before)\n");
    else if (flag & passout)
        ft_putstderr("\t-passout\tsend password for output encryption (flag -encout <cmd> needs to exist before)\n");
    else if (flag & p_des)
        ft_putstderr("\t-p\tsend the password in hex\t(Override the behavior of global flag -p if any des command is past)\n");
    else if (flag & s_des)
        ft_putstderr("\t-s\tsend the salt in hex\t(Override the behavior of global flag -s if any des command is past)\n");
    else if (flag & k_des)
        ft_putstderr("\t-k\tsend the key in hex\n");
    else if (flag & v_des)
        ft_putstderr("\t-v\tsend initialization vector in hex\n");
    else if (flag & P_des)
        ft_putstderr("\t-P\tprint the vector/key and exit\n");
    else if (flag & nopad)
        ft_putstderr("\t-nopad\tdisable standard block padding\n");
    else if (flag & pbkdf2_iter)
        ft_putstderr("\t-iter\tspecify the iteration count of PBKDF2\n");
    else if (flag & prob)
        ft_putstderr("\t-prob\tprobability requested for Miller-Rabin primality test in percentile (0 < p <= 100)\n");
    else if (flag & min)
        ft_putstderr("\t-min\tlower bound for prime generation (Default as 0)\n");
    else if (flag & max)
        ft_putstderr("\t-max\tupper bound for prime generation (Default as 2^63 - 1)\n");
    else if (flag & rand_path)
        ft_putstderr("\t-rand\ta file containing random data used to seed the random number generator\n");
    else if (flag & inform)
        ft_putstderr("\t-inform\tinput format [PEM | DER] (Default as PEM)\n");
    else if (flag & outform)
        ft_putstderr("\t-outform\toutput format [PEM | DER] (Default as PEM)\n");
    else if (flag & check)
        ft_putstderr("\t-check\tverify key consistency\n");
    else if (flag & noout)
        ft_putstderr("\t-noout\tdon't print key out\n");
    else if (flag & text)
        ft_putstderr("\t-text\tprint key propoerties in hex\n");
    else if (flag & modulus)
        ft_putstderr("\t-modulus print RSA key modulus in hex\n");
    else if (flag & pubin)
        ft_putstderr("\t-pubin\texpect a public key in input file (private key by default)\n");
    else if (flag & pubout)
        ft_putstderr("\t-pubout\toutput a public key (private key by default). This option is automatically set if the input is a public key.\n");
    else
    {
        printf("WTFF ?\n");
        exit(0);
    }
}

static void     print_command_flags(e_flags flags)
{
    for (Long_64bits i = 1, flag = 1<<1; i < N_FLAGS + 1; i++, flag <<= 1)
    {
        // printf("flag %d: %d & %d = %d\n", i, flag, rand_path, flag & flags);
        if (flag & flags)
            print_flag_usage(flag);
    }
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
    ft_putstderr("Valid flags are:\n");
    print_command_flags(DES_flags);
}

static void     print_genprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl genprime [files] [flags]\n");
    ft_putstderr("Generate 64-bits random prime number.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(GENPRIME_flags);
}

static void     print_isprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl isprime [files] [flags]\n");
    ft_putstderr("Handle 64-bits numbers (up to ~19 digits).\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(ISPRIME_flags);
}

static void     print_genrsa_usage()
{
    ft_putstderr("Usage: ./ft_ssl genrsa [files] [flags]\n");
    ft_putstderr("Generating RSA private key, 64 bit long modulus.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(GENRSA_flags);
}

static void     print_rsa_usage()
{
    ft_putstderr("Usage: ./ft_ssl rsa [files] [flags]\n");
    ft_putstderr("RSA keys visualization.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(RSA_flags);
}

void    print_command_usage(e_command cmd)
{
    // Transform to list of function pt
    if (cmd & MD)
        print_md_usage();
    else if (cmd & BASE64)
        print_base64_usage();
    else if (cmd & DES)
        print_des_usage();
    else if (cmd & GENPRIME)
        print_genprime_usage();
    else if (cmd & ISPRIME)
        print_isprime_usage();
    else if (cmd & GENRSA)
        print_genrsa_usage();
    else if (cmd & RSA)
        print_rsa_usage();
    freexit(EXIT_SUCCESS);
}

void    print_commands()
{
    ft_putstderr("usage: ./ft_ssl <command> [files] [flags]\n");
    ft_putstderr("see './ft_ssl <command> -help' for command details.\n");
    ft_putstderr("\nMessage Digest commands:\n\tmd5\n\tsha256\n");
    ft_putstderr("\nCipher commands:\n\tbase64\n\tdes\t(Default as des-cbc)\n\tdes-ecb\n\tdes-cbc\n");
    ft_putstderr("\nPrime numbers commands:\n\tgenprime\n\tisprime\n");
    ft_putstderr("\nStandard commands:\n\tgenrsa\n");
    freexit(EXIT_SUCCESS);
}

void    print_global_usage()
{
    ft_putstderr("Type './ft_ssl help' for commands list.\n");
    freexit(EXIT_SUCCESS);
}
