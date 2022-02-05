#include "ft_ssl.h"

static void     print_md_usage()
{
    ft_putstderr("Usage: ./ft_ssl md5 | sha256 [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-p\tforce data reception in stdin\n");
    ft_putstderr("\t-s\tinput data as string\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstderr("\t-ai\tdecode the input in base64\n");
    ft_putstderr("\t-ao\tencode the output in base64\n");
    ft_putstderr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstderr("\t-q\tquiet mode\n");
    ft_putstderr("\t-r\treverse the format of the output\n");
}

static void     print_base64_usage()
{
    ft_putstderr("Usage: ./ft_ssl base64 [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-p\tforce data reception in stdin\n");
    ft_putstderr("\t-s\tinput data as string\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-q\tquiet mode\n");
    ft_putstderr("\t-r\treverse the format of the output\n");
    ft_putstderr("\t-e\tencrypt mode (default mode) (-e has priority over -d)\n");
    ft_putstderr("\t-d\tdecrypt mode\n");
}

static void     print_des_usage()
{
    ft_putstderr("Usage: ./ft_ssl des | des-ecb | des-cbc [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstderr("\t-ai\tdecode the input in base64\n");
    ft_putstderr("\t-ao\tencode the output in base64\n");
    ft_putstderr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstderr("\t-q\tquiet mode\n");
    ft_putstderr("\t-r\treverse the format of the output\n");
    ft_putstderr("\t-e\tencrypt mode (default mode) (-e has priority over -d)\n");
    ft_putstderr("\t-d\tdecrypt mode\n");
    ft_putstderr("\t-ecb\tECB mode of DES (Electronic Code Book)\n");
    ft_putstderr("\t-cbc\tCBC mode of DES (Cipher Block Chaining)\n");
    ft_putstderr("\t-k\tsend the key in hex\n");
    ft_putstderr("\t-p\tsend password in ascii\t(Override the behavior of global flag -p)\n");
    ft_putstderr("\t-s\tsend the salt in hex\t(Override the behavior of global flag -s)\n");
    ft_putstderr("\t-v\tsend initialization vector in hex\n");
    ft_putstderr("\t-P\tprint the vector/key and exit\n");
    ft_putstderr("\t-nopad\tdisable standard block padding\n");
    ft_putstderr("\t-iter\tSpecify the iteration count of PBKDF2\n");
}

static void     print_genprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl genprime [files] [flags]\n");
    ft_putstderr("Generate big 64-bits random prime number.\n\n");
    ft_putstderr("Valid flags are:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstderr("\t-ai\tdecode the input in base64\n");
    ft_putstderr("\t-ao\tencode the output in base64\n");
    ft_putstderr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstderr("\t-q\tquiet mode\n");
    // ft_putstderr("\t-r\treverse the format of the output\n");
}

static void     print_isprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl isprime [files] [flags]\n");
    ft_putstderr("Handle 64-bits numbers (up to ~19 digits).\n\n");
    ft_putstderr("Valid flags are:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-p\tforce data reception in stdin\n");
    ft_putstderr("\t-s\tinput data as string\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstderr("\t-ai\tdecode the input in base64\n");
    ft_putstderr("\t-ao\tencode the output in base64\n");
    ft_putstderr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstderr("\t-q\tquiet mode\n");
    ft_putstderr("\t-r\treverse the format of the output\n");
    ft_putstderr("\t-prob\tprobability requested for Miller-Rabin primality test in percentile (0 < p <= 100)\n");
}

static void     print_genrsa_usage()
{
    ft_putstderr("Usage: ./ft_ssl genrsa [files] [flags]\n");
    ft_putstderr("Generating RSA private key, 64-bits long modulus.\n\n");
    ft_putstderr("Valid flags are:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstderr("\t-ai\tdecode the input in base64\n");
    ft_putstderr("\t-ao\tencode the output in base64\n");
    ft_putstderr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstderr("\t-q\tquiet mode\n");
    // ft_putstderr("\t-r\treverse the format of the output\n");
    ft_putstderr("\t-des\tencrypt the private key with des-cbc before outputting it. DES options:\n");
    ft_putstderr("\t\t-ecb\tECB mode of DES (Electronic Code Book)\n");
    ft_putstderr("\t\t-cbc\tCBC mode of DES (Cipher Block Chaining)\n");
    ft_putstderr("\t\t-k\tsend the key in hex\n");
    ft_putstderr("\t\t-p\tsend password in ascii\t(Override the behavior of global flag -p)\n");
    ft_putstderr("\t\t-s\tsend the salt in hex\t(Override the behavior of global flag -s)\n");
    ft_putstderr("\t\t-v\tsend initialization vector in hex\n");
    ft_putstderr("\t\t-P\tprint the vector/key and exit\n");
    ft_putstderr("\t\t-nopad\tdisable standard block padding\n");
    ft_putstderr("\t\t-iter\tSpecify the iteration count of PBKDF2\n");
}

void    print_command_usage(e_command cmd)
{
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
    freexit(EXIT_SUCCESS);
}

void    print_global_usage()
{
    ft_putstderr("usage: ./ft_ssl <command> [files] [flags]\n");
    ft_putstderr("see './ft_ssl <command> -help' for commands details.\n");
    ft_putstderr("\nMessage Digest commands:\n\tmd5\n\tsha256\n");
    ft_putstderr("\nCipher commands:\n\tbase64\n\tdes\t(Default as des-cbc)\n\tdes-ecb\n\tdes-cbc\n");
    ft_putstderr("\nStandard commands:\n\tgenprime\n\tisprime\n\tgenrsa\n");
    freexit(EXIT_SUCCESS);
}
