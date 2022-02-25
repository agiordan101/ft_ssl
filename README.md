DESCRIPTION
==

**usage: ./ft_ssl command [files] [flags]**

Recode a part of **openssl** library, and additionnal features, from scratch.

Only these externals functions are used (**no C libraries allowed**) :  
    - open()  
    - close()  
    - read()  
    - write()  
    - malloc()  
    - perror()  
    - exit()  



COMMANDS
==
A random exemple with possible flags is given for each command

Message Digest commands
-
* md5  
    ./ft_ssl md5 -i Makefile -o ft_ssl_out
* sha256  
    echo "42" | ./ft_ssl sha256 Makefile -p

Cipher commands
-
* base64
* des       (Default as des-cbc)  
* des-cbc
* des-ecb
    echo "Coucou" | ./ft_ssl base64 -q | ./ft_ssl base64 -d
    ./ft_ssl des -i Makefile -v 0123456789abcdef -k 1415926535 -q
    ./ft_ssl des-cbc Makefile -v 0123456789abcdef -o ft_ssl_out
    cat Makefile | ./ft_ssl des-ecb -k acbbca
    ./ft_ssl des-ecb Makefile -s 542842e266c5541a -p mybigpassword -iter 666

Standard commands
-
* genprime
    ./ft_ssl genprime -rand seed_file -min 1000 -max 10000
* isprime
    ./ft_ssl genprime | ./ft_ssl isprime -s 45 -p
* genrsa
    ./ft_ssl genrsa -encout des -v 0123456789abcdef -k 1415926535
    ./ft_ssl genrsa -pubout -outform DER
* rsa
    ./ft_ssl genrsa | ./ft_ssl rsa -text -check
* rsautl



FLAGS
==

Each commands has some of these flags

Global flags :
-
    -help           display this summary and exit
    -i              input file for plaintext
    -o              output file for hash
    -decin          decode the input with the given hashing command (command flags can ONLY be passed after)
    -passin         send password for input decryption (flag -decin <cmd> needs to exist before)
    -encout         encode the output with the given hashing command (command flags can ONLY be passed after)
    -passout        send password for output encryption (flag -encout <cmd> needs to exist before)
    -a              decode/encode the input/output in base64, depending on the encrypt mode
    -A              used with -[a | -decin base64 | -encout base64] to specify base64 buffer as a single line
    -s              print the sum of the given string
    -p              echo STDIN to STDOUT and append the checksum to STDOUT
    -r              reverse the format of the output
    -q              quiet mode

Only ciphers flags
-
    -e              encrypt mode (default mode) (-e has priority over -d)
    -d              decrypt mode

    Only DES :
        -k          send the key in hex
        -s          send the salt in hex (Overwrite global -s behavior)
        -p          send password in ascii (Overwrite global -s behavior)
        -v          send initialization vector in hex
        -P          print the vector/key and exit
        -nopad      disable standard block padding
        -iter       specify the iteration count of PBKDF2

Only RSA cryptosystem flags
-
    -pubin          expect a public key in input file (private key by default)
    -pubout         output a public key (private key by default). This option is automatically set if the input is a public key.
    -inform         input format [PEM | DER] (Default as PEM)
    -outform        output format [PEM | DER] (Default as PEM)
    -text           print key properties in hex
    -modulus        print RSA key modulus in hex
    -check          verify key consistency
    -noout          don't print key out
    -rand           a file containing random data used to seed the random rsa generator

Only genprime flags
-
    -min            lower bound for prime generation (Default as 0)
    -max            upper bound for prime generation (Default as 2^63 - 1)
    -rand           a file containing random data used to seed the random rsa generator

Only isprime flags
-
    -prob           probability requested for Miller-Rabin primality test in percentile (0 < p <= 100)
