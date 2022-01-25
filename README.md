    Recode a part of openssl library

Author: agiordan




usage: ft_ssl <algorithm> [flags] [file | string]


Global flags:
    -help   Display this summary and exit
    -i      input file for plaintext
    -o      output file for hash
    -q      quiet mode


Message Digest commands:
    md5
    sha256
Message Digest flags:
    -p      echo STDIN to STDOUT and append the checksum to STDOUT
    -r      reverse the format of the output
    -s      print the sum of the given string


Cipher commands:
    base64
    des     (Default as des-cbc)
    des-ecb
    des-cbc
Cipher flags:
    -e      encrypt mode (default mode) (-e has priority over -d)
    -d      decrypt mode
    -a      decode/encode the input/output in base64, depending on the encrypt mode
    -ai     decode the input in base64
    -ao     encode the output in base64
    -A      Used with -[a | ai | ao] to specify base64 buffer as a single line
    -k      send the key in hex
    -p      send password in ascii
    -s      send the salt in hex
    -v      send initialization vector in hex
    -P      print the vector/key and exit
    -nopad  disable standard block padding


Standard commands:
    Not yet...


Road map:

- srcs structure
- Makefile en fonction de la nouvelle struct de srcs 
- rsa prime number gemerator

