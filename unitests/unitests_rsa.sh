make -C .. > /dev/null
cp ../ft_ssl . > /dev/null

echo "\n --- Unitests isprime: This script will display others things than 'writing RSA key' if a potential error is found"

# 12 possibles cases with rsa command:
#   -> 4 cases in and 4 cases out (16 possibilities),
#       but few cases are impossible (pub to priv)

# Binary sheme with 4 bits:
#           X_X to X_X

# 0 : PEM_pub   to  PEM_pub
# 1 : PEM_pub   to  PEM_priv    # Impossible !
# 2 : PEM_pub   to  DER_pub
# 3 : PEM_pub   to  DER_priv    # Impossible !
# 4 : PEM_priv  to  PEM_pub
# 5 : PEM_priv  to  PEM_priv
# 6 : PEM_priv  to  DER_pub
# 7 : PEM_priv  to  DER_priv

# 8 : DER_pub   to  PEM_pub
# 9 : DER_pub   to  PEM_priv    # Impossible !
# 10: DER_pub   to  DER_pub
# 11: DER_pub   to  DER_priv    # Impossible !
# 12: DER_priv  to  PEM_pub
# 13: DER_priv  to  PEM_priv
# 14: DER_priv  to  DER_pub
# 15: DER_priv  to  DER_priv



    # - TESTS

# Generate private key in PEM and DER forms
echo "\nGenerate PEM_privkey and DER_privkey ->"
./ft_ssl genrsa -o PEM_privkey
openssl rsa -in PEM_privkey -outform DER -out DER_privkey


# First test (Compare ft_ssl cycle AND openssl DER_priv / DER_pub)
# Cycle test :

    # 13: DER_priv  to  PEM_priv
    # 5 : PEM_priv  to  PEM_priv
    # 7 : PEM_priv  to  DER_priv
    # 15: DER_priv  to  DER_priv

    # 14: DER_priv  to  DER_pub

    # 8 : DER_pub   to  PEM_pub
    # 0 : PEM_pub   to  PEM_pub
    # 2 : PEM_pub   to  DER_pub
    # 10: DER_pub   to  DER_pub

echo "\nTest 1: 9 ft_ssl cycles compare to 1 openssl (DER_priv to DER_pub) ->"
./ft_ssl rsa -inform DER -outform PEM -i DER_privkey |\
./ft_ssl rsa -inform PEM -outform PEM |\
./ft_ssl rsa -inform PEM -outform DER |\
./ft_ssl rsa -inform DER -outform DER |\
./ft_ssl rsa -inform DER -outform DER -pubout |\
./ft_ssl rsa -inform DER -pubin -outform PEM -pubout |\
./ft_ssl rsa -inform PEM -pubin -outform PEM -pubout |\
./ft_ssl rsa -inform PEM -pubin -outform DER -pubout |\
./ft_ssl rsa -inform DER -pubin -outform DER -pubout -o ft_ssl_out
openssl rsa -inform DER -outform DER -pubout -in DER_privkey -out openssl_out
diff ft_ssl_out openssl_out


echo "\nTest 2: Compare ft_ssl and openssl (DER_priv to PEM_pub) ->"
# Second test (Compare ft_ssl AND openssl):
    # 12: DER_priv  to  PEM_pub
./ft_ssl rsa -i DER_privkey -inform DER -outform PEM -pubout -o ft_ssl_out
openssl rsa -in DER_privkey -inform DER -outform PEM -pubout -out openssl_out
diff ft_ssl_out openssl_out


echo "\nTest 3: Compare ft_ssl and openssl (PEM_priv to DER_pub) ->"
# Third test (Compare ft_ssl AND openssl):
    # 6 : PEM_priv  to  DER_pub
./ft_ssl rsa -i PEM_privkey -outform DER -pubout -o ft_ssl_out
openssl rsa -in PEM_privkey -outform DER -pubout -out openssl_out
diff ft_ssl_out openssl_out


echo "\nTest 4: Compare ft_ssl and openssl (DES encryption) ->"
# Others tests
./ft_ssl rsa -i PEM_privkey -outform DER -pubout -encout des-ecb -passout pwdpwd |\
./ft_ssl rsa -inform DER -pubin -decin des-ecb -passin pwdpwd -o ft_ssl_out
openssl rsa -in PEM_privkey -pubout -out openssl_out
diff ft_ssl_out openssl_out

rm ft_ssl PEM_privkey DER_privkey ft_ssl_out openssl_out
