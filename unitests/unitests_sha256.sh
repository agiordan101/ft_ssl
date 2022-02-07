make -C .. > /dev/null
cp ../ft_ssl . > /dev/null

echo "\n --- Unitests sha256: This script will display differences if a potential error is found"

echo "1ceb55d2845d9dd98557b50488db12bbf51aaca5aa9c1199eb795607a2457dafSHA256(\"42 is nice\")= b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f" > sha256_subject_responses

echo "https://www.42.fr/" > website
./ft_ssl sha256 -q website > sha256_responses
./ft_ssl sha256 -s "42 is nice" >> sha256_responses

diff sha256_responses sha256_subject_responses
rm sha256_responses sha256_subject_responses website ft_ssl