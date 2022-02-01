echo "\nUnitests ft_ssl ->\n"
sh unitests_md5.sh $1
echo "\n\n"
sh unitests_sha256.sh $1
echo "\n\n"

sh unitests_des_ecb.sh $1
echo "\n\n"
sh unitests_des_cbc.sh $1
echo "\n\n"
sh unitests_des_cbc_pbkdf2.sh $1
echo "\n\n"

sh unitests_isprime.sh
echo "\n\n"
