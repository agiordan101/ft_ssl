make
sh unitests_des_ecb.sh $1
echo "\n\n\n"
sh unitests_des_cbc.sh $1
echo "\n\n\n"
sh unitests_des_cbc_pbkdf2.sh $1