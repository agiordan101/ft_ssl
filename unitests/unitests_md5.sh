make -C .. > /dev/null
cp ../ft_ssl . > /dev/null

echo "\n --- Unitests md5: This script will display differences if errors are found"

echo "(stdin)= 35f1d6de0302e2086a4e472266efb3a9
(\"42 is nice\")= 35f1d6de0302e2086a4e472266efb3a9
e20c3b973f63482a778f3fd1869b7f25
MD5(file)= 53d53ea94217b259c11a5a2d104ec58a
53d53ea94217b259c11a5a2d104ec58a file
MD5(\"pity those that aren't following baerista on spotify.\")= a3c990a1964705d9bf0e602f44572f5f
(\"be sure to handle edge cases carefully\")= 3553dc7dc5963b583c056d1b9fa3349c
MD5(file)= 53d53ea94217b259c11a5a2d104ec58a
MD5(file)= 53d53ea94217b259c11a5a2d104ec58a
(\"but eventually you will understand\")= dcdd84e0f635694d2a943fa8d3905281
53d53ea94217b259c11a5a2d104ec58a file
(\"GL HF let's go\")= d1e3cc342b6da09480b27ec57ff243e2
MD5(\"foo\")= acbd18db4cc2f85cedef654fccc4a4d8
MD5(file)= 53d53ea94217b259c11a5a2d104ec58a
(\"one more thing\")= a0bd1876c6f011dd50fae52827f445f5
acbd18db4cc2f85cedef654fccc4a4d8 \"foo\"
53d53ea94217b259c11a5a2d104ec58a file
just to be extra clear
3ba35f1ea0d170cb3b9a752e3360286c
acbd18db4cc2f85cedef654fccc4a4d8
53d53ea94217b259c11a5a2d104ec58a" > md5_subject_responses

echo "42 is nice" | ./ft_ssl md5 > md5_responses
echo "42 is nice" | ./ft_ssl md5 -p >> md5_responses
echo "Pity the living." | ./ft_ssl md5 -q -r >> md5_responses
echo "And above all," > file
./ft_ssl md5 file >> md5_responses
./ft_ssl md5 -r file >> md5_responses
./ft_ssl md5 -s "pity those that aren't following baerista on spotify." >> md5_responses
echo "be sure to handle edge cases carefully" | ./ft_ssl md5 -p file >> md5_responses
echo "some of this will not make sense at first" | ./ft_ssl md5 file >> md5_responses
echo "but eventually you will understand" | ./ft_ssl md5 -p -r file >> md5_responses
echo "GL HF let's go" | ./ft_ssl md5 -p -s "foo" file >> md5_responses
echo "one more thing" | ./ft_ssl md5 -r -p -s "foo" file -s "bar" >> md5_responses
echo "just to be extra clear" | ./ft_ssl md5 -r -q -p -s "foo" file >> md5_responses

diff md5_responses md5_subject_responses
rm md5_responses md5_subject_responses file ft_ssl