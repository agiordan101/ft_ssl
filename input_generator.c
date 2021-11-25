int main(int argc, char **argv)
{
    char key[8] = {
        '\x12',
        '\x34',
        '\x56',
        '\xab',
        '\xcd',
        '\x13',
        '\x25',
        '\x36'
    };
    // char key[8] = {
    //     '\x36',
    //     '\x25',
    //     '\x13',
    //     '\xcd',
    //     '\xab',
    //     '\x56',
    //     '\x34',
    //     '\x12'
    // };
    printf("%s", key);
}