# include "ft_ssl.h"

/*        
    RSA keys parsing with DER format
*/

static Mem_8bits    *DER_tag_integer_parsing(Mem_8bits *mem, t_dertag *tag, Long_64bits *integer)
{
    if (!*(mem + tag->header_length))       // Handle possible leading zero (00 byte) before INTEGERS tag
    {
        mem++;
        tag->content_length--;
    }

    ft_bzero(integer, LONG64_byteSz);
    if (tag->content_length <= LONG64_byteSz)
    {
        // Read 64 bit integer
        ft_memcpy(integer, mem + tag->header_length, tag->content_length);
        endianReverse((Mem_8bits *)integer, tag->content_length);        // Like openssl
    }
    else
        rsa_keys_integer_size_error(tag->content_length);
    return ft_memdup(mem + tag->header_length, tag->content_length);
}

static void        DER_tag_parsing(Mem_8bits *mem, t_dertag *tag)
{
    ft_bzero(tag, sizeof(t_dertag));

    tag->tag_number = *mem;
    mem++;

    // Count additionnal length octets numbers
    int additional_length_octets = *mem & 0x80 ? *mem & 0x7f : 0;
    if (additional_length_octets)
    {
        tag->length_octets_number = additional_length_octets;                      // Add first length octet number
        mem++;
    }
    else
        tag->length_octets_number = 1;

    for (
        int i = 0, hexexp = 1 << ((tag->length_octets_number - 1) * LONG64_byteSz);\
        i < tag->length_octets_number;\
        i++, hexexp >>= LONG64_byteSz
    )
        tag->content_length += mem[i] * hexexp;                 // Sum content length (Concat binary values in big endian)

    tag->length_octets_number = 1 + additional_length_octets;   // Add first length octet number
    tag->header_length = 1 + tag->length_octets_number;         // tag number + length octets numbers
    tag->total_length = tag->header_length + tag->content_length;
}

static void        DER_read_key(Mem_8bits *mem, int byteSz, Long_64bits *integers, Mem_8bits **bigints, int *bigints_byteSz, int n_int, e_flags keyflag)
{
    Mem_8bits   *mem_end = mem + byteSz;
    int         i = 0;
    t_dertag    tag;

    // Search n_int integers
    while (mem < mem_end && i < n_int)
    {
        DER_tag_parsing(mem, &tag);

        if (tag.tag_number == der_integer)
        {
            bigints[i] = DER_tag_integer_parsing(mem, &tag, integers + i);
            if (bigints_byteSz)
                bigints_byteSz[i] = tag.content_length;
            i++;
            mem += tag.total_length;
        }
        else if (tag.tag_number == der_OID)
            mem += tag.total_length;        // Always the same, skip it
        else if (tag.tag_number == der_bitstring)
            mem += tag.header_length + 1;   // Handle 00 byte of bit string tag
        else if (
            tag.tag_number == der_null ||\
            tag.tag_number == der_sequence
        )
            mem += tag.header_length;       // Dig inside sequence or pass null
        else
            rsa_parsing_keys_error(keyflag & pubin, DER, "Unknow DER tag ", tag.tag_number);
    }
    if (i < n_int)
        rsa_parsing_keys_error(keyflag & pubin, DER, "Unable to fetch all integers, missing ", n_int - i);
    if (mem < mem_end)
        rsa_parsing_keys_error(keyflag & pubin, DER, "Additional bytes found: ", mem_end - mem);
}

inline Mem_8bits   *rsa_DER_keys_parsing(t_rsa *rsa, Mem_8bits *file_content, int fileSz, e_flags keyflag)
{
    if (keyflag & pubin)
    {
        Long_64bits integers[RSA_PUBLIC_KEY_INTEGERS_COUNT];     // Try to put one
        Mem_8bits   *bigints[RSA_PUBLIC_KEY_INTEGERS_COUNT];

        DER_read_key(file_content, fileSz, integers, bigints, NULL, RSA_PUBLIC_KEY_INTEGERS_COUNT, keyflag);
        ft_memcpy(&rsa->pubkey, integers, sizeof(t_rsa_public_key));
        ft_memcpy(&rsa->pubkey_bigint, bigints, sizeof(t_rsa_public_key_bigint));
    }
    else
    {
        Long_64bits integers[RSA_PRIVATE_KEY_INTEGERS_COUNT];
        Mem_8bits   *bigints[RSA_PRIVATE_KEY_INTEGERS_COUNT];
        int         bigints_byteSz[RSA_PRIVATE_KEY_INTEGERS_COUNT];

        DER_read_key(file_content, fileSz, integers, bigints, bigints_byteSz, RSA_PRIVATE_KEY_INTEGERS_COUNT, keyflag);
        ft_memcpy(&rsa->privkey, integers, sizeof(t_rsa_private_key));
        ft_memcpy(&rsa->privkey_bigint, bigints, sizeof(t_rsa_private_key_bigint));
        ft_memcpy(&rsa->privkey_bigint_byteSz, bigints_byteSz, sizeof(t_rsa_private_key_bigint_byteSz));
    }
    return file_content;
}

/*        
    RSA keys generation with DER format
*/

Mem_8bits          *DER_generate_public_key_bigint(Mem_8bits *modulus, int modulus_byteSz, Mem_8bits *enc_exp, int enc_exp_byteSz, int *hashByteSz)
{
    modulus_byteSz++;       // Add leading zero
    int modulus_header_byteSz = modulus_byteSz / 0x80 + 2;         // Byte-length count + tag number + 00 byte (leading zero)

    int enc_exp_header_byteSz = enc_exp_byteSz / 0x80 + 2;

    int ints_sequence_length = enc_exp_header_byteSz + enc_exp_byteSz + modulus_header_byteSz + modulus_byteSz;                 // Add their header length
    int ints_sequence_header_byteSz = ints_sequence_length / 0x80 + 2;
    
    int bit_string_length = ints_sequence_header_byteSz + ints_sequence_length + 1;                           // Add its tag number + 00 byte from bit string + header length
    int bit_string_header_byteSz = bit_string_length / 0x80 + 2;

    int key_sequence_length = DER_OID_SEQUENCE_bytes_byteSz + bit_string_header_byteSz + bit_string_length;                  // Add bit-string tag + header length
    int key_sequence_header_byteSz = key_sequence_length / 0x80 + 2;

    *hashByteSz = key_sequence_header_byteSz + key_sequence_length;                                      // +2 to add first header length

    Mem_8bits DER_pubkey[*hashByteSz];
    ft_bzero(DER_pubkey, *hashByteSz);
    int         der_i = 0;

    // First tag: sequence of OID and bit-string
    DER_pubkey[der_i++] = der_sequence;
    if (key_sequence_length < 0x80)
        DER_pubkey[der_i++] = key_sequence_length;
    else
    {
        DER_pubkey[der_i++] = 0x80 | (key_sequence_length / 0x100 + 1);
        DER_pubkey[der_i++] = key_sequence_length / 0x100;
        DER_pubkey[der_i++] = key_sequence_length % 0x100;
    }

    // OID value, unique for RSA algorithm
    ft_memcpy(DER_pubkey + der_i, DER_OID_SEQUENCE_bytes, DER_OID_SEQUENCE_bytes_byteSz);
    der_i += DER_OID_SEQUENCE_bytes_byteSz;

    // Bit-string of sequence of integers
    DER_pubkey[der_i++] = der_bitstring;
    if (bit_string_length < 0x80)
        DER_pubkey[der_i++] = bit_string_length;
    else
    {
        DER_pubkey[der_i++] = 0x80 | (bit_string_length / 0x100 + 1);
        DER_pubkey[der_i++] = bit_string_length / 0x100;
        DER_pubkey[der_i++] = bit_string_length % 0x100;
    }
    der_i++;    // 00 byte (Number of unused bits in last content byte)

    // sequence of integers
    DER_pubkey[der_i++] = der_sequence;
    if (ints_sequence_length < 0x80)
        DER_pubkey[der_i++] = ints_sequence_length;
    else
    {
        DER_pubkey[der_i++] = 0x80 | (ints_sequence_length / 0x100 + 1);
        DER_pubkey[der_i++] = ints_sequence_length / 0x100;
        DER_pubkey[der_i++] = ints_sequence_length % 0x100;
    }

    // Write modulus
    DER_pubkey[der_i++] = der_integer;
    if (modulus_byteSz < 0x80)
    {
        DER_pubkey[der_i++] = modulus_byteSz;
    }
    else
    {
        DER_pubkey[der_i++] = 0x80 | (modulus_byteSz / 0x100 + 1);
        DER_pubkey[der_i++] = modulus_byteSz / 0x100;
        DER_pubkey[der_i++] = modulus_byteSz % 0x100;
    }
    der_i++;                            // Leading zero
    ft_memcpy(DER_pubkey + der_i, modulus, modulus_byteSz);
    der_i += modulus_byteSz - 1;        //Leading zero already add to der_i

    // Write public exponent
    DER_pubkey[der_i++] = der_integer;
    DER_pubkey[der_i++] = enc_exp_byteSz;
    ft_memcpy(DER_pubkey + der_i, enc_exp, enc_exp_byteSz);

    return ft_memdup(DER_pubkey, *hashByteSz);
}

Mem_8bits          *DER_generate_public_key(t_rsa_public_key *pubkey, int *hashByteSz)
{
    /*
        RSA public key in DER format is structured as follow (Truth OID for RSA keys but random modulus):

        30 24                                  // Type: 30 (SEQUENCE)
        |  30 0D                               // Type: 30 (SEQUENCE)
        |  |  06 09                            // Type: 06 (OBJECT_IDENTIFIER)
        |  |  -  2A 86 48                      // 9 bytes OID value. HEX encoding of
        |  |  -  86 F7 0D                      //     1.2.840.113549.1.1.1
        |  |  -  01 01 01                      // Represented by DER_OID_SEQUENCE_bytes
        |  |  05 00                            // Type: 05 (NULL)
        |  03 13                               // Type: 03 (BIT STRING)
        |  |  -  00                            // Number of unused bits in last content byte
        |  |  30 10                            // Type: 30 (SEQUENCE)
        |  |  |  02 09                         // Type: 02 (INTEGER)
        |  |  |  -  00                         // Leading ZERO of integer
        |  |  |  -  D1 14 D5 3E FB DD DA 12
        |  |  |  02 03                         // Type: 02 (INTEGER)
        |  |  |  -  01 00 01                   // Public Exponent (65537)
    */
    int exp_length = count_bytes(pubkey->enc_exp);
    
    int modulus_length = count_bytes(pubkey->modulus);                    // +1 to add 00 byte / leading zero
    endianReverse((Mem_8bits *)&pubkey->modulus, modulus_length);           // Like openssl
    int modulus_leading_zero = (0x80 <= (pubkey->modulus & 0xF0));
    if (modulus_leading_zero)
        modulus_length++;

    int ints_sequence_length = exp_length + modulus_length + 4;                 // +4 to add their header length (2 and 2)
    int bit_string_length = ints_sequence_length + 3;                           // +3 to add its   header length and 00 byte from bit string
    int key_sequence_length = DER_OID_SEQUENCE_length + bit_string_length + 4;  // +4 to add their header length (2 and 2)
    *hashByteSz = key_sequence_length + 2;                                      // +2 to add first header length

    Mem_8bits DER_pubkey[*hashByteSz];
    ft_bzero(DER_pubkey, *hashByteSz);

    // First tag: sequence of integers
    DER_pubkey[0] = der_sequence;
    DER_pubkey[1] = key_sequence_length;

    // OID value, unique for RSA algorithm
    ft_memcpy(DER_pubkey + 2, DER_OID_SEQUENCE_bytes, DER_OID_SEQUENCE_bytes_byteSz);

    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz] = der_bitstring;
    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz + 1] = bit_string_length;
    
    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz + 3] = der_sequence;
    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz + 3 + 1] = ints_sequence_length;

    // Write modulus
    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz + 5] = der_integer;
    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz + 5 + 1] = modulus_length;
    if (modulus_leading_zero)
        ft_memcpy(DER_pubkey + 2 + DER_OID_SEQUENCE_bytes_byteSz + 5 + 3, &pubkey->modulus, modulus_length - 1);
    else
        ft_memcpy(DER_pubkey + 2 + DER_OID_SEQUENCE_bytes_byteSz + 5 + 2, &pubkey->modulus, modulus_length);

    // Write public exponent
    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz + 7 + modulus_length] = der_integer;
    DER_pubkey[2 + DER_OID_SEQUENCE_bytes_byteSz + 7 + modulus_length + 1] = exp_length;
    ft_memcpy(DER_pubkey + 2 + DER_OID_SEQUENCE_bytes_byteSz + 7 + modulus_length + 2, &pubkey->enc_exp, exp_length);

    // printBits(DER_pubkey, *hashByteSz);
    return ft_memdup(DER_pubkey, *hashByteSz);
}

Mem_8bits          *DER_generate_private_key(t_rsa_private_key *privkey, int *hashByteSz)
{
    /*
        RSA public key in DER format is structured as follow (Random integers):

        30 5C                                  // Type: 30 (SEQUENCE)
        |  02 08                               // Type: 02 (INTEGER)
        |  -  D1 14 D5 3E FB DD DA 12
        |  02 08                               // Type: 02 (INTEGER)
        |  -  D1 14 D5 3E FB DD DA 12
        |  ...
        |  02 08                               // Type: 02 (INTEGER)
        |  -  D1 14 D5 3E FB DD DA 12
    */
    int         sequence_byteSz = 0;
    int         ints_byteSz[RSA_PRIVATE_KEY_INTEGERS_COUNT];
    Long_64bits integers[RSA_PRIVATE_KEY_INTEGERS_COUNT] = {
        privkey->version, privkey->modulus,
        privkey->enc_exp, privkey->dec_exp, privkey->p, privkey->q,
        privkey->crt_dmp1, privkey->crt_dmq1, privkey->crt_iqmp
    };
    int         leading_zeros[RSA_PRIVATE_KEY_INTEGERS_COUNT] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    // Count byteSz of integers and check there leading zeros
    for (int i = 0; i < RSA_PRIVATE_KEY_INTEGERS_COUNT; i++)
    {
        ints_byteSz[i] = count_bytes(integers[i]);

        endianReverse((Mem_8bits *)(integers + i), ints_byteSz[i]);        // Like openssl
        leading_zeros[i] = (0x80 <= (integers[i] & 0xF0));

        if (leading_zeros[i])
            ints_byteSz[i] += 1;

        sequence_byteSz += ints_byteSz[i] + 2;          // +2 -> INTEGER header (tag type + length)
    }
    *hashByteSz = sequence_byteSz + 2;                  // +2 -> SEQUENCE header (tag type + length)
    
    Mem_8bits DER_privkey[*hashByteSz];
    ft_bzero(DER_privkey, *hashByteSz);

    // First tag: sequence of integers
    DER_privkey[0] = der_sequence;
    DER_privkey[1] = sequence_byteSz;

    // Concatenate each integers with there headers
    int k = 2;
    for (int i = 0; i < RSA_PRIVATE_KEY_INTEGERS_COUNT; i++)
    {
        DER_privkey[k] = der_integer;
        DER_privkey[k + 1] = ints_byteSz[i];

        if (leading_zeros[i])
            ft_memcpy(DER_privkey + k + 3, integers + i, ints_byteSz[i] - 1);
        else
            ft_memcpy(DER_privkey + k + 2, integers + i, ints_byteSz[i]);

        k += ints_byteSz[i] + 2;
    }

    // printBits(DER_privkey, *hashByteSz);
    return ft_memdup(DER_privkey, *hashByteSz);
}
