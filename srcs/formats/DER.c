# include "ft_ssl.h"

/*        
    RSA keys parsing with DER format
*/

static void        print_tag(t_dertag *tag)
{
    printf("\ntag->tag_number: %x\n", tag->tag_number);
    printf("tag->length_octets_number: %x\n", tag->length_octets_number);
    printf("tag->header_length: %x\n", tag->header_length);
    printf("tag->content_length: %x\n", tag->content_length);
    printf("tag->total_length: %x\n", tag->total_length);
}

static Long_64bits DER_tag_integer_parsing(Mem_8bits *mem, t_dertag *tag)
{
    // print_tag(tag);
    if (tag->content_length > 8)
    {
        return 0;
        rsa_keys_integer_size_error(tag->content_length);
    }

    Mem_8bits   content[LONG64_byteSz];
    ft_bzero(content, LONG64_byteSz);
    ft_memcpy(content, mem + tag->header_length, tag->content_length);

    return *((Long_64bits *)content);
}

static void        DER_tag_parsing(Mem_8bits *mem, t_dertag *tag)
{
    ft_bzero(tag, sizeof(t_dertag));

    tag->tag_number = *mem;
    mem++;

    if (tag->tag_number == 0)
    {
        printf("exit bc tag number = 0\n");
        printf("content left: >%s<\n", *mem);
        exit(0);
    }

    // Count additionnal length octets numbers
    int additional_length_octets = *mem & 0x80 ? *mem & 0x7f : 0;
    if (additional_length_octets)
    {
        tag->length_octets_number = additional_length_octets;                      // Add first length octet number
        mem++;
    }
    else
        tag->length_octets_number = 1;

    // printf("tag->length_octets_number: %x\n", tag->length_octets_number);
    for (
        int i = 0, hexexp = 1 << ((tag->length_octets_number - 1) * 8);\
        i < tag->length_octets_number;\
        i++, hexexp >>= 8
    )
        tag->content_length += mem[i] * hexexp;                 // Sum content length (Concat binary values in big endian)

    tag->length_octets_number = 1 + additional_length_octets;   // Add first length octet number
    tag->header_length = 1 + tag->length_octets_number;         // tag number + length octets numbers
    tag->total_length = tag->header_length + tag->content_length;
}

static void        DER_read_key(Mem_8bits *mem, int byteSz, Long_64bits *integers, int n_int)
{
    Mem_8bits   *mem_end = mem + byteSz;
    int         i = 0;
    t_dertag    tag;

    // Skip tous ce qui n'est pas du 0x20
    while (mem < mem_end && i < n_int)
    {
        if (*mem == 0)
            mem++;
        DER_tag_parsing(mem, &tag);

        if (tag.tag_number == der_integer)
        {
            integers[i++] = DER_tag_integer_parsing(mem, &tag);
            mem += tag.total_length;
            printf("READ INTEGER / add %x\n", tag.total_length);
        }
        else if (tag.tag_number == der_OID)
        {
            mem += tag.total_length;
            printf("SKIP OID / add %x\n", tag.total_length);
        }
        else if (
            tag.tag_number == der_bitstring ||\
            tag.tag_number == der_null ||\
            tag.tag_number == der_sequence
        )
        {
            mem += tag.header_length;
            printf("READ %x / add %x\n", tag.tag_number, tag.header_length);
        }
        else
        {
            printf("Unknow type: %x\n", tag.tag_number);
            print_tag(&tag);
            freexit(0);
        }
    }
    if (i < n_int)
    {
        printf("ERROR DER READ: Catch %d integers, missing %d.\n", i, n_int - i);
        exit(0);
    }
}


void               DER_read_public_key(Mem_8bits *mem, int byteSz, t_rsa_public_key *pubkey)
{
    Long_64bits integers[RSA_PUBLIC_KEY_INTEGERS_COUNT];
    printf("RSA_PUBLIC_KEY_INTEGERS_COUNT: %lu\n", RSA_PUBLIC_KEY_INTEGERS_COUNT);

    DER_read_key(mem, byteSz, integers, RSA_PUBLIC_KEY_INTEGERS_COUNT);
    ft_memcpy(pubkey, integers, sizeof(t_rsa_public_key));
}

void               DER_read_private_key(Mem_8bits *mem, int byteSz, t_rsa_private_key *pubkey)
{
    Long_64bits integers[RSA_PRIVATE_KEY_INTEGERS_COUNT];
    printf("RSA_PRIVATE_KEY_INTEGERS_COUNT: %lu\n", RSA_PRIVATE_KEY_INTEGERS_COUNT);

    DER_read_key(mem, byteSz, &integers, RSA_PRIVATE_KEY_INTEGERS_COUNT);
    ft_memcpy(pubkey, integers, sizeof(t_rsa_private_key));
}

/*        
    RSA keys generation with DER format
*/

Mem_8bits          *DER_generate_public_key(t_rsa_public_key *pubkey, Long_64bits *hashByteSz)
{
    /*
        RSA public key in DER format is structured as follow (Random OID and integers):

        30 26                                  // Type: 30 (SEQUENCE)
        |  30 0D                               // Type: 30 (SEQUENCE)
        |  |  06 09                            // Type: 06 (OBJECT_IDENTIFIER)
        |  |  -  2A 86 48                      // 9 bytes OID value. HEX encoding of
        |  |  -  86 F7 0D                      //     1.2.840.113549.1.1.1
        |  |  -  01 01 01 
        |  |  05 00                            // Type: 05 (NULL)
        |  03 15                               // Type: 03 (BIT STRING)
        |  |  -  00                            // Number of unused bits in last content byte
        |  |  30 12                            // Type: 30 (SEQUENCE)
        |  |  |  02 09                         // Type: 02 (INTEGER)
        |  |  |  -  00                         // Leading ZERO of integer
        |  |  |  -  D1 14 D5 3E FB DD DA 12
        |  |  |  02 03                         // Type: 02 (INTEGER)
        |  |  |  -  01 00 01                   // Public Exponent
    */
    pubkey->enc_exp = RSA_ENC_EXP;
    int exp_length = bytes_counter(pubkey->enc_exp);
    int modulus_length = bytes_counter(pubkey->modulus) + 1;                    // +1 to add 00 byte
    int ints_sequence_length = exp_length + modulus_length + 4;                 // +4 to add their header length (2 and 2)
    int bit_string_length = ints_sequence_length + 3;                           // +3 to add its   header length and 00 byte
    int key_sequence_length = DER_OID_SEQUENCE_length + bit_string_length + 4;  // +4 to add their header length (2 and 2)
    *hashByteSz = key_sequence_length + 2;                                      // +2 to add first header length

    // printf("*hashByteSz: %d\n", *hashByteSz);
    // printf("key_sequence_length: %d\n", key_sequence_length);
    // printf("DER_OID_SEQUENCE_length: %ld\n", DER_OID_SEQUENCE_length);
    // printf("bit_string_length: %d\n", bit_string_length);
    // printf("ints_sequence_length: %d\n", ints_sequence_length);
    // printf("modulus_length: %d\n", modulus_length);
    // printf("exp_length: %d\n", exp_length);

    // Mem_8bits   *

    exit(0);
}

// Mem_8bits           DER_generate_public_key(t_rsa_public_key *pubkey)
// {
    
// }
