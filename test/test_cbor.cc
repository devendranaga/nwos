#include <stdint.h>
#include <string>

#include "cbor_encode.h"
#include "cbor_decode.h"

int main()
{
    uint8_t buf[1024];
    uint8_t byte_string[] = {0x01, 0x02, 0x03, 0x05, 0x06};

    netos::cbor_encode enc(buf, sizeof(buf));
    uint8_t *enc_buf;
    uint32_t enc_buf_len;
    uint32_t i;

    // number of elements in the map
    enc.encode_map(3);

    // 1st type is test
    //enc.encode_str("test");

    // value
    //enc.encode_uint(200);

    // 2nd type is data
    enc.encode_str("data");

    // array of values
    enc.encode_array(5);
    enc.encode_uint(3);
    enc.encode_uint(24);
    enc.encode_uint(30);
    enc.encode_uint(300);
    enc.encode_uint(6553521);

    enc.encode_str("bytearray");
    enc.encode_byte_string(byte_string, sizeof(byte_string));

    enc.encode_str("123456789012345678901234567890");
    enc.encode_uint(1);

    enc_buf = enc.get_data();
    enc_buf_len = enc.get_len();

    printf("encoded data: len [%d] ", enc_buf_len);
    for (i = 0; i < enc_buf_len; i ++) {
        printf("%02x", enc_buf[i]);
    }
    printf("\n");

    netos::cbor_decode dec(enc_buf, enc_buf_len);

    do {
        uint32_t type, len;
        dec.decode_type_len(&type, &len);

        switch (type) {
            case CBOR_MAJOR_TYPE_MAP: {
                printf("is a map\n");
            } break;
            case CBOR_MAJOR_TYPE_ARRAY:
                printf("is an array\n");
            break;
            case CBOR_MAJOR_TYPE_UINT: {
                uint32_t val = dec.decode_uint(len);
                printf("is an uint <%u>\n", val);
            } break;
            case CBOR_MAJOR_TYPE_BSTR: {
                uint8_t *byte_string;
                uint32_t i;

                byte_string = (uint8_t *)calloc(1, len);
                if (!byte_string) {
                    return -1;
                }

                printf("bytestring: \n");
                dec.decode_byte_string(byte_string, len);
                for (i = 0; i < len; i ++) {
                    printf("%02x ", byte_string[i]);
                }
                printf("\n");
            } break;
            case CBOR_MAJOR_TYPE_TEXT: {
                std::string str = dec.decode_str(len);
                printf("is a text <%s>\n", str.c_str());
            } break;
            default:
                printf("unknown type\n");
            break;
        }
    } while (dec.remaining_len() > 0);

    return 0;
}
