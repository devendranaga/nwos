#include <stdint.h>
#include <string>

#include "cbor_encode.h"
#include "cbor_decode.h"

int main()
{
    netos::cbor_encode enc(1024);
    uint8_t *enc_buf;
    uint32_t enc_buf_len;
    uint32_t i;

    enc.encode_map(2);
    enc.encode_str("test");
    enc.encode_uint(2);
    enc.encode_str("data");
    enc.encode_array(2);
    enc.encode_uint(3);
    enc.encode_uint(5);

    enc_buf = enc.get_data();
    enc_buf_len = enc.get_len();

    printf("encoded data: ");
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
