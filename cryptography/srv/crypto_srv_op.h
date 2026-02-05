#ifndef CRYPTO_SRV_OP_H
#define CRYPTO_SRV_OP_H

#include <stdint.h>

namespace netos {

class crypto_srv_op {
    public:
        explicit crypto_srv_op() = default;
        ~crypto_srv_op() = default;

        void handle_op(uint8_t *rx_buffer, uint32_t rx_buf_len);
    private:
};

}

#endif
