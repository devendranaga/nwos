#ifndef CRYPTO_SRV_INTERFACE_H
#define CRYPTO_SRV_INTERFACE_H

#if defined(__cplusplus)
extern "C" {
#endif

#define CRYPTO_OP_INTF_VERSION 1

#define CRYPTO_OP_HASH 1

typedef struct __attribute__ ((__packed__)) {
    uint8_t hash_algorithm;
    uint16_t msg_len;
    uint8_t msg[0];
} crypto_op_hash_t;

typedef struct __attribute__ ((__packed__)) {
    uint8_t version;
    uint8_t op;
    uint16_t len;

    /**
     * if op is CRYPTO_OP_HASH: use crypto_op_hash_t.
     */
    uint8_t data[0];
} crypto_op_interface_t;

#define CRYPTO_OP_INTERFACE_INIT(__buf, __intf_ptr) {\
    __intf_ptr = (crypto_op_interface_t *)__buf;\
    __intf_ptr->version = CRYPTO_OP_INTF_VERSION;\
}

#define CRYPTO_OP_HASH_INIT(__buf, __intf_ptr, __alg, __len) {\
    CRYPTO_OP_INTERFACE_INIT(__buf, __intf_ptr);\
    __intf_ptr->op = CRYPTO_OP_HASH;\
    __intf_ptr->len = __len;\
    __intf_ptr->data = (uint8_t *)__buf +\
                        sizeof(crypto_op_interface_t) +\
                        sizeof(crypto_op_hash_t);\
}

#if defined(__cplusplus)
}
#endif

#endif
