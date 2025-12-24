#ifndef NETOS_PLATFORM_LIB_ERROR_CODES_H
#define NETOS_PLATFORM_LIB_ERROR_CODES_H

namespace netos {

namespace lib {

enum netos_status {
    NETOS_STATUS_SUCCESS                = 0x00000000,

    NETOS_STATUS_INVAL_INPUT            = 0x00000001,
    NETOS_STATUS_INVAL_MACADDR          = 0x00000002,
    NETOS_STATUS_ALLOC_FAILURE          = 0x00000003,

    NETOS_STATUS_GENERIC_ERROR          = 0xFEFEFEFE,
};

}

}

#endif
