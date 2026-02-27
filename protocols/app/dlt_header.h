#ifndef PROTOCOLS_APP_DLT_HEADER_H
#define PROTOCOLS_APP_DLT_HEADER_H

#include <stdint.h>

#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

struct dlt_base_header {

};

struct dlt_header {
    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

}

#endif

