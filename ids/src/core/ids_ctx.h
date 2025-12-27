#ifndef IDS_CTX_H
#define IDS_CTX_H

#include <vector>
#include "ids_intf.h"

namespace netos {

namespace ids {

struct ids_ctx {
    std::vector<ids_intf> intf_list_;
};

}

}

#endif

