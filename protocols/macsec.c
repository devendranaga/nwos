#include <string.h>
#include "netos_status.h"
#include "netos_config.h"
#include "gcd.h"
#include "macsec.h"

#define NETOS_MACSEC_SECY_MAX 128

static netos_macsec_protocol_t macsec_p;

static uint32_t netos_macsec_hash_fn(void *key)
{
    return 0;
}

static bool netos_macsec_cmp(void *key1, void *key2)
{
    return false;
}

netos_status_t netos_macsec_init(netos_config_t *config,
                                 netos_gcd_ctx_t *gcd_ctx)
{
    macsec_p.secy_table = netos_hash_table_init(NETOS_MACSEC_SECY_MAX,
                                                netos_macsec_hash_fn,
                                                netos_macsec_cmp);
    if (!macsec_p.secy_table) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    memset(&macsec_p.mib, 0, sizeof(netos_macsec_mib_t));

    return NETOS_STATUS_SUCCESS;
}
