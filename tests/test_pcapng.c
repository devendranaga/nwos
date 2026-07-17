#include "pcapng_intf.h"

int main(int argc, char **argv)
{
    char *filename = argv[1];
    netos_pcapng_ctx_t *pcapng;

    pcapng = netos_pcapng_ctx_init(NETOS_PCAPNG_OP_READ, filename);
    if (!pcapng) {
        return -1;
    }

    return 0;
}
