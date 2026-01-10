#ifndef IDS_SRC_PKT_POOL_H
#define IDS_SRC_PKT_POOL_H

#include <stdint.h>
#include <memory>
#include <vector>

#include "packet_buf.h"
#include "parsed_pkt.h"
#include "error_codes.h"

namespace netos {

namespace ids {

struct pkt_pool {
    std::vector<std::shared_ptr<packet_buf>> used_pkt_buf;
    std::vector<std::shared_ptr<packet_buf>> free_pkt_buf;
    std::vector<std::shared_ptr<parsed_pkt>> used_parsed_pkt_buf;
    std::vector<std::shared_ptr<parsed_pkt>> free_parsed_pkt_buf;

    netos_status prepare(uint32_t n_buffers)
    {
        netos_status ret;
        uint32_t i;

        for (i = 0; i < n_buffers; i ++) {
            ret = this->prepare_pkt_buf();
            if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                return ret;
            }

            ret = this->prepare_parsed_pkt_buf();
            if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                return ret;
            }
        }

        return netos_status::NETOS_STATUS_SUCCESS;
    }

    std::shared_ptr<packet_buf> get_packet_buf()
    {
        std::shared_ptr<packet_buf> pkt_buf;
        std::vector<std::shared_ptr<packet_buf>>::iterator it;

        it = free_pkt_buf.begin();
        if (*it == nullptr) {
            return nullptr;
        }

        pkt_buf = *it;

        free_pkt_buf.erase(it);

        used_pkt_buf.push_back(pkt_buf);
        return pkt_buf;
    }

    std::shared_ptr<parsed_pkt> get_parsed_pkt_buf()
    {
        std::shared_ptr<parsed_pkt> pp;
        std::vector<std::shared_ptr<parsed_pkt>>::iterator it;

        it = free_parsed_pkt_buf.begin();
        if (*it == nullptr) {
            return nullptr;
        }

        pp = *it;

        free_parsed_pkt_buf.erase(it);

        used_parsed_pkt_buf.push_back(pp);
        return pp;
    }

    void put_packet_buf(std::shared_ptr<packet_buf> pkt_buf)
    {
        std::vector<std::shared_ptr<packet_buf>>::iterator it;

        for (it = used_pkt_buf.begin(); it != used_pkt_buf.end(); it ++) {
            if (*it == pkt_buf) {
                used_pkt_buf.erase(it);
                break;
            }
        }

        if (it != used_pkt_buf.end()) {
            free_pkt_buf.push_back(*it);
        }
    }

    void put_parsed_pkt_buf(std::shared_ptr<parsed_pkt> pp)
    {
        std::vector<std::shared_ptr<parsed_pkt>>::iterator it;

        for (it = used_parsed_pkt_buf.begin(); it != used_parsed_pkt_buf.end(); it ++) {
            if (*it == pp) {
                used_parsed_pkt_buf.erase(it);
                break;
            }
        }

        if (it != used_parsed_pkt_buf.end()) {
            free_parsed_pkt_buf.push_back(*it);
        }
    }

    static pkt_pool *instance()
    {
        static pkt_pool pool;
        return &pool;
    }

    ~pkt_pool() { }

    private:
        explicit pkt_pool() { }
        netos_status prepare_pkt_buf()
        {
            netos_status ret;
            std::shared_ptr<packet_buf> pkt_buf;

            pkt_buf = std::make_shared<packet_buf>();
            if (!pkt_buf) {
                return netos_status::NETOS_STATUS_ALLOC_FAILURE;
            }

            ret = pkt_buf->allocate();
            if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                return ret;
            }

            this->free_pkt_buf.push_back(pkt_buf);
            return ret;
        }

        netos_status prepare_parsed_pkt_buf()
        {
            std::shared_ptr<parsed_pkt> pp;

            pp = std::make_shared<parsed_pkt>();
            if (!pp) {
                return netos_status::NETOS_STATUS_ALLOC_FAILURE;
            }

            this->free_parsed_pkt_buf.push_back(pp);
            return netos_status::NETOS_STATUS_SUCCESS;
        }
};

}

}

#endif
