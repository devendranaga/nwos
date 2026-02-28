#include "mka.h"

using namespace netos::lib;

namespace netos {

netos_status ieee8021x_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_icv_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_icv_header::deserialize(packet_buf *pkt_buf)
{
    uint32_t len = 0;

    pkt_buf->offset_ ++;

    len = ((pkt_buf->buf_[pkt_buf->offset_] & 0x0F) >> 8) +
           (pkt_buf->buf_[pkt_buf->offset_ + 1]);
    pkt_buf->offset_ += 2;

    if (len > MKA_ICV_LEN) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    memcpy(this->icv,
           &pkt_buf->buf_[pkt_buf->offset_],
           len);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_basic_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_basic_header::deserialize(packet_buf *pkt_buf)
{
    uint16_t val;
    uint16_t remaining_len;

    // raise if mandatory elements are missing
    if (pkt_buf->get_remaining_len() < MKA_BASIC_PARAM_LEN_NO_CKN) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_SHORT_MKA_BASIC_PARAMS,
                                            event_protocol_level::EVENT_PROTOCOL_L2_MKA,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->version);
    if (this->version != IEEE8021X_VERSION_2010) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->key_server_priority);

    pkt_buf->deserialize_2_bytes(&val);
    memcpy(&this->opts, &val, sizeof(val));

    pkt_buf->deserialize_bytes(this->sci, MKA_SCI_LEN);
    pkt_buf->deserialize_bytes(this->mi, MKA_MI_LEN);
    pkt_buf->deserialize_4_bytes(&this->mn);
    pkt_buf->deserialize_4_bytes(&this->algorithm_agility);

    remaining_len = this->opts.paramset_body_len - MKA_BASIC_PARAM_LEN_NO_CKN;

    // validate CKN length
    if (remaining_len == 0) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_ZERO_MKA_CKN,
                                            event_protocol_level::EVENT_PROTOCOL_L2_MKA,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }
    if (remaining_len > MKA_CKN_LEN) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_LARGE_MKA_CKN,
                                            event_protocol_level::EVENT_PROTOCOL_L2_MKA,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    memcpy(this->ckn, &pkt_buf->buf_[pkt_buf->offset_], remaining_len);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_potential_peer_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_potential_peer_header::deserialize(packet_buf *pkt_buf)
{
    uint32_t i;
    uint16_t paramset_body_len = 0;

    pkt_buf->offset_ ++;
    pkt_buf->deserialize_2_bytes(&paramset_body_len);

    paramset_body_len &= 0x0FFF;

    this->n_peers = paramset_body_len / sizeof(mka_peer);

    for (i = 0; i < this->n_peers; i++) {
        pkt_buf->deserialize_bytes(this->peers[i].peer_mi, MKA_MI_LEN);
        pkt_buf->deserialize_4_bytes(&this->peers[i].peer_mn);
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_live_peer_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_live_peer_header::deserialize(packet_buf *pkt_buf)
{
    uint32_t i;
    uint16_t paramset_body_len = 0;

    pkt_buf->offset_ ++;
    pkt_buf->deserialize_2_bytes(&paramset_body_len);

    paramset_body_len &= 0x0FFF;

    this->n_peers = paramset_body_len / sizeof(mka_peer);

    for (i = 0; i < this->n_peers; i++) {
        pkt_buf->deserialize_bytes(this->peers[i].peer_mi, MKA_MI_LEN);
        pkt_buf->deserialize_4_bytes(&this->peers[i].peer_mn);
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_dist_sak_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_dist_sak_header::deserialize(packet_buf *pkt_buf)
{
    uint32_t remaining_len = 0;

    this->opt.dist_an = (pkt_buf->buf_[pkt_buf->offset_] & 0xC0) >> 6;
    this->opt.conf_off = (pkt_buf->buf_[pkt_buf->offset_] & 0x30) >> 4;
    pkt_buf->offset_ ++;

    this->opt.reserved = 0;
    this->opt.paramset_body_len =
                    ((pkt_buf->buf_[pkt_buf->offset_] & 0x0F) << 8) |
                     (pkt_buf->buf_[pkt_buf->offset_ + 1]);
    pkt_buf->offset_ += 2;

    pkt_buf->deserialize_4_bytes(&this->kn);

    remaining_len = pkt_buf->offset_ - this->opt.paramset_body_len;
    this->aes_keywrap_len = remaining_len;

    this->aes_wrap = &pkt_buf->buf_[pkt_buf->offset_];

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_macsec_sak_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_macsec_sak_header::deserialize(packet_buf *pkt_buf)
{
    this->opt.lan = (pkt_buf->buf_[pkt_buf->offset_] & 0xC0) >> 6;
    this->opt.ltx = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x20);
    this->opt.lrx = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x10);
    this->opt.oan = (pkt_buf->buf_[pkt_buf->offset_] & 0x0C) >> 2;
    this->opt.otx = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x02);
    this->opt.orx = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x01);
    pkt_buf->offset_ ++;

    this->opt.ptx = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x80);
    this->opt.prx = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x40);
    this->opt.dp = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x10);
    this->opt.paramset_body_len =
                    ((pkt_buf->buf_[pkt_buf->offset_] & 0x0F) << 8) |
                     (pkt_buf->buf_[pkt_buf->offset_ + 1]);
    pkt_buf->offset_ += 2;

    if (pkt_buf->get_remaining_len() < MKA_MACSEC_DIST_PARAM_LEN_DEFAULT) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_bytes(this->latest_mi, MKA_MI_LEN);
    pkt_buf->deserialize_4_bytes(&this->latest_kn);
    pkt_buf->deserialize_4_bytes(&this->latest_lowest_pn);
    pkt_buf->deserialize_bytes(this->oldest_mi, MKA_MI_LEN);
    pkt_buf->deserialize_4_bytes(&this->oldest_kn);
    pkt_buf->deserialize_4_bytes(&this->oldest_lowest_pn);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_header::serialize(packet_buf *pkt_buf)
{
    netos_status ret;

    ret = this->bh.serialize(pkt_buf);
    return ret;
}

netos_status mka_header::deserialize(packet_buf *pkt_buf)
{
    netos_status ret;

    ret = this->bh.deserialize(pkt_buf);
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    this->available_headers = 0;

    while ((pkt_buf->get_remaining_len() > 0) &&
           (pkt_buf->get_remaining_len() < NETOS_PACKET_BUF_SIZE)) {
        uint32_t param_type = pkt_buf->buf_[pkt_buf->offset_];
        pkt_buf->offset_ ++;

        switch (param_type) {
            case MKA_POTENTIAL_PEER_PARAM_TYPE:
                ret = this->ph.deserialize(pkt_buf);
                if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                    return ret;
                }

                this->available_headers |= MKA_POTENTIAL_HDR;
            break;
            case MKA_LIVE_PEER_PARAM_TYPE:
                ret = this->lh.deserialize(pkt_buf);
                if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                    return ret;
                }

                this->available_headers |= MKA_LIVE_PEER_HDR;
            break;
            case MKA_DIST_SAK_PARAM_TYPE:
                ret = this->dh.deserialize(pkt_buf);
                if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                    return ret;
                }

                this->available_headers |= MKA_DIST_SAK_HDR;
            break;
            case MKA_MACSEC_SAK_USE_PARAM_TYPE:
                ret = this->mh.deserialize(pkt_buf);
                if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                    return ret;
                }

                this->available_headers |= MKA_MACSEC_SAK_HDR;
            break;
            case MKA_ICV_PARAM_TYPE:
                ret = this->ih.deserialize(pkt_buf);
                if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                    return ret;
                }

                this->available_headers |= MKA_ICV_HDR;
            break;
            default:
            break;
        }
    }

    return ret;
}

netos_status ieee8021x_header::deserialize(packet_buf *pkt_buf)
{
    netos_status ret = NETOS_STATUS_UNSUPPORTED_IEEE8021X_TYPE;

    pkt_buf->deserialize_byte(&this->version);
    pkt_buf->deserialize_byte(&this->type);
    pkt_buf->deserialize_2_bytes(&this->len);

    if (this->type == IEEE8021X_TYPE_MKA) {
        ret = this->mh.deserialize(pkt_buf);
    }

    return ret;
}

}


