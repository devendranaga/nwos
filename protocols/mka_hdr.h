#ifndef NETOS_PROTOCOL_MKA_HDR_H
#define NETOS_PROTOCOL_MKA_HDR_H

typedef struct {

} netos_basic_hdr_t;

typedef struct {

} netos_pp_paramset_t;

typedef struct {

} netos_lp_paramset_t;

typedef struct {

} netos_dist_sak_paramset_t;

typedef struct {

} netos_macsec_sak_paramset_t;

typedef struct {
    netos_basic_hdr_t           bh;
    netos_pp_paramset_t         pp;
    netos_lp_paramset_t         lp;
    netos_dist_sak_paramset_t   dist_sak;
    netos_macsec_sak_paramset_t macsec_sak;
} netos_mka_hdr_t;

#endif

