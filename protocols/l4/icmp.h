#ifndef PROTOCOLS_L4_ICMP_H
#define PROTOCOLS_L4_ICMP_H

#include <stdint.h>
#include <memory>
#include <error_codes.h>
#include <packet_buf.h>
#include <ip_macros.h>

namespace netos {

/**
 * List of types for ICMP.
 */
enum class icmp_type : uint8_t {
    ECHO_REPLY = 0,
    DEST_UNREACHABLE = 3,
    SOURCE_QUENCH = 4,
    REDIRECT_MSG = 5,
    ECHO_REQUEST = 8,
    TIME_EXCEEDED = 11,
    PARAMETER_PROBLEM = 12,
    TIMESTAMP = 13,
    TIMESTAMP_REPLY = 14,
    IDENTIFICATION_REQ = 15,
    IDENTIFICATION_REPLY = 16,
};

/**
 * List of codes for ICMP.
 */
enum class icmp_code : uint8_t {
    /* List of codes for destination unreachable. */
    DEST_UNREACHABLE_NET_UNREACHABLE = 0,
    DEST_UNREACHABLE_HOST_UNREACHABLE = 1,
    DEST_UNREACHABLE_PROTOCOL_UNREACHABLE = 2,
    DEST_UNREACHABLE_PORT_UNREACHABLE = 3,
    DEST_UNREACHABLE_FRAGMENTATION_NEEDED_AND_DF_SET = 4,
    DEST_UNREACHABLE_SOURCE_ROUTE_FAILED = 5,

    /* List of codes for the time exceeded. */
    TTL_EXCEEDED_IN_TRANSIT = 0,
    FRAGMENTATION_REASSEMBLY_TIME_EXCEEDED = 1,

    /* List of codes for the parameter problem. */
    PARAMETER_POINTER = 0,

    /* List of codes for the source quench. */
    SOURCE_QUENCH = 0,

    /* List of codes for the redirect message. */
    REDIRECT_FOR_NETWORK = 0,
    REDIRECT_FOR_HOST = 1,
    REDIRECT_FOR_TOS_AND_NETWORK = 2,
    REDIRECT_FOR_TOS_AND_HOST = 3,

    /* List of codes for the echo request. */
    ECHO_REQUEST = 0,

    /* List of codes for the echo reply. */
    ECHO_REPLY = 0,

    /* List of codes for the timestamp. */
    TIMESTAMP = 0,

    /* List of codes for the timestamp reply. */
    TIMESTAMP_REPLY = 0,

    /* List of codes for the identification request. */
    IDENTIFICATION_REQ = 0,

    /* List of codes for the identification reply. */
    IDENTIFICATION_REPLY = 0,
};

struct icmp_dest_unreachable {
    uint32_t unused;
    uint8_t ip_hdr_data[NETOS_IP_HDR_MAX_LEN];
    uint8_t datagram_data[8];

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

struct icmp_time_exceeded {
    uint32_t unused;
    uint8_t ip_hdr_data[NETOS_IP_HDR_MAX_LEN];
    uint8_t datagram_data[8];

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

struct icmp_parameter_problem {
    uint8_t pointer;
    uint8_t unused[3];
    uint8_t ip_hdr_data[NETOS_IP_HDR_MAX_LEN];
    uint8_t datagram_data[8];

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

struct icmp_source_quench {
    uint32_t unused;
    uint8_t ip_hdr_data[NETOS_IP_HDR_MAX_LEN];
    uint8_t datagram_data[8];

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

struct icmp_redirect {
    uint32_t gateway_ip;
    uint8_t ip_hdr_data[NETOS_IP_HDR_MAX_LEN];
    uint8_t datagram_data[8];

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

struct icmp_echo {
    uint16_t identifier;
    uint16_t sequence_number;
    uint16_t icmp_data_len;
    uint8_t *icmp_data;

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

struct icmp_timestamp {
    uint16_t identifier;
    uint16_t sequence_number;
    uint32_t originate_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

struct icmp_identification {
    uint16_t identifier;
    uint16_t sequence_number;

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

/**
 * @brief - Defines ICMP header.
 */
struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t start_off;
    uint32_t end_off;
    uint32_t checksum_off;

    std::shared_ptr<icmp_dest_unreachable> dest_unreachable;
    std::shared_ptr<icmp_time_exceeded> time_exceeded;
    std::shared_ptr<icmp_parameter_problem> param_problem;
    std::shared_ptr<icmp_source_quench> source_quench;
    std::shared_ptr<icmp_redirect> redirect;
    std::shared_ptr<icmp_echo> echo_request;
    std::shared_ptr<icmp_echo> echo_reply;
    std::shared_ptr<icmp_timestamp> timestamp;
    std::shared_ptr<icmp_timestamp> timestamp_reply;
    std::shared_ptr<icmp_identification> identification_req;
    std::shared_ptr<icmp_identification> identification_reply;

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status calc_checksum(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

}

#endif
