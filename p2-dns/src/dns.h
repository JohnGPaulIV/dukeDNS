#ifndef __cs361_dns_h__
#define __cs361_dns_h__

#include "utils.h"
#include <stdint.h>

#define NUM_REC_TYPES 7

// Supported record types
#define A 1
#define NS 2
#define CNAME 5
#define SOA 6
#define PTR 12
#define MX 15
#define AAAA 28

// Supported class types
#define IN 1

void print_dns_header (dns_message_t *msg);
void print_question_section (dns_message_t *msg);
void print_answer_section (dns_message_t *msg);
void print_authority_section (dns_message_t *msg);
void print_additional_section (dns_message_t *msg);

size_t build_dns_request (uint8_t *buf, int xid, char *domain, char *type);

dns_message_t *destructure (uint8_t *packet);

uint8_t *construct_messages (dns_message_t *msg, size_t *msg_size,
                             bool use_compressed);

/* Create header/flags/questions/records in host/network order. */
dns_header_t build_header_from (uint16_t xid, dns_flags_t *flags,
                                uint16_t qdcount, uint16_t ancount,
                                uint16_t nscount, uint16_t arcount);
dns_flags_t build_flags_from (uint16_t flags);
dns_question_t build_question_from (uint8_t *qname, uint16_t type,
                                    uint16_t class);
dns_record_t build_record_from (uint8_t *rname, uint16_t type, uint16_t class,
                                uint32_t ttl, uint16_t rd_length,
                                uint8_t *rdata);

/* Host-order getters for DNS message fields. */
dns_header_t get_header_host (dns_message_t *msg);
size_t get_record_count (dns_message_t *msg);
uint16_t get_qdcount_host (dns_message_t *msg);
uint16_t get_ancount_host (dns_message_t *msg);
uint16_t get_nscount_host (dns_message_t *msg);
uint16_t get_arcount_host (dns_message_t *msg);
uint16_t get_qtype_host (dns_message_t *msg, uint16_t qdnum);
uint16_t get_qclass_host (dns_message_t *msg, uint16_t qdnum);
uint16_t get_record_type_host (dns_message_t *msg, size_t ridx);
uint16_t get_record_class_host (dns_message_t *msg, size_t ridx);
uint32_t get_record_ttl_host (dns_message_t *msg, size_t ridx);
uint16_t get_record_rd_length_host (dns_message_t *msg, size_t ridx);

/* Retrieve DNS names and string representations. The returned
 * strings are dynamically allocated and must be freed by the calling function.
 */
char *get_name (uint8_t *msg_start, uint8_t *name_data, size_t start_offset);
char *get_question_name (dns_message_t *msg, uint16_t qdidx);
char *get_record_name (dns_message_t *msg, uint16_t ridx);
char *get_qclass_str (dns_message_t *msg, uint16_t qdnum);
char *get_qtype_str (dns_message_t *msg, uint16_t qdnum);
char *get_record_class_str (dns_message_t *msg, size_t ridx);
char *get_record_type_str (dns_message_t *msg, size_t ridx);
char *get_record_ttl_str (dns_message_t *msg, size_t ridx, bool trailing_dot);
char *get_record_rdata (dns_message_t *msg, size_t ridx);
char *get_dns_record_printable (dns_message_t *msg, size_t ridx);
char *get_header_str (dns_message_t *msg);
char *get_flags_str (dns_message_t *msg);

void print_server_response (dns_message_t *msg);

/* DNS message construction helpers for request names, data, records, etc. */
void build_name_data (uint8_t *buffer, char *name, size_t *curr_byte);
void build_data (uint8_t *buffer, dns_header_t *hdr, dns_question_t *questions,
                 dns_record_t *answers, size_t *curr_byte,
                 bool used_compressed);
void write_question (uint8_t *buffer, size_t *off, dns_question_t *q);
void write_record (uint8_t *buffer, size_t *off, dns_record_t *r,
                   bool used_compressed);

/* Helper for skipping over a name in a DNS packet. */
void consume_name (uint8_t **p);

/* Set record type from string for build_dns_request. Returns non-zero on
 * success, 0 on failure.
 */
int set_record_type (int *record_type, char *type);

#endif
