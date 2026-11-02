#ifndef __cs361_utils_h__
#define __cs361_utils_h__

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BUFFER_LENGTH 512
#define HEADER_SIZE 12
#define MAX_NAME_SIZE 512
#define MAX_RECORDS 1024
#define FST_COL_CHRS 31
#define MID_COL_CHRS 17
#define MAX_U16_CHARS 6
#define MAX_U32_CHARS 13
#define MAX_FLAG_BYTES 32
#define DNS_RESPONSE_FLAGS 0x8180
#define QUESTION_NAME_OFFSET 12

/* Supported DNS record/class values are in dns.h. */

// dns question/respons/message set-up (info from project 2 page and
// https://www.geeksforgeeks.org/computer-networks/dns-message-format/)
typedef struct dns_question dns_question_t;
typedef struct dns_record dns_record_t;
typedef struct dns_message dns_message_t;
typedef struct dns_header dns_header_t;
typedef struct dns_flags dns_flags_t;
// typedef struct dns_hash_record dns_hash_record_t;
typedef struct dns_hash dns_hash_t;
typedef struct dns_type_record dns_type_record_t;
typedef struct dns_hash_lookup dns_hash_lookup_t;
// typedef struct dns_hash_test dns_hash_test_t;

typedef enum qr
{
  QR_QUERY,
  QR_RESPONSE
} qr_t;

typedef enum opcode
{
  OPCODE_QUERY,
  OPCODE_IQUERY,
  OPCODE_SREQUEST,
  OPCODE_SRESERVED
} opcode_t;

typedef enum rcode
{
  RCODE_NOERR,
  RCODE_FORMATERR,
  RCODE_SERVERR,
  RCODE_DOMAINERR,
  RCODE_SUPPORTERR,
  RCODE_EXECERR
} rcode_t;

struct __attribute__ ((packed)) dns_flags
{
  unsigned rcode : 4;
  unsigned z : 3;
  unsigned ra : 1;
  unsigned rd : 1;
  unsigned tc : 1;
  unsigned aa : 1;
  unsigned op : 4;
  unsigned qr : 1;
};

struct __attribute__ ((packed)) dns_header
{
  uint16_t xid;
  dns_flags_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct dns_question
{
  uint8_t *qname; /* points into packet bytes */
  uint16_t type;  /* network order */
  uint16_t class; /* network order */
};

struct dns_record
{
  uint8_t *rname;     /* points into packet/db bytes or compression ptr */
  uint16_t type;      /* network order */
  uint16_t class;     /* network order */
  uint32_t ttl;       /* network order */
  uint16_t rd_length; /* network order */
  uint8_t *rdata;     /* points into packet/db bytes */
};

struct dns_message
{
  dns_header_t header; /* network order fields */
  dns_question_t *questions;
  dns_record_t *records;
  size_t record_count;
};

// struct dns_hash_record
// {
//   uint8_t *rname;     /* wire-format name from mappings.bin */
//   uint16_t type;      /* host order: mappings.bin is little-endian */
//   uint32_t ttl;       /* host order */
//   uint16_t rd_length; /* host order */
//   uint8_t *rdata;
// };

// struct dns_hash
// {
//   uint8_t *file_data; /* keep mappings.bin bytes alive */
//   size_t file_len;
//   dns_hash_record_t *records;
//   size_t hash_len;
// };

struct dns_hash_lookup
{
  dns_record_t *self;
  size_t num_connections;
  dns_hash_lookup_t **connections;
};

struct dns_type_record
{
  size_t num_records;
  dns_hash_lookup_t **records;
};

struct dns_hash
{
  uint8_t *file_data; /* keep mappings.bin bytes alive */
  size_t file_len;
  dns_type_record_t *type_records;
};

/* Byte/packet utilities. */
void print_byte_block (uint8_t *bytes, size_t length);
/*
 * Reads the entire contents of the file named by `fname` into a newly
 * allocated buffer. The number of bytes read is stored in `fsize` on
 * success. Returns NULL on error. The caller is responsible for
 * freeing the returned buffer with `free(3)` when it is no longer needed.
 */
uint8_t *read_file (char *fname, size_t *fsize);

/* Socket setup. */
int create_socket (void);
int config_addr (struct sockaddr_in *addr, char *ip_str, socklen_t ip_str_len);
int set_up_server (int *sock_fd, struct timeval *timeout,
                   struct sockaddr_in *addr, char *ip_str);
size_t set_up_client (int *xid, bool has_query_args, char *domain, char *type,
                      int *sock_fd, struct sockaddr_in *addr, char *ip_str,
                      uint8_t *request);

/* Message object helpers. These functions allocate and free
 * `dns_message_t` objects but do not perform any DNS parsing or
 * destructuring.
 */
dns_message_t *create_msg (void);
void destroy_msg (dns_message_t *msg);

// Destorys the given hash by freeing any owned memory/objects in the hash.
void destroy_hash (dns_hash_t *hash);

#endif
