#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#define BUFFER_LENGTH 512

#define HEADER_SIZE 12
#define ID_START 0
#define FLAGS_START 2
#define QDCOUNT_START 4
#define ANCOUNT_START 6
#define NSCOUNT_START 8
#define ARCOUNT_START 10

#define MAX_NAME_SIZE 512
#define NUM_Q_TWO_BYTE_FIELDS 2
#define NUM_A_TWO_BYTE_FIELDS 3
#define NUM_A_FOUR_BYTE_FIELDS 1

#define NUM_BYTES_IN_Q sizeof (uint16_t) * NUM_Q_TWO_BYTE_FIELDS
#define NUM_BYTES2_IN_A sizeof (uint16_t) * NUM_A_TWO_BYTE_FIELDS
#define NUM_BYTES4_IN_A sizeof (uint32_t) * NUM_A_FOUR_BYTE_FIELDS

#define MAX_U16_CHARS 6
#define MAX_U32_CHARS 13

#define A 1
#define NS 2
#define CNAME 5
#define SOA 6
#define PTR 12
#define MX 15
#define AAAA 28

typedef struct dns_question dns_question_t;
typedef struct dns_answer dns_answer_t;

typedef struct dns_flags dns_flags_t;
typedef struct dns_header dns_header_t;

typedef struct dns_message dns_message_t;

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
  uint8_t *qname;
  uint16_t type;
  uint16_t class;
};

struct dns_answer
{
  uint8_t *rname;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rd_length;
  uint8_t *rdata;
};

struct dns_message
{
  size_t msg_len;
  dns_header_t header;
  dns_question_t *questions;
  dns_answer_t *answers;
};

typedef struct __attribute__ ((packed)) dns_message_2
{
  dns_header_t header;
  size_t msg_len;
  dns_question_t *questions;
  dns_answer_t *answers;

} dns_message_2_t;

void
consume (uint8_t **resp, size_t byte_amt)
{
  *resp += byte_amt;
}

void
consume1 (uint8_t **resp)
{
  consume (resp, sizeof (uint8_t));
}

void
consume2 (uint8_t **resp)
{
  consume (resp, sizeof (uint16_t));
}
void
consume4 (uint8_t **resp)
{
  consume (resp, sizeof (uint32_t));
}

void
consume_header (uint8_t **resp)
{
  consume (resp, sizeof (dns_header_t));
}

// void
// consume_type_and_class (uint8_t **resp)
// {
//   consume2 (resp);
//   consume2 (resp);
// }

void
consume_into (uint8_t **resp, uint8_t **dest, size_t byte_amt)
{
  memcpy (*dest, *resp, byte_amt);
  consume (resp, byte_amt);
}

void
consume1_into (uint8_t **resp, uint8_t *dest)
{
  uint8_t tmp;
  memcpy (&tmp, *resp, sizeof (uint8_t));
  *dest = tmp;
  consume1 (resp);
}

void
consume2_into (uint8_t **resp, uint16_t *dest)
{
  uint16_t tmp;
  memcpy (&tmp, *resp, sizeof (uint16_t));
  *dest = tmp;
  consume2 (resp);
}

void
consume4_into (uint8_t **resp, uint32_t *dest)
{
  uint32_t tmp;
  memcpy (&tmp, *resp, sizeof (uint32_t));
  *dest = tmp;
  consume4 (resp);
}

void
consume_header_into (uint8_t **resp, dns_header_t *hdr)
{
  uint16_t flags;
  memcpy (hdr, *resp, sizeof (dns_header_t));
  memcpy (&flags, (*resp) + sizeof (uint16_t), sizeof (uint16_t));
  flags = ntohs (flags);
  memcpy (&hdr->flags, &flags, sizeof (uint16_t));
  consume_header (resp);
}

void
consume_type_and_class_into (uint8_t **resp, uint16_t *type, uint16_t *class)
{
  consume2_into (resp, type);
  consume2_into (resp, class);
}

bool
is_ptr_to_name (uint8_t check)
{
  return (check & 0xC0) == 0xC0;
}

bool
name_is_root (uint8_t check)
{
  return check == 0;
}

void
skip_name_bytes (uint8_t **resp, bool *is_unique_case)
{
  *is_unique_case = is_ptr_to_name (**resp);
  if (is_ptr_to_name (**resp))
    consume (resp, sizeof (uint16_t));
  else
    consume (resp, sizeof (uint8_t) + **resp);
}

void
consume_name (uint8_t **resp)
{
  bool has_unique_case = (**resp == 0) || is_ptr_to_name (**resp);
  if (**resp == 0)
    consume (resp, sizeof (uint8_t));
  else if (is_ptr_to_name (**resp))
    consume (resp, sizeof (uint16_t));

  while (**resp != 0 && !has_unique_case)
    skip_name_bytes (resp, &has_unique_case);

  if (!has_unique_case)
    consume (resp, sizeof (uint8_t));
}

char *
decode_partial (uint8_t **name_data)
{
  uint8_t len;
  consume1_into (name_data, &len);
  char *local_name = calloc (len + 1, sizeof (char));
  uint8_t *temp = (uint8_t *)local_name;
  consume_into (name_data, &temp, len);
  return local_name;
}

uint16_t
get_name_ptr_offset (uint8_t *msg_start, uint8_t **name_data)
{
  uint16_t compressed_pointer;
  memcpy (&compressed_pointer, *name_data, sizeof (uint16_t));
  compressed_pointer = ntohs (compressed_pointer);
  compressed_pointer = compressed_pointer & 0x3FFF;

  return compressed_pointer;
}

uint8_t
get_length (uint8_t **name_data)
{
  uint8_t len = **name_data;
  return len;
}

uint8_t
get_lenth_and_increment (uint8_t *msg_start, uint8_t **name_data)
{
  if (((**name_data) & 0xC0) != 0xC0)
    return get_length (name_data);
  uint16_t ptr_off = get_name_ptr_offset (msg_start, name_data);

  // offset is from start of entire message, msg_start is 12 bytes in
  *name_data = (msg_start - HEADER_SIZE) + ptr_off;
  uint8_t len = **name_data;
  return **name_data;
}

char *
decode (uint8_t *msg_start, uint8_t **name_data)
{
  uint8_t result[MAX_NAME_SIZE] = { 0 };
  uint8_t *local_ptr = result;

  while (1)
    {
      uint8_t len = get_lenth_and_increment (msg_start, name_data);

      if (len == 0)
        break;

      char *partial = decode_partial (name_data);
      memcpy (local_ptr, partial, len);
      local_ptr += len;
      *local_ptr = '.';
      local_ptr++;
      free (partial);
    }

  *local_ptr = '\0';
  char *return_name = malloc (local_ptr - result + 1);
  memcpy (return_name, result, local_ptr - result);
  return_name[local_ptr - result] = '\0';
  return return_name;
}

char *
get_name (uint8_t *msg_start, uint8_t *name_data)
{
  if (name_is_root (*name_data))
    return ".";
  return decode (msg_start, &name_data);
}

char *
get_question_name (dns_message_t *msg, uint16_t qdidx)
{
  if (qdidx >= msg->header.qdcount)
    return NULL;
  uint8_t *name_queried = msg->questions[qdidx].qname;
  return get_name (msg->questions[0].qname, name_queried);
}

char *
get_answer_name (dns_message_t *msg, uint16_t anidx)
{
  if (anidx >= msg->header.ancount)
    return NULL;
  uint8_t *name_queried = msg->answers[anidx].rname;
  return get_name (msg->questions[0].qname, name_queried);
}

char *
read_rdata_as_addr (dns_message_t *msg, uint8_t *data, uint16_t type)
{
  char *addr = calloc (INET6_ADDRSTRLEN + 1, sizeof (char));
  int AF_TYPE = type == A ? AF_INET : AF_INET6;
  inet_ntop (AF_TYPE, data, addr, INET6_ADDRSTRLEN);
  return addr;
}

char *
read_rdata_as_MX (dns_message_t *msg, uint8_t *data)
{
  uint16_t pref;
  memcpy (&pref, data, sizeof (uint16_t));

  pref = ntohs (pref);
  data += sizeof (uint16_t);

  uint8_t *msg_start = msg->questions[0].qname;
  char *domain = get_name (msg_start, data);

  size_t domain_len = strlen (domain);
  size_t size_alloc = domain_len + MAX_U16_CHARS + 1;
  char *mx_str = calloc (size_alloc, sizeof (char));

  snprintf (mx_str, size_alloc, "%u %s", pref, domain);

  return mx_str;
}

char *
read_rdata_as_SOA (dns_message_t *msg, uint8_t *data)
{
  uint8_t *msg_start = msg->questions[0].qname;
  char *m_name = get_name (msg_start, data);
  char *r_name = get_name (msg_start, data);

  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minimum;

  consume4_into (&data, &serial);
  consume4_into (&data, &refresh);
  consume4_into (&data, &retry);
  consume4_into (&data, &expire);
  consume4_into (&data, &minimum);

  serial = ntohl (serial);
  refresh = ntohl (refresh);
  retry = ntohl (retry);
  expire = ntohl (expire);
  minimum = ntohl (minimum);

  size_t m_len = strlen (m_name);
  size_t r_len = strlen (r_name);
  size_t size_alloc = m_len + r_len + MAX_U32_CHARS + 1;

  char *SOA_str = calloc (size_alloc, sizeof (char));
  snprintf (SOA_str, size_alloc, "%s %s %u %u %u %u %u", m_name, r_name,
            serial, refresh, retry, expire, minimum);

  return SOA_str;
}

char *
read_rdata_non_domain (dns_message_t *msg, uint8_t *data, uint16_t type)
{
  if (type == A || type == AAAA)
    return read_rdata_as_addr (msg, data, type);
  if (type == MX)
    return read_rdata_as_MX (msg, data);
  if (type == SOA)
    return read_rdata_as_SOA (msg, data);
  return NULL;
}

char *
read_rdata (dns_message_t *msg, uint16_t anidx)
{
  uint16_t type = ntohs (msg->answers[anidx].type);
  uint8_t *data = msg->answers[anidx].rdata;
  if (type != NS && type != CNAME && type != PTR)
    return read_rdata_non_domain (msg, data, type);

  uint8_t *msg_start = msg->questions[0].qname;
  return get_name (msg_start, data);
}

char *
get_answer_rdata (dns_message_t *msg, uint16_t anidx)
{
  if (anidx >= msg->header.ancount)
    return NULL;
  return read_rdata (msg, anidx);
}

void
build_header (uint8_t **resp, dns_message_t *msg)
{
  consume_header_into (resp, &msg->header);
}

dns_question_t
build_question (uint8_t **resp)
{
  dns_question_t q;
  q.qname = *resp;
  consume_name (resp);
  consume_type_and_class_into (resp, &q.type, &q.class);
  return q;
}

dns_answer_t
build_answer (uint8_t **resp)
{
  dns_answer_t ans;
  ans.rname = *resp;
  consume_name (resp);
  consume_type_and_class_into (resp, &ans.type, &ans.class);
  consume4_into (resp, &ans.ttl);
  consume2_into (resp, &ans.rd_length);
  ans.rdata = calloc (ntohs (ans.rd_length), sizeof (uint8_t));
  consume_into (resp, &ans.rdata, ntohs (ans.rd_length));
  return ans;
}

void
insert_question_into_questions (uint8_t **resp, dns_message_t *msg,
                                size_t qdnum)
{
  printf ("INSERTING QUESTION INDEX: %lu\n", qdnum);
  dns_question_t q = build_question (resp);
  printf ("BUILT QUESTION INDEX: %lu\n", qdnum);
  msg->questions[qdnum] = q;
  printf ("QUESTION INDEX %lu INSERTED\n\n", qdnum);
}

void
insert_answer_into_answers (uint8_t **resp, dns_message_t *msg, size_t annum)
{
  printf ("INSERTING ANSWER INDEX: %lu\n", annum);
  dns_answer_t ans = build_answer (resp);
  printf ("BUILT ANSWER INDEX: %lu\n", annum);
  msg->answers[annum] = ans;
  printf ("ANSWER INDEX %lu INSERTED\n\n", annum);
}

void
build_fields (uint8_t **resp, dns_message_t *msg, size_t field_count,
              void (*builder) (uint8_t **, dns_message_t *, size_t))
{
  printf ("ENTERED BUILD FIELDS.\n");
  for (size_t i = 0; i < field_count; i++)
    {
      builder (resp, msg, i);
    }
  printf ("EXIT BUILD FIELDS\n\n");
}

void
build_questions (uint8_t **resp, dns_message_t *msg, size_t qdcount)
{
  build_fields (resp, msg, qdcount, insert_question_into_questions);
}

void
build_answers (uint8_t **resp, dns_message_t *msg, size_t ancount)
{
  build_fields (resp, msg, ancount, insert_answer_into_answers);
}

void
init_questions (uint8_t **resp, dns_message_t *msg)
{
  uint16_t qdcount = ntohs (msg->header.qdcount);
  msg->questions = calloc (qdcount, sizeof (dns_question_t));
  build_questions (resp, msg, qdcount);
}

void
init_answers (uint8_t **resp, dns_message_t *msg)
{
  uint16_t ancount = ntohs (msg->header.ancount);
  msg->answers = calloc (ancount, sizeof (dns_answer_t));
  build_answers (resp, msg, ancount);
}

void
init_message (dns_message_t *msg)
{
  memset (msg, 0, sizeof (dns_message_t));
}

dns_message_t
destructure (uint8_t *resp)
{
  dns_message_t msg;
  init_message (&msg);
  if (!resp)
    return msg;

  build_header (&resp, &msg);
  if (ntohs (msg.header.qdcount) <= 0)
    return msg;

  init_questions (&resp, &msg);

  if (ntohs (msg.header.ancount) > 0)
    init_answers (&resp, &msg);
  return msg;
}

int
main (int argc, char *argv[])
{
  uint8_t resp[]
      = { 0xa7, 0xb9, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
          0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
          0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x02,
          0x00, 0x01, 0x00, 0x01, 0x4a, 0xca, 0x00, 0x14, 0x01, 0x62, 0x0c,
          0x69, 0x61, 0x6e, 0x61, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
          0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x0c, 0x00, 0x02, 0x00,
          0x01, 0x00, 0x01, 0x4a, 0xca, 0x00, 0x04, 0x01, 0x61, 0xc0, 0x2b };

  dns_message_t msg = destructure (resp);
  msg.msg_len = sizeof (resp);
  // header
  printf ("=== HEADER ===\n");
  printf ("XID (expected 0x1234): 0x%04X\n", ntohs (msg.header.xid));
  printf ("QR (expected 1): %u\n", msg.header.flags.qr);
  printf ("OPCODE (expected 0): %u\n", msg.header.flags.op);
  printf ("AA (expected 1): %u\n", msg.header.flags.aa);
  printf ("TC (expected 0): %u\n", msg.header.flags.tc);
  printf ("RD (expected 0): %u\n", msg.header.flags.rd);
  printf ("RA (expected 0): %u\n", msg.header.flags.ra);
  printf ("Z (expected 0): %u\n", msg.header.flags.z);
  printf ("RCODE (expected 0): %u\n", msg.header.flags.rcode);
  printf ("QDCOUNT (expected 1): %u\n", ntohs (msg.header.qdcount));
  printf ("ANCOUNT (expected 2): %u\n", ntohs (msg.header.ancount));
  printf ("NSCOUNT (expected 0): %u\n", ntohs (msg.header.nscount));
  printf ("ARCOUNT (expected 0): %u\n", ntohs (msg.header.arcount));

  printf ("=== Question 0 ===\n");
  printf ("NAME: %s\n", get_question_name (&msg, 0));
  printf ("TYPE: %u\n", ntohs (msg.questions[0].type));
  printf ("CLASS: %u\n", ntohs (msg.questions[0].class));

  printf ("=== Answer 0 ===\n");
  printf ("NAME: %s\n", get_answer_name (&msg, 0));
  // printf("TYPE RAW:  %0x %02x", msg.)
  printf ("TYPE: %u\n", ntohs (msg.answers[0].type));
  printf ("CLASS: %u\n", ntohs (msg.answers[0].class));
  printf ("TTL: %u\n", ntohl (msg.answers[0].ttl));
  printf ("RD_LENGTH: %u\n", ntohs (msg.answers[0].rd_length));
  printf ("ANSWER NAME: %s\n", get_answer_rdata (&msg, 0));

  printf ("=== Answer 1 ===\n");
  printf ("NAME: %s\n", get_answer_name (&msg, 1));
  printf ("TYPE: %u\n", ntohs (msg.answers[1].type));
  printf ("CLASS: %u\n", ntohs (msg.answers[1].class));
  printf ("TTL: %u\n", ntohl (msg.answers[1].ttl));
  printf ("RD_LENGTH: %u\n", ntohs (msg.answers[1].rd_length));
  printf ("ANSWER NAME: %s\n", get_answer_rdata (&msg, 1));
  return EXIT_SUCCESS;
}