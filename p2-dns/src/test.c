#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#define HEADER_SIZE 12
#define MAX_NAME_SIZE 512
#define NUM_Q_TWO_BYTE_FIELDS 2
#define NUM_A_TWO_BYTE_FIELDS 3
#define NUM_A_FOUR_BYTE_FIELDS 1

typedef struct __attribute__ ((packed)) dns_flags
{
  unsigned rcode : 4;
  unsigned z : 3;
  unsigned ra : 1;
  unsigned rd : 1;
  unsigned tc : 1;
  unsigned aa : 1;
  unsigned op : 4;
  unsigned qr : 1;
} dns_flags_t;
typedef struct __attribute__ ((packed)) dns_header
{
  uint16_t xid;
  dns_flags_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} dns_header_tt;
typedef struct __attribute__ ((packed)) dns_question_test
{
  char *qname;
  uint16_t type;
  uint16_t class;
} dns_question_test_t;

typedef struct __attribute__ ((packed)) dns_answer_test
{
  char *rname;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rd_length;
  uint8_t *rdata;
} dns_answer_test_t;

typedef struct __attribute__ ((packed)) dns_message_test
{
  dns_header_tt header;
  dns_question_test_t *questions;
  dns_answer_test_t *answers;
} dns_message_test_t;

dns_flags_t
ntoh_flags (dns_flags_t flags)
{
  uint16_t host;
  memcpy (&host, &flags, sizeof (uint16_t));
  host = ntohs (host);
  dns_flags_t fgs;
  memcpy (&fgs, &host, sizeof (uint16_t));
  return fgs;
}

dns_header_tt
ntoh_header (dns_header_tt header)
{
  dns_header_tt hdr;
  hdr.xid = ntohs (header.xid);
  hdr.flags = ntoh_flags (header.flags);
  hdr.qdcount = ntohs (header.qdcount);
  hdr.ancount = ntohs (header.ancount);
  hdr.nscount = ntohs (header.nscount);
  hdr.arcount = ntohs (header.arcount);
  return hdr;
}

dns_question_test_t
ntoh_question (dns_question_test_t question)
{
  dns_question_test_t q;
  q.qname = question.qname;
  q.type = ntohs (question.type);
  q.class = ntohs (question.class);
  return q;
}

dns_question_test_t *
ntoh_questions (dns_question_test_t *questions, uint16_t qdcount)
{
  if (!questions)
    return NULL;
  dns_question_test_t *qs = calloc (qdcount, sizeof (dns_question_test_t));
  for (size_t i = 0; i < qdcount; i++)
    {
      qs[i] = ntoh_question (questions[i]);
    }
  return qs;
}

dns_answer_test_t
ntoh_answer (dns_answer_test_t answer)
{
  dns_answer_test_t ans;
  ans.rname = answer.rname;
  ans.type = ntohs (answer.type);
  ans.class = ntohs (answer.class);
  ans.ttl = ntohl (answer.ttl);
  ans.rd_length = ntohs (answer.rd_length);

  ans.rdata = calloc (ans.rd_length, sizeof (uint8_t));
  memcpy (ans.rdata, answer.rdata, ans.rd_length);
  return ans;
}

dns_answer_test_t *
ntoh_answers (dns_answer_test_t *answers, uint16_t ancount)
{
  if (!answers)
    return NULL;
  dns_answer_test_t *anss = calloc (ancount, sizeof (dns_answer_test_t));
  for (size_t i = 0; i < ancount; i++)
    {
      anss[i] = ntoh_answer (answers[i]);
    }
  return anss;
}

dns_message_test_t
ntoh_message (dns_message_test_t message)
{
  dns_message_test_t msg;
  msg.header = ntoh_header (message.header);
  uint16_t qdcount = msg.header.qdcount;
  uint16_t ancount = msg.header.ancount;
  msg.questions = ntoh_questions (message.questions, qdcount);
  msg.answers = ntoh_answers (message.answers, ancount);
  return msg;
}

void
mvn_update (void *dest, void *src, size_t src_len, size_t off,
            size_t *start_at, size_t mv_len)
{
  if (!dest || !src || !start_at)
    {
      printf ("Stop #1");
      return;
    }
  if (src_len <= 0 || mv_len <= 0 || off < 0 || *start_at < 0
      || *start_at >= src_len)
    {
      printf ("Stop #2");
      return;
    }
  if (*start_at + mv_len > src_len)
    {
      printf ("Stop #3");
      return;
    }

  memcpy ((uint8_t *)(dest) + off, (uint8_t *)(src) + *start_at, mv_len);
  *start_at += mv_len;
}

void
mvn_update_decoder (void *dest, void *src, size_t src_len, size_t *off,
                    size_t *start_at, size_t mv_len)
{
  if (!dest || !src || !off || !start_at)
    return;
  if (src_len <= 0 || mv_len <= 0 || *off < 0 || *start_at < 0
      || *start_at >= src_len)
    return;

  char delim = '.';
  mvn_update (dest, src, src_len, *off, start_at, mv_len);
  *off += mv_len;
  memcpy ((uint8_t *)dest + (*off)++, &delim, 1);
  // (*off)++;
}

void
set_name (char **field, char *name)
{
  if (!field || !(*field) || !name)
    return;
  *field = name;
}

char *
build_name (char *local_name, size_t local_size)
{
  if (!local_name || local_size <= 0)
    return NULL;

  local_name[local_size++] = '\0';
  char *name = calloc (local_size, sizeof (char));
  if (!name)
    return NULL;

  memcpy (name, local_name, local_size);
  return name;
}

char *
get_name (uint8_t *resp, size_t resp_len, size_t *start_byte)
{
  if (!resp || !start_byte)
    return NULL;
  if (resp_len <= 0 || *start_byte < 0 || *start_byte >= resp_len)
    return NULL;

  char local_name[MAX_NAME_SIZE];
  size_t local_size = 0;
  while (*start_byte < resp_len)
    {
      uint8_t len = resp[(*start_byte)++];
      if (len == 0)
        return build_name (local_name, local_size);

      if (*start_byte + len >= resp_len
          || local_size + len > sizeof (local_name))
        return NULL;
      mvn_update_decoder (local_name, resp, resp_len, &local_size, start_byte,
                          len);
    }
  return NULL;
}

char *
decode_names (uint8_t *resp, size_t resp_len, size_t *curr_byte)
{
  if (!resp || !curr_byte)
    return NULL;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return NULL;

  if (resp[*curr_byte] == 0)
    {
      char *root = calloc (2, sizeof (char));
      root[0] = '.';
      root[1] = '\0';
      (*curr_byte)++;
      return root;
    }
  if ((resp[*curr_byte] & 0xC0) != 0xC0)
    return get_name (resp, resp_len, curr_byte);

  size_t fst_v = ntohs (*(uint16_t *)(resp + *curr_byte)) & 0x3FFF;
  printf ("DECODE NAME START BYTE: %04lX\n", *curr_byte);
  *curr_byte += 2;
  printf ("CURR_BYTE AFTER NAME DECODED: %04lX\n", *curr_byte);
  return get_name (resp, resp_len, &fst_v);
}

void
set_qname (uint8_t *resp, size_t resp_len, size_t *curr_byte,
           dns_question_test_t *question)
{
  if (!resp || !curr_byte || !question)
    return;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return;

  char *name = decode_names (resp, resp_len, curr_byte);
  // question->qname = name;
  set_name (&question->qname, name);
}

dns_question_test_t *
build_question (uint8_t *resp, size_t resp_len, size_t *curr_byte)
{
  if (!resp || !curr_byte)
    return NULL;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return NULL;

  dns_question_test_t *q = calloc (1, sizeof (dns_question_test_t));
  if (!q)
    return NULL;
  // Decode the qname of the question
  q->qname = decode_names (resp, resp_len, curr_byte);
  // set_qname (resp, resp_len, curr_byte, q);

  // Move the remaining bytes of the question into the struct and increment the
  // current byte
  size_t mv_len = sizeof (uint16_t) * NUM_Q_TWO_BYTE_FIELDS;
  size_t q_off = sizeof (char *);
  mvn_update (q, resp, resp_len, q_off, curr_byte, mv_len);

  return q;
}

void *
build_q_void (uint8_t *resp, size_t resp_len, size_t *curr_byte)
{
  if (!resp || !curr_byte)
    return NULL;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return NULL;

  return build_question (resp, resp_len, curr_byte);
}

uint8_t *
retrieve_rdata (uint8_t *resp, size_t resp_len, size_t *curr_byte,
                size_t rdata_len)
{
  if (!resp || !curr_byte)
    return NULL;
  if (resp_len <= 0 || rdata_len < 0 || *curr_byte < 0
      || *curr_byte >= resp_len)
    return NULL;

  uint8_t *rdata = calloc (rdata_len, sizeof (uint8_t));
  printf ("CURR_BYTE BEFORE RDATA RETRIEVAL: %04lX\n", *curr_byte);
  mvn_update (rdata, resp, resp_len, 0, curr_byte, rdata_len);
  printf ("CURR_BYTE AFTER RDATA RETRIEVAL: %04lX\n", *curr_byte);
  return rdata;
}

void
set_rname (uint8_t *resp, size_t resp_len, size_t *curr_byte,
           dns_answer_test_t *answer)
{
  if (!resp || !curr_byte || !answer)
    return;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return;
  char *name = decode_names (resp, resp_len, curr_byte);
  answer->rname = name;
  // set_name (&answer->rname, name);
}

void
set_rdata (uint8_t *resp, size_t resp_len, size_t *curr_byte,
           dns_answer_test_t *answer)
{
  if (!resp || !curr_byte || !answer)
    return;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return;

  size_t rdata_len = ntohs (answer->rd_length);
  answer->rdata = retrieve_rdata (resp, resp_len, curr_byte, rdata_len);
}

dns_answer_test_t *
build_answer (uint8_t *resp, size_t resp_len, size_t *curr_byte)
{
  if (!resp || !curr_byte)
    return NULL;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return NULL;

  dns_answer_test_t *a = calloc (1, sizeof (dns_answer_test_t));
  if (!a)
    return NULL;

  // set_rname (resp, resp_len, curr_byte, a);
  a->rname = decode_names (resp, resp_len, curr_byte);

  size_t mv_len = sizeof (uint16_t) * NUM_A_TWO_BYTE_FIELDS
                  + sizeof (uint32_t) * NUM_A_FOUR_BYTE_FIELDS;
  size_t a_off = sizeof (char *);
  mvn_update (a, resp, resp_len, a_off, curr_byte, mv_len);

  set_rdata (resp, resp_len, curr_byte, a);

  return a;
}

void *
build_a_void (uint8_t *resp, size_t resp_len, size_t *curr_byte)
{
  if (!resp || !curr_byte)
    return NULL;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return NULL;

  return build_answer (resp, resp_len, curr_byte);
}

void *
build (uint8_t *resp, size_t resp_len, size_t *curr_byte,
       size_t dest_item_size, size_t num_items,
       void *(*builder_function) (uint8_t *, size_t, size_t *))
{
  if (!resp || !curr_byte || !builder_function)
    return NULL;
  if (resp_len <= 0 || dest_item_size < 0 || num_items < 0 || *curr_byte < 0
      || *curr_byte >= resp_len)
    return NULL;

  uint8_t *elems = calloc (num_items, dest_item_size);
  for (size_t i = 0; i < num_items; i++)
    {
      uint8_t *bytes_to_move
          = (uint8_t *)builder_function (resp, resp_len, curr_byte);
      uint8_t *load_bytes_to = &elems[i * dest_item_size];
      memcpy (load_bytes_to, bytes_to_move, dest_item_size);
    }
  return (void *)elems;
}

void
build_questions (dns_message_test_t *msg, uint8_t *resp, size_t resp_len,
                 size_t *curr_byte)
{
  if (!msg || !resp || !curr_byte)
    return;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return;

  size_t qcount = ntohs (msg->header.qdcount);
  size_t qsize = sizeof (dns_question_test_t);
  msg->questions = (dns_question_test_t *)build (resp, resp_len, curr_byte,
                                                 qsize, qcount, build_q_void);
  printf ("CURR_BYTE AFTER PARSING QUESTIONS:  %04lX\n", *curr_byte);
}

void
build_answers (dns_message_test_t *msg, uint8_t *resp, size_t resp_len,
               size_t *curr_byte)
{
  if (!msg || !resp || !curr_byte)
    return;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return;

  size_t ancount = ntohs (msg->header.ancount);
  size_t asize = sizeof (dns_answer_test_t);
  msg->answers = (dns_answer_test_t *)build (resp, resp_len, curr_byte, asize,
                                             ancount, build_a_void);
}

void
construct_response (dns_message_test_t *msg, uint8_t *resp, size_t resp_len,
                    size_t *curr_byte)
{
  if (!msg || !resp || !curr_byte)
    return;
  if (resp_len <= 0 || *curr_byte < 0 || *curr_byte >= resp_len)
    return;

  build_questions (msg, resp, resp_len, curr_byte);
  build_answers (msg, resp, resp_len, curr_byte);
  // build_answers () return;
}

void
consume_and_construct (dns_message_test_t *msg, uint8_t *resp, size_t resp_len)
{
  if (!msg || !resp)
    return;
  // Only begin header construction if there are atleast HEADER_SIZE bytes in
  // the response.
  if (resp_len <= HEADER_SIZE)
    return;

  // construct DNS header into msg->header
  memcpy (&msg->header, resp, HEADER_SIZE);
  // msg->header = ntoh_header (msg->header);
  // msg->header.qdcount = ntohs (msg->header.qdcount);
  // msg->header.ancount = ntohs (msg->header.ancount);
  size_t curr_byte = HEADER_SIZE;

  // Only begin response construction if there are more than HEADER_SIZE bytes
  // in the response.
  if (resp_len <= curr_byte)
    return;

  // construct DNS response into msg->questions and msg->answers
  construct_response (msg, resp, resp_len, &curr_byte);
}

int
main (int argc, char *argv[])
{
  //   uint8_t dns_name[] = { 0x03, 'j',  'm', 'u', 0x03, 'e', 'd',
  //                          'u',  0x03, 'c', 'o', 'm',  0x00 };
  //   size_t curr_byte = 0;
  //   size_t resp_len = 1000;
  //   char *testStr = decode_names (dns_name, resp_len, &curr_byte);
  // uint8_t dns_question[]
  //     = { // QNAME (jmu.edu.com.)
  //         0x03, 'j', 'm', 'u', 0x03, 'e', 'd', 'u', 0x03, 'c', 'o', 'm',
  //         0x00,

  //         // QTYPE (A record = 1)
  //         0x00, 0x06,

  //         // QCLASS (IN = 1)
  //         0x00, 0x07
  //       };
  // size_t resp_len = 1000;
  // size_t curr_byte = 0;
  // dns_question_test_t q = build_question (dns_question, resp_len,
  // &curr_byte); printf ("Name = %s\nClass = %u\nType = %u\n", q.qname,
  // q.class, q.type); printf ("Name = %s\nClass = %u\nType = %u\n", q.qname,
  // ntohs (q.class),
  //         ntohs (q.type));

  uint8_t dns_response[] = {
    // ===== HEADER (12 bytes) =====
    /* 0x00 */ 0x12,
    /* 0x01 */ 0x34, // ID = 0x1234
    /* 0x02 */ 0x84,
    /* 0x03 */ 0x00, // Flags: response, standard query, no error
    /* 0x04 */ 0x00,
    /* 0x05 */ 0x01, // QDCOUNT = 1 question
    /* 0x06 */ 0x00,
    /* 0x07 */ 0x02, // ANCOUNT = 2 answers
    /* 0x08 */ 0x00,
    /* 0x09 */ 0x00, // NSCOUNT = 0
    /* 0x0A */ 0x00,
    /* 0x0B */ 0x00, // ARCOUNT = 0

    // ===== QUESTION SECTION =====
    // QNAME: example.com.
    /* 0x0C */ 0x07,
    /* 0x0D */ 'e',
    /* 0x0E */ 'x',
    /* 0x0F */ 'a',
    /* 0x10 */ 'm',
    /* 0x11 */ 'p',
    /* 0x12 */ 'l',
    /* 0x13 */ 'e',
    /* 0x14 */ 0x03,
    /* 0x15 */ 'c',
    /* 0x16 */ 'o',
    /* 0x17 */ 'm',
    /* 0x18 */ 0x00,
    // QTYPE = A (1)
    /* 0x19 */ 0x00,
    /* 0x1A */ 0x01,
    // QCLASS = IN (1)
    /* 0x1B */ 0x00,
    /* 0x1C */ 0x01,

    // ===== ANSWER 1 =====
    // NAME: example.com. (compression pointer to offset 12)
    /* 0x1D */ 0xC0,
    /* 0x1E */ 0x0C,
    // TYPE = A (1)
    /* 0x1F */ 0x00,
    /* 0x20 */ 0x01,
    // CLASS = IN (1)
    /* 0x21 */ 0x00,
    /* 0x22 */ 0x01,
    // TTL = 3600 seconds
    /* 0x23 */ 0x00,
    /* 0x24 */ 0x00,
    /* 0x25 */ 0x0E,
    /* 0x26 */ 0x10,
    // RDLENGTH = 4 bytes
    /* 0x27 */ 0x00,
    /* 0x28 */ 0x04,
    // RDATA = 93.184.216.34 (IPv4 address)
    /* 0x29 */ 0x5D,
    /* 0x2A */ 0xB8,
    /* 0x2B */ 0xD8,
    /* 0x2C */ 0x22,

    // ===== ANSWER 2 =====
    // NAME: example.com. (compression pointer to offset 12)
    /* 0x2D */ 0xC0,
    /* 0x2E */ 0x0C,
    // TYPE = A (1)
    /* 0x2F */ 0x00,
    /* 0x30 */ 0x01,
    // CLASS = IN (1)
    /* 0x31 */ 0x00,
    /* 0x32 */ 0x01,
    // TTL = 3600 seconds
    /* 0x33 */ 0x00,
    /* 0x34 */ 0x00,
    /* 0x35 */ 0x0E,
    /* 0x36 */ 0x10,
    // RDLENGTH = 4 bytes
    /* 0x37 */ 0x00,
    /* 0x38 */ 0x04,
    // RDATA = 93.184.216.35 (IPv4 address)
    /* 0x39 */ 0x5D,
    /* 0x3A */ 0xB8,
    /* 0x3B */ 0xD8,
    /* 0x3C */ 0x23,
  };
  /*
  uint16_t dns_response[] = {
    htons (0x0001), htons (0x8180),         htons (0x0001), htons (0x0001),
    htons (0x0000), htons (0x0000), htons (0x0001), htons (0x0001),
    htons (0x0562), htons (0x0c72),         htons (0x6f6f), htons (0x742d),
    htons (0x7365), htons (0x7276),         htons (0x6572), htons (0x7303),
    htons (0x6e65), htons (0x7400),         htons (0x0001), htons (0x0001),
    htons (0x0000), htons (0x8ca0),         htons (0x0004), htons (0xaaf7),
    htons (0xaa02)
  };
  */
  // uint8_t dns_response[] = {
  //   // ===== HEADER =====
  //   0x00, 0x01, // ID = 0x0001
  //   0x81, 0x80, // FLAGS
  //   0x00, 0x01, // QDCOUNT = 1
  //   0x00, 0x01, // ANCOUNT = 1
  //   0x00, 0x00, // NSCOUNT = 0
  //   0x00, 0x00, // ARCOUNT = 0

  //   // ===== QUESTION =====
  //   0x00,       // QNAME = root "."
  //   0x00, 0x01, // QTYPE = A
  //   0x00, 0x01, // QCLASS = IN

  //   // ===== ANSWER =====
  //   // NAME = b.root-servers.net.
  //   0x01, 0x62, // "b"
  //   0x0c,       // length = 12
  //   0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
  //   0x73,                   // "root-servers"
  //   0x03, 0x6e, 0x65, 0x74, // "net"
  //   0x00,                   // end of name

  //   0x00, 0x01,             // TYPE = A
  //   0x00, 0x01,             // CLASS = IN
  //   0x00, 0x00, 0x8c, 0xa0, // TTL = 36000
  //   0x00, 0x04,             // RDLENGTH = 4
  //   0xaa, 0xf7, 0xaa, 0x02  // RDATA = 170.247.170.2
  // };

  size_t dns_response_len = sizeof (dns_response);

  dns_message_test_t *msg = calloc (1, sizeof (dns_message_test_t));
  consume_and_construct (msg, dns_response, dns_response_len);
  // *msg = ntoh_message (*msg);
  // msg->header = ntoh_header (msg->header);
  // ===== HEADER =====
  printf ("=== HEADER ===\n");
  printf ("XID (expected 0x1234): 0x%04X\n", msg->header.xid);
  printf ("QR (expected 1): %u\n", msg->header.flags.qr);
  printf ("OPCODE (expected 0): %u\n", msg->header.flags.op);
  printf ("AA (expected 1): %u\n", msg->header.flags.aa);
  printf ("TC (expected 0): %u\n", msg->header.flags.tc);
  printf ("RD (expected 0): %u\n", msg->header.flags.rd);
  printf ("RA (expected 0): %u\n", msg->header.flags.ra);
  printf ("Z (expected 0): %u\n", msg->header.flags.z);
  printf ("RCODE (expected 0): %u\n", msg->header.flags.rcode);
  printf ("QDCOUNT (expected 1): %u\n", msg->header.qdcount);
  printf ("ANCOUNT (expected 2): %u\n", msg->header.ancount);
  printf ("NSCOUNT (expected 0): %u\n", msg->header.nscount);
  printf ("ARCOUNT (expected 0): %u\n", msg->header.arcount);

  // ===== QUESTION =====
  printf ("\n=== QUESTION 0 ===\n");
  printf ("QNAME (expected 'example.com.'): %s\n", msg->questions[0].qname);
  printf ("QTYPE (expected 1 for A): %u\n", msg->questions[0].type);
  printf ("QCLASS (expected 1 for IN): %u\n", msg->questions[0].class);

  // ===== ANSWER 1 =====
  printf ("\n=== ANSWER 0 ===\n");
  printf ("RNAME (expected 'example.com.'): %s\n", msg->answers[0].rname);
  printf ("TYPE (expected 1 for A): %u\n", msg->answers[0].type);
  printf ("CLASS (expected 1 for IN): %u\n", msg->answers[0].class);
  printf ("TTL (expected 3600): %u\n", msg->answers[0].ttl);
  printf ("RD_LENGTH (expected 4): %u\n", msg->answers[0].rd_length);
  printf ("RDATA (expected 93.184.216.34): %u.%u.%u.%u\n",
          msg->answers[0].rdata[0], msg->answers[0].rdata[1],
          msg->answers[0].rdata[2], msg->answers[0].rdata[3]);

  // // ===== ANSWER 2 =====
  // printf ("\n=== ANSWER 1 ===\n");
  // printf ("RNAME (expected 'example.com.'): %s\n", msg->answers[1].rname);
  // printf ("TYPE (expected 1 for A): %u\n", msg->answers[1].type);
  // printf ("CLASS (expected 1 for IN): %u\n", msg->answers[1].class);
  // printf ("TTL (expected 3600): %u\n", msg->answers[1].ttl);
  // printf ("RD_LENGTH (expected 4): %u\n", msg->answers[1].rd_length);
  // printf ("RDATA (expected 93.184.216.35): %u.%u.%u.%u\n",
  //         msg->answers[1].rdata[0], msg->answers[1].rdata[1],
  //         msg->answers[1].rdata[2], msg->answers[1].rdata[3]);
}