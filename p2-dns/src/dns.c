#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "utils.h"

// Most of the DNS parsing, construction and display helpers/logic are in this
// file

/* DNS name helpers */

// Check whether the given byte is the start of a compressed name
// pointer (ie. byte && c0 == c0).
static bool
is_name_ptr (uint8_t b)
{
  return (b & 0xc0) == 0xc0;
}

// Extract the 14-bit offset from a compression pointer.
static uint16_t
name_ptr_offset (const uint8_t *name)
{
  uint16_t raw;
  memcpy (&raw, name, sizeof (raw));
  raw = ntohs (raw);
  return raw & 0x3fff;
}

// Compute the length of a DNS name in byte format, including the
// zero byte.  Compression pointers count as 2 bytes.
static size_t
dns_name_len (const uint8_t *name)
{
  if (name == NULL)
    return 0;
  const uint8_t *p = name;
  while (*p != 0)
    {
      if (is_name_ptr (*p))
        return (size_t)(p - name) + 2;
      p += 1 + *p;
    }
  return (size_t)(p - name) + 1;
}

// Copy a byte-format name from `name` into `out` at the provided
// offset.  Advances off by the number of bytes copied.
static void
copy_dns_name (uint8_t *out, size_t *off, const uint8_t *name)
{
  size_t nlen = dns_name_len (name);
  memcpy (out + *off, name, nlen);
  *off += nlen;
}

// Compare two DNS names in dotted notation by parsing their byte-format
// data.  Returns true if the names are equal.
static bool
dns_name_suffix_equal (uint8_t *a, uint8_t *b)
{
  char *a_name = get_name (NULL, a, 0);
  char *b_name = get_name (NULL, b, 0);
  bool same = a_name && b_name && strcmp (a_name, b_name) == 0;
  free (a_name);
  free (b_name);
  return same;
}

// Search the buffer for an occurrence of the given name suffix and
// return its offset.  Only exact suffix matches are considered.  If no
// match is found, returns 0xffff (because it is supposed to return
// a pointer to the buffer).Used when writing compressed names.
static uint16_t
find_name_suffix_offset (uint8_t *buffer, size_t off, uint8_t *name)
{
  for (size_t i = 0; i < off; i++)
    {
      if ((buffer[i] & 0xc0) == 0xc0)
        continue;
      if (buffer[i] == 0)
        continue;
      if (dns_name_suffix_equal (buffer + i, name))
        return (uint16_t)i;
    }
  return 0xffff;
}

// Write a byte-format name, applying compression if a matching suffix
// has already been written to the buffer.  Advances the off by
// the number of bytes written.
static void
write_compressed_name (uint8_t *buffer, size_t *off, uint8_t *name)
{
  uint8_t *p = name;
  while (*p != 0)
    {
      uint16_t match = find_name_suffix_offset (buffer, *off, p);
      if (match != 0xffff)
        {
          uint16_t ptr = htons ((uint16_t)(0xc000 | match));
          memcpy (buffer + *off, &ptr, 2);
          *off += 2;
          return;
        }
      uint8_t len = *p;
      memcpy (buffer + *off, p, (size_t)len + 1);
      *off += (size_t)len + 1;
      p += (size_t)len + 1;
    }
  buffer[(*off)++] = 0;
}

// Advance a pointer through a byte-format DNS name.  If the name
// contains compression pointers, the pointer is advanced by two bytes
// and the function returns immediately.  Otherwise it consumes each
// part until the terminating zero byte.
void
consume_name (uint8_t **p)
{
  while (**p != 0)
    {
      if (is_name_ptr (**p))
        {
          *p += 2;
          return;
        }
      *p += 1 + **p;
    }
  *p += 1;
}

/* message construction helpers */

// Build a byte-format name into the buffer from a dotted-domain string.
// The string is split on '.' and each part is prefixed with its
// length.  An empty or root name is encoded as a single zero byte.
void
build_name_data (uint8_t *buffer, char *name, size_t *curr_byte)
{
  if (name == NULL || strcmp (name, ".") == 0 || strcmp (name, "") == 0)
    {
      buffer[(*curr_byte)++] = 0;
      return;
    }
  char *copy = strdup (name);
  char *token = strtok (copy, ".");
  while (token != NULL)
    {
      uint8_t len = (uint8_t)strlen (token);
      buffer[(*curr_byte)++] = len;
      memcpy (buffer + *curr_byte, token, len);
      *curr_byte += len;
      token = strtok (NULL, ".");
    }
  buffer[(*curr_byte)++] = 0;
  free (copy);
}

// Write a question into the buffer at the given offset (off).  The
// qname pointer must already point into the packet being in question.
void
write_question (uint8_t *buffer, size_t *off, dns_question_t *q)
{
  copy_dns_name (buffer, off, q->qname);
  memcpy (buffer + *off, &q->type, sizeof (q->type));
  *off += sizeof (q->type);
  memcpy (buffer + *off, &q->class, sizeof (q->class));
  *off += sizeof (q->class);
}

// Write a resource record into the buffer at the given offset.
// If compression is enabled, record names and (for certain types)
// rdata are compressed when possible.  The rd_length field is
// set after the rdata has been appended (compression).
void
write_record (uint8_t *buffer, size_t *off, dns_record_t *r,
              bool used_compressed)
{
  if (used_compressed)
    write_compressed_name (buffer, off, r->rname);
  else
    copy_dns_name (buffer, off, r->rname);
  memcpy (buffer + *off, &r->type, sizeof (r->type));
  *off += sizeof (r->type);
  memcpy (buffer + *off, &r->class, sizeof (r->class));
  *off += sizeof (r->class);
  memcpy (buffer + *off, &r->ttl, sizeof (r->ttl));
  *off += sizeof (r->ttl);
  size_t rdlength_pos = *off;
  *off += sizeof (r->rd_length);
  size_t rdata_start = *off;
  uint16_t type = ntohs (r->type);
  if (type == NS || type == CNAME || type == PTR)
    {
      if (used_compressed)
        write_compressed_name (buffer, off, r->rdata);
      else
        copy_dns_name (buffer, off, r->rdata);
    }
  else if (type == MX)
    {
      memcpy (buffer + *off, r->rdata, 2);
      *off += 2;
      uint8_t *mx_name = r->rdata + 2;
      if (used_compressed)
        write_compressed_name (buffer, off, mx_name);
      else
        copy_dns_name (buffer, off, mx_name);
    }
  else if (type == SOA)
    {
      uint8_t *p = r->rdata;
      if (used_compressed)
        write_compressed_name (buffer, off, p);
      else
        copy_dns_name (buffer, off, p);
      consume_name (&p);
      if (used_compressed)
        write_compressed_name (buffer, off, p);
      else
        copy_dns_name (buffer, off, p);
      consume_name (&p);
      size_t remaining = ntohs (r->rd_length) - (size_t)(p - r->rdata);
      memcpy (buffer + *off, p, remaining);
      *off += remaining;
    }
  else
    {
      memcpy (buffer + *off, r->rdata, ntohs (r->rd_length));
      *off += ntohs (r->rd_length);
    }
  uint16_t new_rdlength = htons ((uint16_t)(*off - rdata_start));
  memcpy (buffer + rdlength_pos, &new_rdlength, sizeof (new_rdlength));
}

// Build an entire DNS message into the buffer from the header,
// questions and records arrays.  Handles network-order counts and
// iterates over the questions and records.
void
build_data (uint8_t *buffer, dns_header_t *hdr, dns_question_t *questions,
            dns_record_t *answers, size_t *curr_byte, bool used_compressed)
{
  memcpy (buffer + *curr_byte, hdr, sizeof (*hdr));
  *curr_byte += sizeof (*hdr);
  for (uint16_t i = 0; i < ntohs (hdr->qdcount); i++)
    write_question (buffer, curr_byte, &questions[i]);
  uint16_t total
      = ntohs (hdr->ancount) + ntohs (hdr->nscount) + ntohs (hdr->arcount);
  for (uint16_t i = 0; i < total; i++)
    write_record (buffer, curr_byte, &answers[i], used_compressed);
}

// Construct a DNS response message from the provided message.  The
// calling function must free the returned buffer when done.  If allocation
// fails, NULL is returned and msg_size is set to zero.
uint8_t *
construct_messages (dns_message_t *msg, size_t *msg_size, bool use_compressed)
{
  uint8_t *out = calloc (BUFFER_LENGTH, sizeof (uint8_t));
  if (out == NULL)
    {
      *msg_size = 0;
      return NULL;
    }
  uint16_t response_flags = htons (DNS_RESPONSE_FLAGS);
  memcpy (&msg->header.flags, &response_flags, sizeof (response_flags));
  size_t off = 0;
  build_data (out, &msg->header, msg->questions, msg->records, &off,
              use_compressed);
  *msg_size = off;
  return out;
}

/* DNS message component constructors */

// Construct a header in host byte order, given host byte order inputs. The
// returned header contains network-order fields except for flags which
// must already be in host order.
dns_header_t
build_header_from (uint16_t xid, dns_flags_t *flags, uint16_t qdcount,
                   uint16_t ancount, uint16_t nscount, uint16_t arcount)
{
  dns_header_t hdr;
  memset (&hdr, 0, sizeof (hdr));
  hdr.xid = htons (xid);
  uint16_t raw_flags;
  memcpy (&raw_flags, flags, sizeof (raw_flags));
  hdr.flags = *flags;
  hdr.qdcount = htons (qdcount);
  hdr.ancount = htons (ancount);
  hdr.nscount = htons (nscount);
  hdr.arcount = htons (arcount);
  return hdr;
}

// Convert a 16-bit flag value into a dns_flags_t with host byte order
// fields.
dns_flags_t
build_flags_from (uint16_t flags)
{
  dns_flags_t f;
  uint16_t net = htons (flags);
  memcpy (&f, &net, sizeof (f));
  return f;
}

// Build a question structure given a byte-format qname pointer and
// host-order type/class values.
dns_question_t
build_question_from (uint8_t *qname, uint16_t type, uint16_t class)
{
  dns_question_t q;
  q.qname = qname;
  q.type = htons (type);
  q.class = htons (class);
  return q;
}

// Build a record structure given a byte-format name pointer, host-order
// type/class, ttl, length and a byte-format rdata pointer.
dns_record_t
build_record_from (uint8_t *rname, uint16_t type, uint16_t class, uint32_t ttl,
                   uint16_t rd_length, uint8_t *rdata)
{
  dns_record_t r;
  r.rname = rname;
  r.type = htons (type);
  r.class = htons (class);
  r.ttl = htonl (ttl);
  r.rd_length = htons (rd_length);
  r.rdata = rdata;
  return r;
}

/* parsing helpers */

// Parse a raw DNS packet into a dns_message_t structure.  The qname and
// rname pointers in the result point into the provided response packet.  The
// calling function is responsible for destroying the returned structure with
// the destroy_msg() function.
dns_message_t *
destructure (uint8_t *packet)
{
  dns_message_t *msg = create_msg ();
  if (packet == NULL || msg == NULL)
    return msg;
  uint8_t *p = packet;
  memcpy (&msg->header, p, sizeof (dns_header_t));
  p += sizeof (dns_header_t);
  uint16_t qdcount = get_qdcount_host (msg);
  msg->questions = calloc (qdcount, sizeof (dns_question_t));
  for (uint16_t i = 0; i < qdcount; i++)
    {
      msg->questions[i].qname = p;
      consume_name (&p);
      memcpy (&msg->questions[i].type, p, sizeof (uint16_t));
      p += sizeof (uint16_t);
      memcpy (&msg->questions[i].class, p, sizeof (uint16_t));
      p += sizeof (uint16_t);
    }
  uint16_t record_count = get_ancount_host (msg) + get_nscount_host (msg)
                          + get_arcount_host (msg);
  msg->record_count = record_count;
  if (record_count > 0)
    msg->records = calloc (record_count, sizeof (dns_record_t));
  for (uint16_t i = 0; i < record_count; i++)
    {
      msg->records[i].rname = p;
      consume_name (&p);
      memcpy (&msg->records[i].type, p, sizeof (uint16_t));
      p += sizeof (uint16_t);
      memcpy (&msg->records[i].class, p, sizeof (uint16_t));
      p += sizeof (uint16_t);
      memcpy (&msg->records[i].ttl, p, sizeof (uint32_t));
      p += sizeof (uint32_t);
      memcpy (&msg->records[i].rd_length, p, sizeof (uint16_t));
      p += sizeof (uint16_t);
      msg->records[i].rdata = p;
      p += get_record_rd_length_host (msg, i);
    }
  return msg;
}

/* Host-order getters */

dns_header_t
get_header_host (dns_message_t *msg)
{
  dns_header_t hdr = msg->header;
  hdr.xid = ntohs (hdr.xid);
  hdr.qdcount = ntohs (hdr.qdcount);
  hdr.ancount = ntohs (hdr.ancount);
  hdr.nscount = ntohs (hdr.nscount);
  hdr.arcount = ntohs (hdr.arcount);
  return hdr;
}

size_t
get_record_count (dns_message_t *msg)
{
  return msg->record_count;
}

uint16_t
get_qdcount_host (dns_message_t *msg)
{
  return ntohs (msg->header.qdcount);
}

uint16_t
get_ancount_host (dns_message_t *msg)
{
  return ntohs (msg->header.ancount);
}

uint16_t
get_nscount_host (dns_message_t *msg)
{
  return ntohs (msg->header.nscount);
}

uint16_t
get_arcount_host (dns_message_t *msg)
{
  return ntohs (msg->header.arcount);
}

uint16_t
get_qtype_host (dns_message_t *msg, uint16_t qdnum)
{
  return ntohs (msg->questions[qdnum].type);
}

uint16_t
get_qclass_host (dns_message_t *msg, uint16_t qdnum)
{
  return ntohs (msg->questions[qdnum].class);
}

uint16_t
get_record_type_host (dns_message_t *msg, size_t ridx)
{
  return ntohs (msg->records[ridx].type);
}

uint16_t
get_record_class_host (dns_message_t *msg, size_t ridx)
{
  return ntohs (msg->records[ridx].class);
}

uint32_t
get_record_ttl_host (dns_message_t *msg, size_t ridx)
{
  return ntohl (msg->records[ridx].ttl);
}

uint16_t
get_record_rd_length_host (dns_message_t *msg, size_t ridx)
{
  return ntohs (msg->records[ridx].rd_length);
}

/* Name getters and string conversions */

// Convert a byte-format DNS name (name_data) into a dotted string.
// msg_start should point to the beginning of the original packet or
// message for resolving compression pointers. "Start" of DNS message is
// dns_message_struct.questions[0].qname which points to the beginning length
// byte of the first question after the header. In this case "start_offset"
// would be 12. start_offset gives the offset of msg_start from the true start
// of the packet.  When msg_start is NULL, compression pointers are resolved
// relative to name_data only (used for mapping-file names).
char *
get_name (uint8_t *msg_start, uint8_t *name_data, size_t start_offset)
{
  if (name_data == NULL)
    return NULL;
  char out[MAX_NAME_SIZE] = { 0 };
  size_t out_pos = 0;
  uint8_t *p = name_data;
  size_t jumps = 0;
  while (1)
    {
      if (is_name_ptr (*p))
        {
          if (msg_start == NULL || jumps++ > 16)
            return strdup ("");
          p = (msg_start - start_offset) + name_ptr_offset (p);
          continue;
        }
      if (*p == 0)
        break;
      uint8_t len = *p++;
      if (out_pos + len + 1 >= sizeof (out))
        break;
      memcpy (out + out_pos, p, len);
      out_pos += len;
      out[out_pos++] = '.';
      p += len;
    }
  if (out_pos == 0)
    return strdup (".");
  out[out_pos] = '\0';
  return strdup (out);
}

char *
get_question_name (dns_message_t *msg, uint16_t qdidx)
{
  if (qdidx >= get_qdcount_host (msg))
    return NULL;
  return get_name (msg->questions[0].qname, msg->questions[qdidx].qname,
                   HEADER_SIZE);
}

char *
get_record_name (dns_message_t *msg, uint16_t ridx)
{
  if (ridx >= msg->record_count)
    return NULL;
  return get_name (msg->questions[0].qname, msg->records[ridx].rname,
                   HEADER_SIZE);
}

// Convert numeric class/type codes to strings.  Unknown codes
// produce "UNKNOWN". Numeric values must be in host order.
static char *
class_str (uint16_t class)
{
  return class == IN ? "IN" : "UNKNOWN";
}

static char *
type_str (uint16_t type)
{
  switch (type)
    {
    case A:
      return "A";
    case NS:
      return "NS";
    case CNAME:
      return "CNAME";
    case SOA:
      return "SOA";
    case PTR:
      return "PTR";
    case MX:
      return "MX";
    case AAAA:
      return "AAAA";
    default:
      return "UNKNOWN";
    }
}

static char *
get_op_str (dns_flags_t *flags)
{
  int op = flags->op;
  if (op == OPCODE_QUERY)
    return "QUERY";
  else if (op == OPCODE_IQUERY)
    return "IQUERY";
  else if (op == OPCODE_SREQUEST)
    return "SREQUEST";
  else if (op == OPCODE_SRESERVED)
    return "SRESERVED";
  else
    return "";
}

static char *
get_rcode_str (dns_flags_t *flags)
{
  int rcode = flags->rcode;
  if (rcode == RCODE_NOERR)
    return "NOERROR";
  else if (rcode == RCODE_FORMATERR)
    return "FORMERR";
  else if (rcode == RCODE_SERVERR)
    return "SERVFAIL";
  else if (rcode == RCODE_DOMAINERR)
    return "NXDOMAIN";
  else if (rcode == RCODE_SUPPORTERR)
    return "NOTIMP";
  else if (rcode == RCODE_EXECERR)
    return "REFUSED";
  else
    return "";
}

char *
get_qclass_str (dns_message_t *msg, uint16_t qdnum)
{
  return class_str (get_qclass_host (msg, qdnum));
}

char *
get_qtype_str (dns_message_t *msg, uint16_t qdnum)
{
  return type_str (get_qtype_host (msg, qdnum));
}

char *
get_record_class_str (dns_message_t *msg, size_t ridx)
{
  return class_str (get_record_class_host (msg, ridx));
}

char *
get_record_type_str (dns_message_t *msg, size_t ridx)
{
  return type_str (get_record_type_host (msg, ridx));
}

char *
get_record_ttl_str (dns_message_t *msg, size_t ridx, bool trailing_dot)
{
  char *ttl = calloc (MAX_U32_CHARS + 2, 1);
  snprintf (ttl, MAX_U32_CHARS + 2, "%u%s", get_record_ttl_host (msg, ridx),
            trailing_dot ? "." : "");
  return ttl;
}

// Read raw address (A or AAAA) rdata into a dotted string.
static char *
read_addr (uint8_t *data, uint16_t type)
{
  char *addr = calloc (INET6_ADDRSTRLEN + 1, 1);
  inet_ntop (type == A ? AF_INET : AF_INET6, data, addr, INET6_ADDRSTRLEN);
  return addr;
}

// Read a name-based rdata (NS/CNAME/PTR) into a dotted string.
static char *
read_name_rdata (dns_message_t *msg, uint8_t *data)
{
  return get_name (msg->questions[0].qname, data, HEADER_SIZE);
}

// Read MX rdata: preference (16-bit) followed by a domain name.
static char *
read_mx_rdata (dns_message_t *msg, uint8_t *data)
{
  uint16_t pref;
  memcpy (&pref, data, sizeof (pref));
  pref = ntohs (pref);
  char *domain = read_name_rdata (msg, data + 2);
  size_t len = strlen (domain) + MAX_U16_CHARS + 2;
  char *out = calloc (len, 1);
  snprintf (out, len, "%u %s", pref, domain);
  free (domain);
  return out;
}

// Read SOA rdata: two domain names followed by five 32-bit integers.
static char *
read_SOA_rdata (dns_message_t *msg, uint8_t *data)
{
  uint8_t *msg_start = msg->questions[0].qname;
  char *m_name = get_name (msg_start, data, HEADER_SIZE);
  consume_name (&data);
  char *r_name = get_name (msg_start, data, HEADER_SIZE);
  consume_name (&data);
  uint32_t soa_info[5];
  memcpy (soa_info, data, sizeof (soa_info));
  for (int i = 0; i < 5; i++)
    soa_info[i] = ntohl (soa_info[i]);
  size_t m_len = strlen (m_name);
  size_t r_len = strlen (r_name);
  size_t size_alloc = m_len + r_len + (MAX_U32_CHARS * 5) + 7;
  char *SOA_str = calloc (size_alloc, sizeof (char));
  snprintf (SOA_str, size_alloc, "%s %s %u %u %u %u %u", m_name, r_name,
            soa_info[0], soa_info[1], soa_info[2], soa_info[3], soa_info[4]);
  free (m_name);
  free (r_name);
  return SOA_str;
}

char *
get_record_rdata (dns_message_t *msg, size_t ridx)
{
  uint16_t type = get_record_type_host (msg, ridx);
  uint8_t *data = msg->records[ridx].rdata;
  if (type == A || type == AAAA)
    return read_addr (data, type);
  if (type == NS || type == CNAME || type == PTR)
    return read_name_rdata (msg, data);
  if (type == MX)
    return read_mx_rdata (msg, data);
  if (type == SOA)
    return read_SOA_rdata (msg, data);
  return strdup ("");
}

char *
get_dns_record_printable (dns_message_t *msg, size_t ridx)
{
  char *name = get_record_name (msg, ridx);
  char *ttl = get_record_ttl_str (msg, ridx, true);
  char *rdata = get_record_rdata (msg, ridx);
  char middle[64];
  snprintf (middle, sizeof (middle), "%s %s %s",
            get_record_class_str (msg, ridx), get_record_type_str (msg, ridx),
            ttl);
  size_t out_len = FST_COL_CHRS + MID_COL_CHRS + strlen (rdata) + 16;
  char *out = calloc (out_len, 1);
  snprintf (out, out_len, "%-31s%-17s%s", name, middle, rdata);
  free (name);
  free (ttl);
  free (rdata);
  return out;
}

// Build a human-readable summary of the DNS header (opcode, status, id).
char *
get_header_str (dns_message_t *msg)
{
  dns_header_t hdr = get_header_host (msg);
  uint16_t f;
  memcpy (&f, &hdr.flags, sizeof (uint16_t));
  f = ntohs (f);
  memcpy (&hdr.flags, &f, sizeof (uint16_t));
  dns_flags_t flags = hdr.flags;
  char *out = calloc (80, 1);
  snprintf (out, 80, "opcode: %s, status: %s, id: %u", get_op_str (&flags),
            get_rcode_str (&flags), hdr.xid);
  return out;
}

// Builds a human-readable summary of the DNS flags (qdcount, ancount, nscount,
// adcount).
char *
get_flags_str (dns_message_t *msg)
{
  dns_header_t hdr = get_header_host (msg);
  uint16_t raw_flags;
  memcpy (&raw_flags, &msg->header.flags, sizeof (raw_flags));
  raw_flags = ntohs (raw_flags);
  char *out = calloc (120, 1);
  snprintf (
      out, 120,
      "flags:%s%s%s%s%s; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u",
      (raw_flags & 0x8000) ? " qr" : "", (raw_flags & 0x0400) ? " aa" : "",
      (raw_flags & 0x0200) ? " tc" : "", (raw_flags & 0x0100) ? " rd" : "",
      (raw_flags & 0x0080) ? " ra" : "", hdr.qdcount, hdr.ancount, hdr.nscount,
      hdr.arcount);
  return out;
}

// Prints the readable header to the client.
void
print_dns_header (dns_message_t *msg)
{
  char *header = get_header_str (msg);
  char *flags = get_flags_str (msg);
  printf (";; ->>HEADER<<- %s\n", header);
  printf (";; %s\n\n", flags);
  free (header);
  free (flags);
}

// Prints the readable question section to the client.
void
print_question_section (dns_message_t *msg)
{
  printf (";; QUESTION SECTION:\n");
  for (size_t i = 0; i < get_qdcount_host (msg); i++)
    {
      char *name = get_question_name (msg, i);
      char *class = get_qclass_str (msg, i);
      char *type = get_qtype_str (msg, i);
      printf (";%s %s %s\n", name, class, type);
      free (name);
    }
}

// Print a short response summary for the client.  Only the first
// answer (if type A) is printed as an IPv4 address.
void
print_server_response (dns_message_t *msg)
{
  if (get_ancount_host (msg) == 0)
    return;
  char *name = get_record_name (msg, 0);
  char *class = get_record_class_str (msg, 0);
  char *type = get_record_type_str (msg, 0);
  char *ttl = get_record_ttl_str (msg, 0, false);
  printf ("Domain name: %s\n", name);
  printf ("Record type: %s %s\n", class, type);
  printf ("TTL: %s\n", ttl);
  free (name);
  free (ttl);
  for (uint16_t i = 0; i < get_ancount_host (msg); i++)
    {
      if (get_record_type_host (msg, i) == A
          && get_record_rd_length_host (msg, i) == 4)
        {
          char *rdata = get_record_rdata (msg, i);
          printf ("IPv4 address: %s\n", rdata);
          free (rdata);
        }
    }
}

/* --- Misc --- */

// Convert a type string (e.g., "A", "NS") into its numeric value.
// Returns non-zero on success, 0 on failure.
int
set_record_type (int *record_type, char *type)
{
  if (strcmp (type, "A") == 0)
    *record_type = A;
  else if (strcmp (type, "NS") == 0)
    *record_type = NS;
  else if (strcmp (type, "CNAME") == 0)
    *record_type = CNAME;
  else if (strcmp (type, "SOA") == 0)
    *record_type = SOA;
  else if (strcmp (type, "PTR") == 0)
    *record_type = PTR;
  else if (strcmp (type, "MX") == 0)
    *record_type = MX;
  else if (strcmp (type, "AAAA") == 0)
    *record_type = AAAA;
  else
    return 0;
  return *record_type;
}

/**
 * Prints a range of records.
 * Params:
 * dns_message_t *msg: Pointer to the message struct holding the data to print.
 *
 * char *title: Title of the current section being printed (Answer, Authority,
 * Additional).
 *
 * size_t start: Starting index of the records in
 * msg->records[...].
 *
 * size_t count: Number of records to print.
 */
void
print_record_range (dns_message_t *msg, const char *title, size_t start,
                    size_t count)
{
  if (count == 0)
    return;
  printf ("\n;; %s SECTION:\n", title);
  for (size_t i = start; i < start + count; i++)
    {
      char *line = get_dns_record_printable (msg, i);
      printf ("%s\n", line);
      free (line);
    }
}

void
print_answer_section (dns_message_t *msg)
{
  print_record_range (msg, "ANSWER", 0, get_ancount_host (msg));
}

void
print_authority_section (dns_message_t *msg)
{
  print_record_range (msg, "AUTHORITY", get_ancount_host (msg),
                      get_nscount_host (msg));
}

void
print_additional_section (dns_message_t *msg)
{
  print_record_range (msg, "ADDITIONAL",
                      get_ancount_host (msg) + get_nscount_host (msg),
                      get_arcount_host (msg));
}

// If domain is a PTR record, append ".in-addr.arpa" to the requested IP.
static char *
build_ptr_name (char *domain)
{
  unsigned int ip0;
  unsigned int ip1;
  unsigned int ip2;
  unsigned int ip3;

  if (sscanf (domain, "%u.%u.%u.%u", &ip0, &ip1, &ip2, &ip3) != 4)
    return NULL;

  char *rtn = calloc (MAX_NAME_SIZE, sizeof (char));
  if (rtn == NULL)
    return NULL;

  snprintf (rtn, MAX_NAME_SIZE, "%u.%u.%u.%u.in-addr.arpa", ip3, ip2, ip1,
            ip0);
  return rtn;
}

/**
 * Builds a request in DNS byte format to send to the DNS server.
 * params:
 * uint8_t *buf: Buffer to store the request data in.
 *
 * int xid: XID for the request message header.
 *
 * char *domain: Domain name user is requesting.
 *
 * char *type: Type of record user is requesting.
 *
 * returns:
 * Lenght of the DNS request (buf).
 */
size_t
build_dns_request (uint8_t *buf, int xid, char *domain, char *type)
{
  int record_type = 0;
  if (set_record_type (&record_type, type) == 0)
    return 0;

  size_t off = 0;
  uint16_t xid_net = htons ((uint16_t)xid);
  uint16_t flags_net = htons (0x0100);
  uint16_t one_net = htons (1);
  uint16_t zero = 0;
  memcpy (buf + off, &xid_net, 2);
  off += 2;
  memcpy (buf + off, &flags_net, 2);
  off += 2;
  memcpy (buf + off, &one_net, 2); // Setting counts (qd = 1, rest = 0)
  off += 2;
  memcpy (buf + off, &zero, 2);
  off += 2;
  memcpy (buf + off, &zero, 2);
  off += 2;
  memcpy (buf + off, &zero, 2);
  off += 2;

  char *qname = domain;
  if (record_type == PTR)
    {
      qname = build_ptr_name (domain);
      if (qname == NULL)
        return 0;
    }
  build_name_data (buf, qname, &off); // building request name from domain
                                      // string ([len byte][char byte(s)]...)
  uint16_t qtype = htons ((uint16_t)record_type);
  uint16_t qclass = htons (IN);
  memcpy (buf + off, &qtype, 2);
  off += 2;
  memcpy (buf + off, &qclass, 2);
  off += 2;
  return off; // length of the request message
}
