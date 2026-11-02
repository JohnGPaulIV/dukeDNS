#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "dns.h"
#include "port_utils.h"
#include "utils.h"

static bool get_args (int, char **, time_t *);
static void usage (void);
static void send_xid1_response (int sock_fd, char *client_addr_str,
                                struct sockaddr_in *client,
                                socklen_t client_len);
static void is_xid2 ();
static dns_hash_t create_hash ();
static void realloc_records (dns_hash_t *hash);
static void realloc_lookups (dns_type_record_t *t_rec, size_t num_recs);

static int get_record_index (uint16_t type);
static dns_hash_lookup_t *create_lookup_record (dns_record_t *record);
static void insert_into_hash (dns_hash_t *hash, dns_hash_lookup_t *l_rec);
static void hton_rec (dns_record_t *rec);
static dns_record_t *create_record (uint8_t **p);
static void add_connection (dns_hash_lookup_t *u, dns_hash_lookup_t *v);
static void connect_cname_targets (dns_hash_t *hash,
                                   dns_hash_lookup_t **lookups,
                                   size_t num_recs);
static void connect_regular_types (dns_hash_lookup_t **lookups,
                                   size_t num_recs, dns_hash_t *hash);
static void find_connections (dns_hash_t *hash, dns_hash_lookup_t **lookups,
                              size_t num_recs);
static dns_record_t *build_msg_response (dns_hash_lookup_t *answers,
                                         uint16_t qtype, size_t *num_ans);
static bool visited_contains (dns_hash_lookup_t **visited, size_t n,
                              dns_hash_lookup_t *node);
static void collect_cname_chain (dns_hash_lookup_t *node, uint16_t qtype,
                                 dns_record_t *out, size_t *out_idx,
                                 size_t *num_ans, dns_hash_lookup_t **visited,
                                 size_t *num_visited);
static dns_record_t *build_msg_response_cname (dns_hash_lookup_t *answers,
                                               uint16_t qtype, char *qname,
                                               size_t *num_ans,
                                               size_t *num_auth,
                                               dns_hash_t *hash);
static void lookup_from_type (dns_message_t *msg, char *q_name,
                              dns_type_record_t *type_hash, uint16_t qdidx,
                              bool use_compression);
static void lookup_from_cname (dns_message_t *msg, char *q_name,
                               dns_type_record_t *cname_hash, uint16_t qdidx,
                               bool use_compression, dns_hash_t *hash);
static dns_message_t lookup_question (dns_message_t *query,
                                      bool use_compression, dns_hash_t *hash);
static void hash_records (dns_hash_t *hash, char *filename, size_t max_hash);
static void print_as_MX (char *rdata);
static void print_as_SOA (char *rdata);
static void print_structured_rdata (char *rdata, char *type);
static void print_lookup_handle (dns_message_t *msg, size_t rnum);
static void print_lookup_output (dns_message_t *msg);

int
main (int argc, char **argv)
{
  time_t seconds = 2;
  if (!get_args (argc, argv, &seconds))
    {
      usage ();
      return EXIT_FAILURE;
    }
  dns_hash_t hash = create_hash ();
  hash_records (&hash, "mappings.bin", MAX_RECORDS);
  realloc_records (&hash);

  if (optind + 1 < argc)
    {
      char *domain = argv[optind++];
      char *type = argv[optind++];
      int xid = 0;

      uint8_t request[BUFFER_LENGTH];
      size_t req_len = build_dns_request (request, xid, domain, type);

      dns_message_t *query = destructure (request);
      dns_message_t msg = lookup_question (query, xid != 2, &hash);

      size_t bytes_recv = 0;
      uint8_t *response = construct_messages (&msg, &bytes_recv, xid != 2);
      printf ("Using fake packet:\n");
      print_byte_block (request, req_len);
      print_lookup_output (&msg);
      printf ("Response as byte block (%lu bytes):\n", bytes_recv);
      print_byte_block (response, bytes_recv);
      destroy_hash (&hash);
      destroy_msg (query);
      free (msg.records);
      free (response);
      return EXIT_SUCCESS;
    }

  struct timeval timeout = { .tv_sec = seconds, .tv_usec = 0 };
  int sock_fd = -1;
  struct sockaddr_in addr;
  char ip_str[INET6_ADDRSTRLEN];

  if (set_up_server (&sock_fd, &timeout, &addr, ip_str) != EXIT_SUCCESS)
    return EXIT_FAILURE;

  uint8_t packet[BUFFER_LENGTH];
  while (1)
    {
      struct sockaddr_in client_addr;
      socklen_t client_len = sizeof (client_addr);
      ssize_t n = recvfrom (sock_fd, packet, sizeof (packet), 0,
                            (struct sockaddr *)&client_addr, &client_len);
      char *client_addr_str = calloc (client_len, sizeof (char));
      inet_ntop (AF_INET, &client_addr.sin_addr, client_addr_str, client_len);

      if (n < 0)
        break;

      printf ("Received %ld bytes from %s:\n", n, client_addr_str);
      print_byte_block (packet, n);

      dns_message_t *query = destructure (packet);

      char *type = get_qtype_str (query, 0);
      char *class = get_qclass_str (query, 0);
      char *qname = get_question_name (query, 0);
      uint16_t xid = ntohs (query->header.xid);

      printf ("Question: %s %s %s\n", qname, type, class);
      if (xid == 1)
        {
          send_xid1_response (sock_fd, client_addr_str, &client_addr,
                              client_len);
          free (qname);
          destroy_msg (query);
          free (client_addr_str);
          continue;
        }

      dns_message_t resp = lookup_question (query, xid != 2, &hash);

      dns_message_t *msg = calloc (1, sizeof (*msg));
      *msg = resp;

      size_t response_len = 0;
      uint8_t *response = construct_messages (msg, &response_len, xid != 2);

      if (response != NULL)
        {
          if (xid == 2)
            is_xid2 ();

          printf ("Sending response to %s:\n", client_addr_str);
          print_byte_block (response, response_len);
          sendto (sock_fd, response, response_len, 0,
                  (struct sockaddr *)&client_addr, client_len);
          free (response);
        }
      free (qname);
      destroy_msg (query);
      msg->questions = NULL;
      destroy_msg (msg);

      free (client_addr_str);
    }

  destroy_hash (&hash);
  close (sock_fd);
  return EXIT_SUCCESS;
}

static bool
get_args (int argc, char **argv, time_t *seconds)
{
  int ch = 0;
  while ((ch = getopt (argc, argv, "s:h")) != -1)
    {
      switch (ch)
        {
        case 's':
          *seconds = (time_t)strtol (optarg, NULL, 10);
          if (errno == EINVAL)
            return false;
          break;
        case 'h':
          return false;
        default:
          return false;
        }
    }

  return true;
}

static void
usage (void)
{
  printf ("dukens, a reference DNS server simulator\n");
  printf ("Usage: dukens [FLAG] [DOMAIN TYPE]\n");
  printf ("FLAG can be any of the following:\n\n");
  printf ("  -s N       use a server timeout of N seconds (default 2)\n");
  printf ("  -d         display the full list of DNS records\n");
  printf ("  -x N       specify an XID for non-server functionality\n");
  printf ("\nIf a DOMAIN and TYPE are listed, -s flag cannot be passed.\n");
  printf ("TYPE must be a supported resource record type numeric value.\n");
  printf ("Supported types are A, AAAA, CNAME, MX, NS, PTR, SOA.\n");
}

void
send_xid1_response (int sock_fd, char *client_addr_str,
                    struct sockaddr_in *client, socklen_t client_len)
{

  printf ("NOTE: XID=1 is a special case for testing purposes\n\n");
  printf ("Sending response to %s:\n", client_addr_str);
  uint8_t response[]
      = { 0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x61, 0x0c, 0x72, 0x6f,
          0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03,
          0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
          0x0a, 0x00, 0x04, 0xc6, 0x29, 0x00, 0x04 };
  print_byte_block (response, sizeof (response));
  sendto (sock_fd, response, sizeof (response), 0, (struct sockaddr *)client,
          client_len);
}

void
is_xid2 ()
{
  printf ("NOTE: XID=2 is a special case for testing purposes\n");
  printf ("Names in resource records will not be compressed\n\n");
}

dns_hash_t
create_hash ()
{
  dns_hash_t hash = { 0 };

  hash.type_records = calloc (NUM_REC_TYPES, sizeof (dns_type_record_t));
  if (hash.type_records == NULL)
    return hash;

  for (int i = 0; i < NUM_REC_TYPES; i++)
    {
      hash.type_records[i].records
          = calloc (MAX_RECORDS, sizeof (dns_hash_lookup_t *));
    }

  return hash;
}

void
realloc_records (dns_hash_t *hash)
{
  if (!hash || !hash->type_records)
    return;

  for (int i = 0; i < NUM_REC_TYPES; i++)
    {
      dns_type_record_t *t_recs = &hash->type_records[i];
      size_t num_recs = t_recs->num_records;

      if (num_recs == 0)
        {
          free (t_recs->records);
          t_recs->records = NULL;
          continue;
        }

      realloc_lookups (t_recs, num_recs);

      dns_hash_lookup_t **tmp
          = realloc (t_recs->records, num_recs * sizeof (*t_recs->records));

      if (tmp)
        t_recs->records = tmp;
    }
}

void
realloc_lookups (dns_type_record_t *t_rec, size_t num_recs)
{
  if (!t_rec || !t_rec->records)
    return;

  for (size_t i = 0; i < num_recs; i++)
    {
      dns_hash_lookup_t *curr_lookup = t_rec->records[i];

      if (!curr_lookup)
        continue;

      size_t num_conns = curr_lookup->num_connections;

      if (num_conns == 0)
        {
          free (curr_lookup->connections);
          curr_lookup->connections = NULL;
          continue;
        }

      dns_hash_lookup_t **tmp
          = realloc (curr_lookup->connections,
                     num_conns * sizeof (*curr_lookup->connections));

      if (tmp)
        curr_lookup->connections = tmp;
    }
}

// Map a record type code to an index in the type_records array. A
// negative result indicates an unsupported type.
static int
get_record_index (uint16_t type)
{
  if (type == A)
    return 0;
  if (type == NS)
    return 1;
  if (type == CNAME)
    return 2;
  if (type == SOA)
    return 3;
  if (type == PTR)
    return 4;
  if (type == MX)
    return 5;
  if (type == AAAA)
    return 6;
  return -1;
}

// Create a lookup wrapper for a dns_record_t.
static dns_hash_lookup_t *
create_lookup_record (dns_record_t *record)
{
  dns_hash_lookup_t *lookup = calloc (1, sizeof (*lookup));
  if (!lookup)
    return NULL;
  lookup->self = record;
  lookup->connections = calloc (MAX_RECORDS, sizeof (dns_hash_lookup_t *));
  lookup->num_connections = 0;
  return lookup;
}

// Insert a lookup record into the hash table based on its type (only if
// supported type).
static void
insert_into_hash (dns_hash_t *hash, dns_hash_lookup_t *l_rec)
{
  int idx = get_record_index (ntohs (l_rec->self->type));
  if (idx < 0)
    return;
  dns_type_record_t *curr_rec = &hash->type_records[idx];
  curr_rec->records[curr_rec->num_records++] = l_rec;
}

// Convert a dns_record_t from host to network order in place.
static void
hton_rec (dns_record_t *rec)
{
  rec->type = htons (rec->type);
  rec->class = htons (rec->class);
  rec->ttl = htonl (rec->ttl);
  rec->rd_length = htons (rec->rd_length);
}

// Normalize the rdata numerical fields in SOA and MX records
// because they need to be endianness swapped.
static void
normalize_rdata (dns_record_t *rec)
{
  uint16_t type = rec->type;

  if (type == MX)
    {
      uint16_t preference;
      memcpy (&preference, rec->rdata, sizeof (preference));
      preference = htons (preference);
      memcpy (rec->rdata, &preference, sizeof (preference));
    }
  else if (type == SOA)
    {
      uint8_t *p = rec->rdata;

      consume_name (&p);
      consume_name (&p);

      for (int i = 0; i < 5; i++)
        {
          uint32_t value;
          memcpy (&value, p, sizeof (value));

          value = htonl (value);

          memcpy (p, &value, sizeof (value));
          p += sizeof (value);
        }
    }
}

// Allocate and populate a dns_record_t from a pointer into the
// mappings.bin data. Advances the pointer past the record.
static dns_record_t *
create_record (uint8_t **p)
{
  dns_record_t *rec = calloc (1, sizeof (dns_record_t));
  if (!rec)
    return NULL;
  rec->rname = *p;
  consume_name (p);
  rec->type = *(uint16_t *)(*p);
  *p += 2;
  rec->class = IN;
  rec->ttl = *(uint32_t *)(*p);
  *p += 4;
  rec->rd_length = *(uint16_t *)(*p);
  *p += 2;
  rec->rdata = calloc (rec->rd_length, sizeof (uint8_t));
  memcpy (rec->rdata, *p, rec->rd_length);
  *p += rec->rd_length;
  normalize_rdata (rec);
  hton_rec (rec);
  return rec;
}

// Connect two lookup records to indicate that they share the same
// resource record name or CNAME chain.
static void
add_connection (dns_hash_lookup_t *u, dns_hash_lookup_t *v)
{
  if (u == NULL || v == NULL || u == v)
    return;
  u->connections[u->num_connections++] = v;
}

// Checks if the given name contains the given suffix
static bool
name_has_suffix (char *name, char *suffix)
{
  size_t n_len = strlen (name);
  size_t s_len = strlen (suffix);

  if (s_len > n_len)
    return false;

  return strcmp (name + (n_len - s_len), suffix) == 0;
}

// Build connections between SOA records and their parent records.
// For each SOA record u, it locates records v whose type is SOA
// and its rname is a suffix of the parents name.
static void
connect_soa_parents (dns_hash_lookup_t **lookups, size_t num_recs,
                     dns_hash_t *hash)
{
  for (size_t i = 0; i < num_recs; i++)
    {
      dns_record_t *child = lookups[i]->self;

      if (ntohs (child->type) != SOA)
        continue;

      char *child_name = get_name (hash->file_data, child->rname, 0);

      for (size_t j = 0; j < num_recs; j++)
        {
          if (i == j)
            continue;

          dns_record_t *parent = lookups[j]->self;

          if (ntohs (parent->type) != SOA)
            continue;

          char *parent_name = get_name (hash->file_data, parent->rname, 0);

          if (name_has_suffix (child_name, parent_name))
            add_connection (lookups[i], lookups[j]);

          free (parent_name);
        }

      free (child_name);
    }
}

// Build connections between CNAME records and their targets. For each
// CNAME record u, it locates records v whose rname matches the CNAME's
// rdata and add a connection from u to v.
static void
connect_cname_targets (dns_hash_t *hash, dns_hash_lookup_t **lookups,
                       size_t num_recs)
{
  for (size_t i = 0; i < num_recs; i++)
    {
      dns_record_t *u = lookups[i]->self;
      if (ntohs (u->type) != CNAME)
        continue;
      char *u_name = get_name (hash->file_data, u->rdata, 0);
      for (size_t j = 0; j < num_recs; j++)
        {
          dns_record_t *v = lookups[j]->self;
          char *v_name = get_name (hash->file_data, v->rname, 0);
          if (!strcmp (u_name, v_name))
            add_connection (lookups[i], lookups[j]);
          free (v_name);
        }
      free (u_name);
    }
}

// Build connections between records of the same type that share the
// same name. Only unique pairs (i < j) are considered in order to prevent 2
// records pointing to eachother for later lookup.
static void
connect_regular_types (dns_hash_lookup_t **lookups, size_t num_recs,
                       dns_hash_t *hash)
{
  for (size_t i = 0; i < num_recs; i++)
    {
      dns_record_t *u = lookups[i]->self;
      char *u_name = get_name (hash->file_data, u->rname, 0);
      uint16_t u_type = ntohs (u->type);
      for (size_t j = i + 1; j < num_recs; j++)
        {
          dns_record_t *v = lookups[j]->self;
          char *v_name = get_name (hash->file_data, v->rname, 0);
          uint16_t v_type = ntohs (v->type);
          if (u_type == v_type && !strcmp (u_name, v_name))
            add_connection (lookups[i], lookups[j]);
          free (v_name);
        }
      free (u_name);
    }
}

// Build all connections between lookup records: same-name same-type and
// follow CNAME targets/pointers.
static void
find_connections (dns_hash_t *hash, dns_hash_lookup_t **lookups,
                  size_t num_recs)
{
  connect_regular_types (lookups, num_recs, hash);
  connect_cname_targets (hash, lookups, num_recs);
  connect_soa_parents (lookups, num_recs, hash);
}

// Build an array of response records from the answer lookup
// record and its connections. Only records matching the query type
// are included. The counts for answer, authority and additional
// sections are updated into the given pointers. The calling function must
// free the returned array.
static dns_record_t *
build_msg_response (dns_hash_lookup_t *answers, uint16_t qtype,
                    size_t *num_ans)
{
  size_t max_recs = answers->num_connections + 1;
  dns_record_t *recs = calloc (max_recs, sizeof (dns_record_t));
  size_t curr_idx = 0;
  uint16_t self_type = ntohs (answers->self->type);
  if (self_type == qtype)
    {
      recs[curr_idx++] = *answers->self;
      (*num_ans)++;
    }
  for (size_t i = 0; i < answers->num_connections; i++)
    {
      dns_hash_lookup_t *curr = answers->connections[i];
      uint16_t rtype = ntohs (curr->self->type);
      if (rtype == qtype)
        {
          recs[curr_idx++] = *curr->self;
          (*num_ans)++;
        }
    }
  dns_record_t *tmp = realloc (recs, curr_idx * sizeof (dns_record_t));
  if (tmp || curr_idx == 0)
    recs = tmp;
  return recs;
}

// Helper to check whether a lookup record appears in the visited list.
static bool
visited_contains (dns_hash_lookup_t **visited, size_t n,
                  dns_hash_lookup_t *node)
{
  for (size_t i = 0; i < n; i++)
    {
      if (visited[i] == node)
        return true;
    }
  return false;
}

// Finds the SOA record (if any) if a record lookup yields no results -> CNAME
// -> no results, then find SOA
static dns_record_t *
find_authority_soa (dns_hash_t *hash, char *qname)
{
  int soa_idx = get_record_index (SOA);
  if (soa_idx < 0)
    return NULL;

  dns_type_record_t *soa_hash = &hash->type_records[soa_idx];

  dns_record_t *best = NULL;
  size_t best_len = 0;

  for (size_t i = 0; i < soa_hash->num_records; i++)
    {
      dns_record_t *rec = soa_hash->records[i]->self;
      char *soa_name = get_name (hash->file_data, rec->rname, 0);

      if (name_has_suffix (qname, soa_name))
        {
          size_t len = strlen (soa_name);
          if (len > best_len)
            {
              best = rec;
              best_len = len;
            }
        }

      free (soa_name);
    }

  return best;
}

// Recursively collect a chain of CNAME records and any final answer
// records of the desired type. Avoid cycles by tracking visited
// nodes. THIS ONE TOOK FOREVER! Lol.
static void
collect_cname_chain (dns_hash_lookup_t *node, uint16_t qtype,
                     dns_record_t *out, size_t *out_idx, size_t *num_ans,
                     dns_hash_lookup_t **visited, size_t *num_visited)
{
  if (node == NULL)
    return;
  if (visited_contains (visited, *num_visited, node))
    return;
  visited[(*num_visited)++] = node;
  uint16_t node_type = ntohs (node->self->type);
  if (node_type == CNAME)
    {
      out[(*out_idx)++] = *node->self;
      (*num_ans)++;
      for (size_t i = 0; i < node->num_connections; i++)
        {
          dns_hash_lookup_t *child = node->connections[i];
          uint16_t child_type = ntohs (child->self->type);
          if (child_type == CNAME)
            collect_cname_chain (child, qtype, out, out_idx, num_ans, visited,
                                 num_visited);
        }
      for (size_t i = 0; i < node->num_connections; i++)
        {
          dns_hash_lookup_t *child = node->connections[i];
          uint16_t child_type = ntohs (child->self->type);
          if (child_type == qtype)
            {
              out[(*out_idx)++] = *child->self;
              (*num_ans)++;
            }
        }
    }
  else if (node_type == qtype)
    {
      out[(*out_idx)++] = *node->self;
      (*num_ans)++;
    }
}

// Build an array of response records following a CNAME chain.
// The calling function must free the returned array.
static dns_record_t *
build_msg_response_cname (dns_hash_lookup_t *answers, uint16_t qtype,
                          char *qname, size_t *num_ans, size_t *num_auth,
                          dns_hash_t *hash)
{
  dns_record_t *recs = calloc (MAX_RECORDS, sizeof (dns_record_t));
  dns_hash_lookup_t **visited
      = calloc (MAX_RECORDS, sizeof (dns_hash_lookup_t *));
  size_t curr_idx = 0;
  size_t num_visited = 0;
  collect_cname_chain (answers, qtype, recs, &curr_idx, num_ans, visited,
                       &num_visited);
  free (visited);

  bool found_requested_type = false;

  for (size_t i = 0; i < curr_idx; i++)
    {
      if (ntohs (recs[i].type) == qtype)
        {
          found_requested_type = true;
          break;
        }
    }

  if (!found_requested_type && qtype != CNAME)
    {
      dns_record_t *soa = find_authority_soa (hash, qname);

      if (soa != NULL)
        {
          recs[curr_idx++] = *soa;
          (*num_auth)++;
        }
    }

  dns_record_t *tmp = realloc (recs, curr_idx * sizeof (dns_record_t));
  if (tmp || curr_idx == 0)
    recs = tmp;
  return recs;
}

// Perform a type-specific lookup for a single question, building the
// response message. If a matching record is found, the response
// fields of msg are updated.
static void
lookup_from_type (dns_message_t *msg, char *q_name,
                  dns_type_record_t *type_hash, uint16_t qdidx,
                  bool use_compression)
{
  size_t num_recs = type_hash->num_records;
  for (size_t i = 0; i < num_recs; i++)
    {
      dns_record_t *check = type_hash->records[i]->self;
      char *check_name = get_name (NULL, check->rname, 0);
      if (!strcmp (q_name, check_name))
        {
          uint16_t query_type = ntohs (msg->questions[qdidx].type);
          size_t num_answers = 0;
          size_t num_authority = 0;
          size_t num_additional = 0;
          dns_record_t *recs = build_msg_response (type_hash->records[i],
                                                   query_type, &num_answers);
          msg->record_count = num_answers + num_authority + num_additional;
          msg->header.ancount = htons (num_answers);
          msg->header.arcount = htons (num_additional);
          msg->header.nscount = htons (num_authority);
          msg->records = recs;
          free (check_name);
          return;
        }
      free (check_name);
    }
}

// Perform a CNAME lookup for a single question. If a CNAME
// record rname equals the query qname, the response fields
// of msg are updated.
static void
lookup_from_cname (dns_message_t *msg, char *q_name,
                   dns_type_record_t *cname_hash, uint16_t qdidx,
                   bool use_compression, dns_hash_t *hash)
{
  size_t num_recs = cname_hash->num_records;
  for (size_t i = 0; i < num_recs; i++)
    {
      dns_record_t *check = cname_hash->records[i]->self;
      char *check_name = get_name (NULL, check->rname, 0);
      if (!strcmp (q_name, check_name))
        {
          uint16_t query_type = ntohs (msg->questions[qdidx].type);
          size_t num_answers = 0;
          size_t num_authority = 0;
          size_t num_additional = 0;
          dns_record_t *recs = build_msg_response_cname (
              cname_hash->records[i], query_type, q_name, &num_answers,
              &num_authority, hash);
          if (num_answers == 1 && query_type != CNAME)
            msg->record_count = num_answers + num_authority + num_additional;
          msg->header.ancount = htons (num_answers);
          msg->header.arcount = htons (num_additional);
          msg->header.nscount = htons (num_authority);
          msg->records = recs;
          free (check_name);
          return;
        }
      free (check_name);
    }
}

// Given a query message and the hash table, produce a response
// message with answer records populated if matches are found. If no
// matches are found, the record_count remains zero.
static dns_message_t
lookup_question (dns_message_t *query, bool use_compression, dns_hash_t *hash)
{
  dns_header_t hdr;
  hdr.flags = query->header.flags;
  hdr.xid = query->header.xid;
  hdr.ancount = 0;
  hdr.arcount = 0;
  hdr.nscount = 0;
  hdr.qdcount = query->header.qdcount;
  dns_message_t resp;
  resp.header = hdr;
  resp.questions = query->questions;
  resp.record_count = 0;
  resp.records = NULL;
  for (size_t i = 0; i < ntohs (hdr.qdcount); i++)
    {
      char *qname = get_name (NULL, query->questions[i].qname, 0);
      uint16_t qtype = ntohs (query->questions[i].type);
      int idx = get_record_index (qtype);
      if (idx >= 0)
        {
          dns_type_record_t *type_hash = &hash->type_records[idx];
          lookup_from_type (&resp, qname, type_hash, (uint16_t)i,
                            use_compression);
          if (resp.record_count == 0 && qtype != CNAME)
            {
              int cname_idx = get_record_index (CNAME);
              if (cname_idx >= 0)
                {
                  dns_type_record_t *cname_hash
                      = &hash->type_records[cname_idx];
                  lookup_from_cname (&resp, qname, cname_hash, (uint16_t)i,
                                     use_compression, hash);
                }
            }
        }
      free (qname);
    }
  return resp;
}

// Load up to max_hash DNS records from a mappings.bin file into the provided
// hash. The file must contain a sequence of dns_record_t entries in host byte
// format. Connections between
// records are created after parsing.
static void
hash_records (dns_hash_t *hash, char *filename, size_t max_hash)
{
  hash->file_data = read_file (filename, &hash->file_len);
  if (hash->type_records == NULL || hash->file_data == NULL)
    return;
  uint8_t *p = hash->file_data;
  uint8_t *end = hash->file_data + hash->file_len;
  dns_hash_lookup_t **lookups
      = calloc (max_hash, sizeof (dns_hash_lookup_t *));
  size_t num_recs = 0;
  while (p < end && num_recs < max_hash)
    {
      dns_record_t *rec = create_record (&p);
      dns_hash_lookup_t *lookup = create_lookup_record (rec);
      lookups[num_recs++] = lookup;
      insert_into_hash (hash, lookup);
    }
  find_connections (hash, lookups, num_recs);
  free (lookups);
}

// Print MX record data in a structured form.
static void
print_as_MX (char *rdata)
{
  char *preference = strtok (rdata, " ");
  char *domain = strtok (NULL, " ");
  printf ("%s (preference %s)\n\n", domain, preference);
}

// Swaps the endianness number strings in the SOA record
// static uint32_t
// swap_string_num_bytes (char *s)
// {
//   uint32_t n = (uint32_t)strtoul (s, NULL, 10);
//   return ntohl (n);
// }

// Print SOA record data in a structured form.
static void
print_as_SOA (char *rdata)
{
  char *m_name = strtok (rdata, " ");
  char *r_name = strtok (NULL, " ");
  char *serial = strtok (NULL, " ");
  char *refresh = strtok (NULL, " ");
  char *retry = strtok (NULL, " ");
  char *expire = strtok (NULL, " ");
  char *minimum = strtok (NULL, " ");

  // uint32_t serial_n = swap_string_num_bytes (serial);
  // uint32_t refresh_n = swap_string_num_bytes (refresh);
  // uint32_t retry_n = swap_string_num_bytes (retry);
  // uint32_t expire_n = swap_string_num_bytes (expire);
  // uint32_t minimum_n = swap_string_num_bytes (minimum);

  printf ("primary = %s\n", m_name);
  printf ("            mailbox = %s\n", r_name);
  printf ("            expire  = %s seconds until not authoritative\n",
          expire);
  printf ("            minimum = %s seconds for minimum TTL\n", minimum);
  printf ("            refresh = %s seconds until refresh needed\n", refresh);
  printf ("            retry   = %s seconds after failed refresh\n", retry);
  printf ("            serial  = %s\n\n", serial);
}

// Print structured rdata when appropriate for MX and SOA records.
static void
print_structured_rdata (char *rdata, char *type)
{
  char *local_rdata = strdup (rdata);
  if (!strcmp ("MX", type))
    print_as_MX (local_rdata);
  else if (!strcmp ("SOA", type))
    print_as_SOA (local_rdata);
  free (local_rdata);
}

// Print a single record in a human-readable form for lookup output.
static void
print_lookup_handle (dns_message_t *msg, size_t rnum)
{
  char *name = get_record_name (msg, rnum);
  char *type_str = get_record_type_str (msg, rnum);
  uint16_t type = get_record_type_host (msg, rnum);
  uint32_t ttl = get_record_ttl_host (msg, rnum);
  printf ("    record: %s (type %u = %s, TTL %u)\n", name, type, type_str,
          ttl);
  printf ("    rdata : ");
  char *rdata = get_record_rdata (msg, rnum);
  if (strcmp (type_str, "MX") && strcmp (type_str, "SOA"))
    printf ("%s\n\n", rdata);
  print_structured_rdata (rdata, type_str);
  free (rdata);
  free (name);
}

// Print the results of a lookup in formatted representation (So far this was
// only used for the "stable" checks in INTER). Sections are printed only when
// they contain records.
static void
print_lookup_output (dns_message_t *msg)
{
  uint16_t ancount = get_ancount_host (msg);
  uint16_t nscount = get_nscount_host (msg);
  uint16_t arcount = get_arcount_host (msg);
  if (ancount > 0)
    printf ("Answers (uncompressed):\n");
  for (size_t i = 0; i < ancount; i++)
    print_lookup_handle (msg, i);
  if (nscount > 0)
    printf ("Authority:\n");
  for (size_t i = ancount; i < ancount + nscount; i++)
    print_lookup_handle (msg, i);
  if (arcount > 0)
    printf ("Additional:\n");
  for (size_t i = ancount + nscount; i < ancount + nscount + arcount; i++)
    print_lookup_handle (msg, i);
}
