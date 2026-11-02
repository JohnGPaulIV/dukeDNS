#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "dns.h"
#include "port_utils.h"
#include "utils.h"

// Reads the entire contents of the file named by (fname) into an
// allocated buffer. The size of the buffer is stored in (fsize). The calling
// function is responsible for freeing the returned buffer.
uint8_t *
read_file (char *fname, size_t *fsize)
{
  FILE *fp = fopen (fname, "rb");
  if (fp == NULL)
    return NULL;

  if (fseek (fp, 0, SEEK_END) != 0)
    {
      fclose (fp);
      return NULL;
    }

  long size = ftell (fp);
  if (size < 0)
    {
      fclose (fp);
      return NULL;
    }
  rewind (fp);

  uint8_t *buffer = calloc ((size_t)size, sizeof (uint8_t));
  if (buffer == NULL)
    {
      fclose (fp);
      return NULL;
    }

  size_t got = fread (buffer, 1, (size_t)size, fp);
  fclose (fp);

  if (got != (size_t)size)
    {
      free (buffer);
      return NULL;
    }

  *fsize = (size_t)size;
  return buffer;
}

// Print a block of bytes in a hexdump style.
void
print_byte_block (uint8_t *bytes, size_t length)
{
  printf ("  ");
  for (size_t i = 0; i < length; i++)
    {
      printf ("%02x", bytes[i]);
      if (i == length - 1)
        printf ("\n\n");
      else if ((i + 1) % 16 == 0)
        printf ("\n  ");
      else if ((i % 2) != 0)
        printf (" ");
    }
}

// Create a UDP socket for client or server use. Returns the file
// descriptor on success or -1 on error.
int
create_socket (void)
{
  return socket (AF_INET, SOCK_DGRAM, 0);
}

// Populate a sockaddr_in structure.
int
config_addr (struct sockaddr_in *addr, char *ip_str, socklen_t ip_str_len)
{
  char *port_str = get_port ();
  long port_num = strtol (port_str, NULL, 10);

  memset (addr, 0, sizeof (*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons ((uint16_t)port_num);

  if (inet_aton ("127.0.0.1", &addr->sin_addr) == 0)
    return -1;

  if (inet_ntop (AF_INET, &addr->sin_addr, ip_str, ip_str_len) == NULL)
    return -1;

  return 0;
}

// Set up a server UDP socket. Creates the socket, binds to the
// address and the configured port, and optionally applies
// timeout. Returns EXIT_SUCCESS on success or EXIT_FAILURE on error.
int
set_up_server (int *sock_fd, struct timeval *timeout, struct sockaddr_in *addr,
               char *ip_str)
{
  *sock_fd = create_socket ();
  if (*sock_fd == -1)
    return EXIT_FAILURE;

  int opt = 1;
  setsockopt (*sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));

  if (config_addr (addr, ip_str, INET6_ADDRSTRLEN) < 0)
    {
      close (*sock_fd);
      return EXIT_FAILURE;
    }

  if (bind (*sock_fd, (struct sockaddr *)addr, sizeof (*addr)) < 0)
    {
      close (*sock_fd);
      return EXIT_FAILURE;
    }

  if (timeout != NULL)
    setsockopt (*sock_fd, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof (*timeout));

  return EXIT_SUCCESS;
}

// Set up a client UDP socket and construct a DNS request. Creates
// the socket and configures the address. The request buffer is
// populated by build_dns_request from dns.c. Returns the number of
// bytes in the request or 0 on failure.
size_t
set_up_client (int *xid, bool has_query_args, char *domain, char *type,
               int *sock_fd, struct sockaddr_in *addr, char *ip_str,
               uint8_t *request)
{
  *sock_fd = create_socket ();
  if (*sock_fd == -1)
    return 0;

  if (config_addr (addr, ip_str, INET6_ADDRSTRLEN) < 0)
    {
      close (*sock_fd);
      return 0;
    }

  *xid = (has_query_args && *xid == 1) ? 1000 : *xid;
  return build_dns_request (request, *xid, domain, type);
}

// Allocate a fresh dns_message_t with all fields zeroed.
dns_message_t *
create_msg (void)
{
  return calloc (1, sizeof (dns_message_t));
}

// Free a dns_message_t and any heap-allocated arrays it owns.
void
destroy_msg (dns_message_t *msg)
{
  if (msg == NULL)
    return;
  free (msg->questions);
  free (msg->records);
  free (msg);
}

// Free a dns_hash_t and any heap-allocated arrays it owns.
void
destroy_hash (dns_hash_t *hash)
{
  if (!hash)
    return;

  if (hash->type_records)
    {
      for (size_t i = 0; i < NUM_REC_TYPES; i++)
        {
          dns_type_record_t *t = &hash->type_records[i];

          if (t->records)
            {
              for (size_t j = 0; j < t->num_records; j++)
                {
                  dns_hash_lookup_t *lookup = t->records[j];
                  if (!lookup)
                    continue;

                  free (lookup->connections);

                  if (lookup->self)
                    {
                      free (lookup->self->rdata);
                      free (lookup->self);
                    }

                  free (lookup);
                }

              free (t->records);
            }
        }

      free (hash->type_records);
    }

  free (hash->file_data);

  hash->type_records = NULL;
  hash->file_data = NULL;
  hash->file_len = 0;
}