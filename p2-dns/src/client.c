#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dns.h"
#include "port_utils.h"
#include "utils.h"

static bool get_args (int, char **, bool *, int *);

int
main (int argc, char *argv[])
{
  bool opendns = false;
  int xid = 1;       // default value
  char *domain = ""; // root
  char *type = "A";  // default
  bool has_query_args = false;

  if (!get_args (argc, argv, &opendns, &xid))
    {
      fprintf (stderr, "ERROR: Show usage\n");
      return EXIT_FAILURE;
    }

  // domain and type are default values unless provided
  if (optind < argc)
    domain = argv[optind];

  if (optind + 1 < argc)
    {
      type = argv[optind + 1];
      has_query_args = true; // there are args present, set to true
    }

  int sock_fd = -1;
  struct sockaddr_in addr;
  char ip_str[INET6_ADDRSTRLEN];
  uint8_t request[BUFFER_LENGTH];

  size_t req_len = set_up_client (&xid, has_query_args, domain, type, &sock_fd,
                                  &addr, ip_str, request);
  if (req_len == 0)
    {
      if (sock_fd != -1)
        close (sock_fd);
      return EXIT_FAILURE;
    }

  ssize_t bytes_sent = sendto (sock_fd, request, req_len, 0,
                               (struct sockaddr *)&addr, sizeof (addr));
  if (bytes_sent != (ssize_t)req_len)
    {
      close (sock_fd);
      return EXIT_FAILURE;
    }

  if (!has_query_args)
    {
      printf ("Sending %ld bytes to %s:\n", bytes_sent, ip_str);
      print_byte_block (request, req_len);
    }

  uint8_t response[BUFFER_LENGTH];
  socklen_t addr_len = sizeof (addr);
  ssize_t bytes_recv = recvfrom (sock_fd, response, sizeof (response), 0,
                                 (struct sockaddr *)&addr, &addr_len);
  if (bytes_recv < 0)
    {
      close (sock_fd);
      return EXIT_FAILURE;
    }

  inet_ntop (AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
  if (!has_query_args)
    {
      printf ("Received %ld bytes from %s:\n", bytes_recv, ip_str);
      print_byte_block (response, bytes_recv);
    }

  dns_message_t *msg = destructure (response);
  if (!has_query_args)
    print_server_response (msg);
  else
    {
      print_dns_header (msg);
      print_question_section (msg);
      print_answer_section (msg);
      print_authority_section (msg);
      print_additional_section (msg);
    }

  destroy_msg (msg);
  close (sock_fd);
  return EXIT_SUCCESS;
}

static bool
get_args (int argc, char **argv, bool *opendns, int *xid)
{
  int ch = 0;
  while ((ch = getopt (argc, argv, "ox:")) != -1)
    {
      switch (ch)
        {
        case 'o':
          *opendns = true;
          break;
        case 'x':
          *xid = strtol (optarg, NULL, 10);
          break;
        default:
          return false;
        }
    }

  return true;
}
