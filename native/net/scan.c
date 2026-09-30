#include "scan.h"
#include "../cpp/dispatch/dispatch.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <stdio.h>

static int set_nonblock(int fd) {
  int f = fcntl(fd, F_GETFL, 0);
  if (f < 0) return -1;
  return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static int connect_timeout(int fd, struct sockaddr* a, socklen_t n, int timeout_ms) {
  if (set_nonblock(fd) != 0) return -1;
  int r = connect(fd, a, n);
  if (r == 0) return 0;
  if (errno != EINPROGRESS) return -1;
  fd_set w; FD_ZERO(&w); FD_SET(fd, &w);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  r = select(fd + 1, 0, &w, 0, &tv);
  if (r <= 0) return -1;
  int err = 0; socklen_t m = sizeof(err);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &m) != 0) return -1;
  return err == 0 ? 0 : -1;
}

int clops_scan_ports(const char* host, const int* ports, int n_ports,
                     int timeout_ms, ClopsPortResult* out, int out_cap) {
  if (!host || !ports || !out) return -1;
  int found = 0;
  for (int i = 0; i < n_ports; i++) {
    char svc[16];
    snprintf(svc, sizeof(svc), "%d", ports[i]);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = 0;
    if (getaddrinfo(host, svc, &hints, &ai) != 0) continue;
    int open = 0;
    int lat = 0;
    for (struct addrinfo* p = ai; p; p = p->ai_next) {
      int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (fd < 0) continue;
      if (connect_timeout(fd, p->ai_addr, p->ai_addrlen, timeout_ms) == 0) {
        open = 1;
        close(fd);
        break;
      }
      close(fd);
    }
    freeaddrinfo(ai);
    if (open && found < out_cap) {
      out[found].port = ports[i];
      out[found].open = 1;
      out[found].service[0] = 0;
      out[found].version[0] = 0;
      out[found].banner[0] = 0;
      out[found].latency_ms = lat;
      found++;
    }
  }
  return found;
}

int clops_banner_grab(const char* host, int port, int timeout_ms,
                      char* out, int out_cap) {
  if (!host || !out || out_cap <= 1) return -1;
  char svc[16];
  snprintf(svc, sizeof(svc), "%d", port);
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* ai = 0;
  if (getaddrinfo(host, svc, &hints, &ai) != 0) return -1;
  int fd = -1;
  for (struct addrinfo* p = ai; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    if (connect_timeout(fd, p->ai_addr, p->ai_addrlen, timeout_ms) == 0) break;
    close(fd); fd = -1;
  }
  freeaddrinfo(ai);
  if (fd < 0) return -1;
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ssize_t n = recv(fd, out, (size_t)(out_cap - 1), 0);
  close(fd);
  if (n <= 0) { out[0] = 0; return 0; }
  out[n] = 0;
  // Strip non printable except \r \n \t for safe table display.
  for (ssize_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)out[i];
    if (c < 32 && c != (unsigned char)'\r' && c != (unsigned char)'\n' && c != (unsigned char)'\t') out[i] = '.';
  }
  return (int)n;
}
