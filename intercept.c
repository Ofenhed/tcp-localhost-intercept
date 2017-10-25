#define _GNU_SOURCE 1
#ifndef CUSTOM
#define ALL_SOCKETS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <pwd.h>
#include <errno.h>

#ifndef SOCK_PATH
#define SOCK_PATH "%s/.tcp/socket-%d"
#endif

#ifndef MAX_SOCKETS
#define MAX_SOCKETS 1024
#endif

static int c_sockets = 0;
static struct {
  int sockfd;
  unsigned short port;
} sockets[MAX_SOCKETS];

static int get_path(char* buf, size_t len, unsigned short port) {
  struct passwd *pw = getpwuid(getuid());

  return snprintf(buf, len, SOCK_PATH, pw->pw_dir, ntohs(port));
}

static int add_socket(int sockfd, unsigned short port)
{
  if (c_sockets < MAX_SOCKETS) {
    sockets[c_sockets].sockfd = sockfd;
    sockets[c_sockets].port = port;
    ++c_sockets;
    return 1;
  }
  return 0;
}

static void remove_socket(int idx)
{
  --c_sockets;
  if (idx == c_sockets) {
    return;
  }
  sockets[idx] = sockets[c_sockets];
}

static int find_socket(int sockfd) {
  for (int i = 0; i < c_sockets; ++i) {
    if (sockets[i].sockfd == sockfd) {
      return i;
    }
  }
  return MAX_SOCKETS;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  int (*orig_func)(int, const struct sockaddr*, socklen_t) = dlsym(RTLD_NEXT, "bind");

  const struct sockaddr_in *addr2 = (const struct sockaddr_in*)addr;
  struct sockaddr_un newaddr = { AF_UNIX };

  // Check if the socket qualifies, e.g. it tries to open a TCP port on
  // localhost (or INADDR_ANY if ALL_SOCKETS is defined)
  if (addr->sa_family == AF_INET && (
#ifdef ALL_SOCKETS
        addr2->sin_addr.s_addr == INADDR_ANY ||
#endif
        addr2->sin_addr.s_addr == inet_addr("127.0.0.1"))) {
    printf("Calling modified bind\n");

    // Close the AF_INET socket and reopen it as a sock_stream. We can't change
    // the FD with the user, so we have to make sure that our new socket gets
    // the same FD.
    int newsock = sockfd;
    do {
      close(newsock);
      newsock = socket(AF_UNIX, SOCK_STREAM, 0);
    } while (newsock != sockfd);

    // Make sure we can store the socket.
    if (!add_socket(sockfd, addr2->sin_port)) {
      errno = ENOMEM;
      return -1;
    }

    // Get the correct filename and bind the file.
    get_path(newaddr.sun_path, sizeof(newaddr.sun_path), addr2->sin_port);
    int result = orig_func(sockfd, (const struct sockaddr*)&newaddr, sizeof(newaddr));

    // If bind() was not sucessful, make sure it is removed from the list of
    // stored sockets.
    if (result != 0) {
      remove_socket(c_sockets - 1);
    }
    return result;
  }
  return orig_func(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  int (*orig_func)(int, const struct sockaddr*, socklen_t) = dlsym(RTLD_NEXT, "connect");

  const struct sockaddr_in *addr2 = (const struct sockaddr_in*)addr;
  struct sockaddr_un newaddr = { AF_UNIX };
  // Check if the socket qualifies, e.g. it tries to connect via TCP to
  // localhost.
  if (addr->sa_family == AF_INET && addr2->sin_addr.s_addr == inet_addr("127.0.0.1")) {
    printf("Calling modified connect\n");

    // Close the AF_INET socket and reopen it as a sock_stream. We can't change
    // the FD with the user, so we have to make sure that our new socket gets
    // the same FD.
    int newsock = sockfd;
    do {
      close(newsock);
      newsock = socket(AF_UNIX, SOCK_STREAM, 0);
    } while (newsock != sockfd);


    // Get the correct filename and bind the file.
    get_path(newaddr.sun_path, sizeof(newaddr.sun_path), addr2->sin_port);
    return orig_func(sockfd, (const struct sockaddr*)&newaddr, sizeof(newaddr));
  }
  return orig_func(sockfd, addr, addrlen);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int (*orig_func)(int, const struct sockaddr*, socklen_t*) = dlsym(RTLD_NEXT, "accept");
  int result = orig_func(sockfd, addr, addrlen);

  // If the user didn't provide a addr, or the socket can't be found in our
  // list, don't do anything else than call accept.
  if (addr != NULL) {
    int sock = find_socket(sockfd);
    if (sock != MAX_SOCKETS && sizeof(struct sockaddr_in) <= *addrlen) {
      // It is one of our sockets, forge it to make it look like the connection
      // was from TCP/localhost.
      struct sockaddr_in *peer = (struct sockaddr_in*)addr;
      peer->sin_family = AF_INET;
      peer->sin_addr.s_addr = inet_addr("127.0.0.1");
      peer->sin_port = sockets[sock].port;
      *addrlen = sizeof(struct sockaddr_in);
    }
  }
  return result;
}

int close(int sockfd)
{
  int (*orig_func)(int) = dlsym(RTLD_NEXT, "close");
  int sock = find_socket(sockfd);
  // If close is called on one of our sockets, make sure that the opened file
  // is also removed.
  if (sock != MAX_SOCKETS) {
    struct sockaddr_un addr;
    get_path(addr.sun_path, sizeof(addr.sun_path), sockets[sock].port);
    unlink(addr.sun_path);
    remove_socket(sock);
  }
  return orig_func(sockfd);
}
