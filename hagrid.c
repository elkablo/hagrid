// SPDX-License-Identifier: Beerware
#define _GNU_SOURCE
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "sha256.h"

__attribute__((noreturn))
static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n\n");
	exit(EXIT_FAILURE);
}

static int parse_addr(struct sockaddr_in *dst, char *src)
{
	char *port = strchr(src, ':');
	unsigned long p;

	dst->sin_family = AF_INET;
	if (port)
		*port++ = '\0';

	if (!inet_aton(src, &dst->sin_addr))
		return -1;

	if (port) {
		p = strtoul(port, NULL, 10);
		if (p > 65535)
			return -1;

		dst->sin_port = htons(p);
	} else {
		dst->sin_port = 0;
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "usage: hagrid <REMOTE_ADDR:REMOTE_PORT> <my_spec> [NEW_ADDR]\n"
			"  ADDR:PORT  IPv4 address and port\n"
			"  my_spec    local peer specification in format 'id:secret',\n"
			"             where id is a 32-bit integer ID of this peer and secret is a shared\n"
			"             secret with remote (at most 64 characters)\n\n");
	exit(EXIT_FAILURE);
}

int main (int argc, char **argv)
{
	struct {
		uint32_t id;
		in_addr_t addr;
		char digest[32];
	} msg;
	int sock;
	struct sockaddr_in remote_addr, new_addr;
	char *idstr, *secret;
	unsigned long id;
	SHA256_CTX ctx;

	if (argc < 3 || argc > 4)
		usage();

	if (parse_addr(&remote_addr, argv[1]))
		die("failed parsing remote address");

	if (!remote_addr.sin_port)
		remote_addr.sin_port = htons(9992);

	if (argc > 3) {
		if (parse_addr(&new_addr, argv[3]))
			die("failed parsing new address");
	} else {
		memset(&new_addr, 0, sizeof(new_addr));
	}

	idstr = argv[2];
	errno = 0;
	id = strtoul(idstr, &secret, 0);
	if (errno || id > 0xffffffff || *secret != ':')
		die("wrong id in local peer specification");
	*secret++ = '\0';

	if (strlen(secret) > 64)
		die("secret too long in local peer specification");

	msg.id = htonl(id);
	msg.addr = new_addr.sin_addr.s_addr;

	sha256_init(&ctx);
	sha256_update(&ctx, (void *)&msg, 8);
	sha256_update(&ctx, secret, strlen(secret));
	sha256_final(&ctx, &msg.digest[0]);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		die("socket: %m");

	if (sendto(sock, (void *)&msg, sizeof(msg), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
		die("sendto: %m");

	close(sock);
}
