// SPDX-License-Identifier: Beerware
#define _GNU_SOURCE
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

static void usage(FILE *fp)
{
	fprintf(fp, "usage: hagridd [-aBIND_ADDR] [-pBIND_PORT] <-cCONF_FILE>\n"
		    "  -aBIND_ADDR  IPv4 address to bind to (default INADDR_ANY)\n"
		    "  -pBIND_PORT  UDP port to bind to (default 9992)\n"
		    "  -cCONF_FILE  must contain line delimited peer specifications\n\n");
	exit(fp == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

enum encap {
	ENCAP_INVALID = 0,
	ENCAP_NONE,
	ENCAP_FOU,
	ENCAP_GUE,
};

struct hagrid_msg {
	uint32_t id;
	struct in_addr addr;
	char digest[32];
};

struct peer {
	char ifname[IFNAMSIZ];
	enum encap encap;
	uint32_t id;
	char secret[65];
};

static struct peer *peers;
static int npeers;

static enum encap strtoencap(const char *encap)
{
	if (!strcmp(encap, "none"))
		return ENCAP_NONE;
	else if (!strcmp(encap, "fou"))
		return ENCAP_FOU;
	else if (!strcmp(encap, "gue"))
		return ENCAP_GUE;
	else
		return ENCAP_INVALID;
}

static void add_peer(const char *ifname, enum encap encap, uint32_t id, const char *secret)
{
	struct peer *p;

	++npeers;
	peers = realloc(peers, sizeof(*peers) * npeers);
	if (!peers)
		die("realloc");

	p = &peers[npeers - 1];
	strcpy(p->ifname, ifname);
	p->encap = encap;
	p->id = id;
	strcpy(p->secret, secret);

	printf("added peer %s:%i:%u\n", p->ifname, p->encap, p->id);
}

static struct peer *find_peer(uint32_t id)
{
	int i;

	for (i = 0; i < npeers; ++i)
		if (peers[i].id == id)
			return &peers[i];

	return NULL;
}

static char *strspace(char *p)
{
	while (*p && !isspace(*p))
		++p;

	return *p ? p : NULL;
}

static char *skip_spaces(char *p)
{
	while (*p && isspace(*p))
		++p;

	return p;
}

static void read_peers(const char *path)
{
	char *line;
	ssize_t rd;
	FILE *fp;
	size_t n;
	int i;

	fp = fopen(path, "r");
	if (!fp)
		die("cannot open %s: %m", path);

	line = NULL;
	n = 0;
	i = 1;
	while ((rd = getline(&line, &n, fp)) > 0) {
		char *ifname, *encapstr, *idstr, *secret, *end;
		enum encap encap;
		uint32_t id;

		ifname = skip_spaces(line);
		if (*ifname == '\0' || *ifname == '#') {
			++i;
			continue;
		}

		encapstr = strspace(ifname);
		if (!encapstr || (encapstr - ifname >= IFNAMSIZ))
			goto spec_fail;
		*encapstr++ = '\0';

		encapstr = skip_spaces(encapstr);
		idstr = strspace(encapstr);
		if (!idstr)
			goto spec_fail;
		*idstr++ = '\0';
		encap = strtoencap(encapstr);
		if (!encap)
			goto spec_fail;

		idstr = skip_spaces(idstr);
		secret = strspace(idstr);
		if (!secret)
			goto spec_fail;

		errno = 0;
		id = strtoul(idstr, &end, 0);
		if (errno || secret != end)
			goto spec_fail;
		*secret++ = '\0';

		secret = skip_spaces(secret);
		end = strspace(secret);
		if (end)
			*end = '\0';

		if (strlen(secret) > 64)
			goto spec_fail;

		add_peer(ifname, encap, id, secret);
		++i;
		continue;
spec_fail:
		die("wrong peer specification on %s:%i", path, i);
	}

	fclose(fp);
}

static void handle_change(struct hagrid_msg *msg, struct peer *p, const char *req_addr)
{
	char cmd[256];
	char *new_addr = inet_ntoa(msg->addr);

	printf("valid msg from %s: peer %u (interface %s) changing remote address to %s\n",
	       req_addr, ntohl(msg->id), p->ifname, new_addr);

	sprintf(cmd, "ip tunnel change %s remote %s", p->ifname, new_addr);
	system(cmd);
}

int main(int argc, char **argv)
{
	int sock, i, port;
	struct sockaddr_in addr;
	const char *addr_arg = "inaddr_any";

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0;
	addr.sin_port = htons(9992);

	for (i = 1; i < argc; ++i) {
		const char *arg = argv[i] + 2;

		if (argv[i][0] != '-')
			usage(stderr);

		switch (argv[i][1]) {
		case 'p':
			addr.sin_port = htons(atoi(arg));
			break;
		case 'a':
			if (!inet_aton(arg, &addr.sin_addr))
				die("Wrong address %s", arg);
				addr_arg = arg;
			break;
		case 'c':
			read_peers(arg);
			break;
		case 'h':
			usage(stdout);
		default:
			usage(stderr);
		}
	}

	if (!npeers)
		die("no peers specified");

	sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		die("socket: %m");

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
		die("cannot bind %s:%u: %m", addr_arg, ntohs(addr.sin_port));

	printf("listening on %s:%u\n", addr_arg, ntohs(addr.sin_port));

	while (1) {
		struct hagrid_msg *msg;
		struct sockaddr_in peer;
		socklen_t slen = sizeof(peer);
		char buf[64], peer_addr[22], digest[32];
		SHA256_CTX ctx;
		struct peer *p;
		ssize_t rd;

		rd = recvfrom(sock, buf, 64, MSG_TRUNC, (struct sockaddr *)&peer, &slen);
		if (rd < 0) {
			fprintf(stderr, "recvfrom: %m\n");
			continue;
		}

		sprintf(peer_addr, "%s:%u", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

		if (rd != sizeof(*msg)) {
			fprintf(stderr, "wrong message size from %s\n", peer_addr);
			continue;
		}

		msg = (void *)buf;

		p = find_peer(ntohl(msg->id));
		if (!p) {
			fprintf(stderr, "unknown peer id %u requested from %s\n", ntohl(msg->id),
				peer_addr);
			continue;
		}

		sha256_init(&ctx);
		sha256_update(&ctx, buf, 8);
		sha256_update(&ctx, p->secret, strlen(p->secret));
		sha256_final(&ctx, digest);

		if (memcmp(msg->digest, digest, 32)) {
			fprintf(stderr, "wrong digest from %s\n", peer_addr);
			continue;
		}

		/* if client didn't fill up address, fill peer address from socket */
		if (!msg->addr.s_addr)
			msg->addr.s_addr = peer.sin_addr.s_addr;

		handle_change(msg, p, peer_addr);
	}
}
