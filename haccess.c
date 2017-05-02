/*
 * haccess.c
 *
 * Check a client against /etc/hosts.{allow,deny}
 *
 * Copyright (C) 1995-1997, Olaf Kirch <okir@monad.swb.de>
 */

#include "site.h"

#ifdef HOSTS_ACCESS
#include "system.h"
#include "haccess.h"
#include <rpc/rpc.h>
#include "logging.h"
#ifdef HAVE_LIBWRAP_BUG
#include <syslog.h>
#endif

/* This is from libwrap.a */
extern int		hosts_ctl(char *, char *, char *, char *);

#define IP_HASH_MASK	0xF
#define IP_HASH(a)	((((a)>>24)^((a)>>16)^((a)>>8)^(a))&IP_HASH_MASK)

typedef struct clnt_host {
	struct clnt_host	*next;
	struct in_addr		clnt_addr;
	char			status;
} clnt_host;

#define HACS_MAXHOSTS		256
#define HACS_INTERVAL		3600		/* one hour */

static clnt_host		*clients[IP_HASH_MASK+1];
static unsigned int		nrhosts = 0;
static time_t			lastflush = 0;


/*
 * libwrap.a from tcp_wrappers-7.2 references these variables when built
 * with OPTIONS support, but does not define them.
 */
#ifdef HAVE_LIBWRAP_BUG
int	deny_severity = LOG_WARNING;
int	allow_severity = LOG_INFO;
#endif


int
client_checkaccess(char *rpcprog, struct sockaddr_in *sin, int checkport)
{
	struct in_addr	   addr = sin->sin_addr;
	struct clnt_host   *hp;
	int		   hash;
	time_t		   now;

	if (checkport && !SECURE_PORT(sin->sin_port)) {
		Dprintf(L_ERROR,
			"client %s called from illegal port %d\n",
				inet_ntoa(addr), ntohs(sin->sin_port));
		return 0;
	}

	/* Flush once per hour */
	if ((now = time(NULL)) - lastflush > HACS_INTERVAL)
		client_flushaccess();

	hash = IP_HASH(addr.s_addr);
	for (hp = clients[hash]; hp != NULL; hp = hp->next) 
		if (hp->clnt_addr.s_addr == addr.s_addr) break;

	if (hp == NULL) {
		if (nrhosts >= HACS_MAXHOSTS)
			client_flushaccess();

		hp = (clnt_host *) xmalloc(sizeof(*hp));
		hp->next = clients[hash];
		clients[hash] = hp;

		hp->clnt_addr = addr;
		hp->status = hosts_ctl(rpcprog, "unknown",
					inet_ntoa(addr), "root");
		nrhosts++;
	}

	if (!hp->status)
		Dprintf(L_ERROR, "access from host %s rejected\n",
					inet_ntoa(addr));

	return hp->status;
}

void
client_flushaccess(void)
{
	static int	flushing = 0;
	clnt_host	*hp;
	int		i;

	if (flushing)
		return;
	flushing = 1;

	Dprintf(D_AUTH, "flushed host access cache\n");
	for (i = 0; i < IP_HASH_MASK+1; i++) {
		while ((hp = clients[i]) != NULL) {
			clients[i] = hp->next;
			free (hp);
		}
	}
	nrhosts = 0;
	flushing = 0;
	lastflush = time(NULL);
}
#endif /* HOSTS_ACCESS */
