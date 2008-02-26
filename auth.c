/*
 * This module contains all generic functions used by the authentication
 * mechanism.
 *
 * Copyright (C) 1995-1997 Olaf Kirch  <okir@monad.swb.de>
 *
 * This software maybe be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 */

#include "nfsd.h"

#define AUTH_DEBUG

static int  hostmatch(const char *, const char *);
static nfs_client * auth_get_client_internal(const char *hname, int *spec);
static void auth_check_wildcards(nfs_client *cp);
static void auth_add_mountlist(nfs_client *, nfs_mount *, int);
static void auth_sort_mountlist(nfs_mount *);
static void auth_create_hashent(nfs_client *, struct in_addr);
static void auth_hash_host(nfs_client *, struct hostent *);
static void auth_unhash_host(nfs_client *);
static void auth_free_list(nfs_client **);
static void auth_warn_anon(void);
static void auth_log_clients(nfs_client *cp);
#ifdef HAVE_INNETGR
static int  auth_match_netgroup(const char *netgroup, const char *hostname);
#endif
static struct hostent * auth_reverse_lookup(struct in_addr);
static struct hostent * auth_forward_lookup(const char *);

/*
 * It appears to be an old and long-standing tradition on Unices not
 * to declare the netgroup functions in any header file.
 * Glibc departs from that tradition, but I'm too lazy to devise an
 * autoconf test for that...
 */
#if defined(HAVE_INNETGR) && !defined(__GLIBC__)
extern int  innetgr(const char *netgroup, const char *host,
		    const char *user, const char *domain);
#endif

#define IPHASH(a)	(((a)^((a)>>8)^((a)>>16)^((a)>>24)) & (IPHASHMAX-1))
#define IPHASHMAX	32
#define IPCACHEMAX	16

typedef struct nfs_hash_ent {
	struct nfs_hash_ent *	next;
	struct in_addr		addr;
	nfs_client *		client;
} nfs_hash_ent;

typedef struct nfs_cache_ent {
	struct in_addr		addr;
	nfs_client *		client;
} nfs_cache_ent;

static nfs_hash_ent *		hashtable[IPHASHMAX];
static nfs_client *		known_clients = NULL;
static nfs_client *		unknown_clients = NULL;
static nfs_client *		wildcard_clients = NULL;
static nfs_client *		netgroup_clients = NULL;
static nfs_client *		netmask_clients = NULL;
static nfs_client *		anonymous_client = NULL;
static nfs_client *		default_client = NULL;
static unsigned int		nr_anonymous_clients = 0;
static int			initialized = 0;

/* We cache the results of the most recent client lookups */
static nfs_cache_ent		cached_clients[IPCACHEMAX];
static int			cached_next = 0;

/*
 * Mount options for the public export
 */
static nfs_options		default_options = {
					identity,	/* uid mapping */
					1,		/* root squash */
					0,		/* all squash */
					0,		/* some squashed */
					1,		/* secure port */
					0,		/* read-only */
					0,		/* relative links */
					0,		/* noaccess */
					1,		/* cross_mounts */
					(uid_t)-2,	/* default uid */
					(gid_t)-2,	/* default gid */
					0,		/* no NIS domain */
				};

static nfs_options		anonymous_options = {
					identity,	/* uid mapping */
					1,		/* root squash */
					1,		/* all squash */
					0,		/* some squashed */
					0,		/* secure port */
					1,		/* read-only */
					0,		/* relative links */
					0,		/* noaccess */
					1,		/* cross_mounts */
					(uid_t)-2,	/* default uid */
					(gid_t)-2,	/* default gid */
					0,		/* no NIS domain */
				};

/*
 * Small helper function for converting IP addresses
 */
static inline int
auth_aton(const char *name, struct in_addr *ap, const char **res)
{
	struct in_addr	addr;
	unsigned int	octets, m;
	int		okay = 0;

	addr.s_addr = 0;
	for (octets = 0; octets < 4; octets++) {
		if (octets) {
			if (*name != '.')
				goto out;
			name++;
		}
		if (!isdigit(*name))
			goto out;
		for (m = 0; isdigit(*name); name++)
			m = m * 10 + (unsigned char) *name - '0';
		if (m > 255)
			goto out;
		addr.s_addr = (addr.s_addr << 8) | m;
	}
	ap->s_addr = htonl(addr.s_addr);
	okay = 1;

out:
	/* If no res pointer given, string must end with NUL */
	if (!res && *name != '\0')
		return 0;

	if (res)
		*res = name;

	return okay;
}

static inline int
auth_atob(const char *name, struct in_addr *ap)
{
	int m;

	if (!isdigit(*name))
		return 0;
	for (m = 0; isdigit(*name); name++)
		m = m * 10 + (unsigned char) *name - '0';
	if (m > 32)
		return 0;
	ap->s_addr = m ? ~((1 << (32 - m)) - 1) : 0;
	return 1;
}

/*
 * Get a client entry for a specific name or pattern.
 * If necessary, this function performs a hostname lookup to
 * obtain the host's FQDN. This is for the benefit of those who
 * use aliases in /etc/exports, or mix qualified and unqualified
 * hostnames.
 *
 * FIXME: Make this function create the nfs_client entry if none
 * is found. Currently, this function is called only from auth_init
 * anyway, which creates the client entry if this function returns
 * NULL.
 */
nfs_client *
auth_get_client(char *hname)
{
	struct hostent	*hp;
	nfs_client	*cp;
	struct in_addr	haddr;
	int		is_special;

	if (hname == NULL || *hname == '\0') {
		auth_warn_anon();
		return anonymous_client;
	}

	if ((cp = auth_get_client_internal(hname, &is_special)) != 0)
		return cp;

	if (is_special)
		return NULL;

	/* Try to resolve the name */
	if (auth_aton(hname, &haddr, NULL))
		hp = auth_reverse_lookup(haddr);
	else
		hp = auth_forward_lookup(hname);

	if (hp != NULL)
		cp = auth_get_client_internal(hp->h_name, &is_special);

	return cp;
}

static nfs_client *
auth_get_client_internal(const char *hname, int *special)
{
	nfs_client	*cp;

	*special = 1;
	if (*hname == '@') {
		for (cp = netgroup_clients; cp != NULL; cp = cp->next) {
			if (!strcmp(cp->clnt_name, hname))
				return cp;
		}
		return NULL;
	}

	if (strchr(hname, '*') != NULL || strchr(hname, '?') != NULL) {
		for (cp = wildcard_clients; cp != NULL; cp = cp->next) {
			if (!strcmp(cp->clnt_name, hname))
				return cp;
		}
		return NULL;
	}

	if (isdigit(hname[0]) && strchr(hname, '/') != NULL) {
		for (cp = netmask_clients; cp != NULL; cp = cp->next) {
			if (!strcmp(cp->clnt_name, hname))
				return cp;
		}
		return NULL;
	}

	*special = 0;
	for (cp = unknown_clients; cp != NULL; cp = cp->next) {
		if (!strcmp(cp->clnt_name, hname))
			return cp;
	}

	for (cp = known_clients; cp != NULL; cp = cp->next) {
		if (!strcmp(cp->clnt_name, hname))
			return cp;
	}

	return NULL;
}

/*
 * Given a client and a pathname, try to find the proper mount point.
 * This code relies on the mount list being sorted from largest to
 * smallest w.r.t strcmp.
 */
nfs_mount *
auth_match_mount(nfs_client *cp, char *path)
{
	nfs_mount	*mp;
	char		c;

	if (path == NULL)
		return NULL;

	for (mp = cp->m; mp != NULL; mp = mp->next) {
		if (!strncmp(mp->path, path, mp->length) &&
		    ((c = path[mp->length]) == '/' || c == '\0')) {
			return mp;
		}
	}
	return NULL;
}

/*
 * Find a known client given its IP address.
 * The matching hash entry is moved to the list head. This may be useful
 * for sites with large exports list (e.g. due to huge netgroups).
 */
nfs_client *
auth_known_clientbyaddr(struct in_addr addr)
{
	nfs_hash_ent	**htp, *hep, *prv;

	htp = hashtable + IPHASH(addr.s_addr);
	hep = *htp;
	for (prv = NULL; hep != NULL; prv = hep, hep = hep->next) {
		if (hep->addr.s_addr == addr.s_addr) {
			if (prv != NULL) {
				prv->next = hep->next;
				hep->next = *htp;
				*htp = hep;
			}
			hep->client->clnt_addr = addr;
			return hep->client;
		}
	}
	return NULL;
}

/*
 * Find a known client given its FQDN.
 */
nfs_client *
auth_known_clientbyname(char *hname)
{
	nfs_client	*cp;

	if (hname == NULL)
		return NULL;

	for (cp = known_clients; cp != NULL; cp = cp->next) {
		if (!strcmp(cp->clnt_name, hname))
			return cp;
	}
	return NULL;
}

/*
 * Perform a reverse lookup on a client IP
 */
static struct hostent *
auth_reverse_lookup(struct in_addr addr)
{
	struct hostent	*hp;
	char		nambuf[256];
	char		**ap;

	hp = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET);

	Dprintf(D_AUTH, "auth_reverse_lookup(%s) %s\n",
		inet_ntoa(addr), hp? hp->h_name : "[FAIL]");

	if (hp != NULL) {
		const char	*n = hp->h_name;
		int		i;

		/* Keep temp copy of hostname. We must take care
		 * of trailing white space because some NIS servers
		 * put it into their maps, and libc doesn't remove it.
		 */
		for (i = 0; *n && i < sizeof(nambuf)-1; i++, n++) {
			if (*n == ' ' || *n == '\t')
				break;
			nambuf[i] = *n;
		}
		nambuf[i] = '\0';

		/*
		 * Do a forward lookup
		 * (FIXME: resolver lib may already have done this).
		 */
		hp = gethostbyname(nambuf);
		if (hp == NULL) {
			Dprintf(L_ERROR,
				"couldn't verify address of host %s\n",
				inet_ntoa(addr));
			return NULL;
		}
		if (hp->h_addrtype != AF_INET) {
			Dprintf(L_WARNING,
				"%s has address type %d != AF_INET.\n",
				inet_ntoa(addr), hp->h_addrtype);
			return NULL;
		}
		if (hp->h_length != 4) {
			Dprintf(L_WARNING,
				"%s has address length %d != 4.\n",
				inet_ntoa(addr), hp->h_length);
			return NULL;
		}

		/*
		 * Make sure this isn't a spoof attempt.
		 */
		for (ap = hp->h_addr_list; *ap != NULL; ap++) {
			if (!memcmp(*ap, &addr, hp->h_length))
				break;
		}

		if (*ap == NULL) {
			Dprintf(L_ERROR,
				"spoof attempt by %s: pretends to be %s!\n",
				inet_ntoa(addr), hp->h_name);
			return NULL;
		}
	}

	return hp;
}

/*
 * Perform a forward lookup on a hostname, with checks
 */
static struct hostent *
auth_forward_lookup(const char *hname)
{
	struct hostent	*hp;

	hp = gethostbyname(hname);

	Dprintf(D_AUTH, "auth_forward_lookup(%s) %s\n",
		hname, hp? hp->h_name : "[FAIL]");

	if (hp != NULL) {
		if (hp->h_addrtype != AF_INET) {
			Dprintf(L_WARNING,
				"%s has address type %d != AF_INET.\n",
				hname, hp->h_addrtype);
			return NULL;
		}
		if (hp->h_length != 4) {
			Dprintf(L_WARNING,
				"%s has address length %d != 4.\n",
				hname, hp->h_length);
			return NULL;
		}
	}
	return hp;
}

/*
 * Find an unknown client given its IP address. This functions checks
 * previously unresolved hostnames, wildcard hostnames, the anon client,
 * and the default client.
 *
 * After we have walked this routine for a single host once, it is
 * either authenticated, and has been added to know_clients, or it
 * is denied access, in which case we just ignore it.
 */
nfs_client *
auth_unknown_clientbyaddr(struct in_addr addr)
{
	struct hostent	*hp = NULL;
	nfs_client	*cp, *ncp = NULL;
	const char	*hname;

	Dprintf(D_AUTH, "check unknown clnt addr %s\n", inet_ntoa(addr));

	/* Don't reverse lookup if never needed */
	if (unknown_clients || wildcard_clients || netgroup_clients)
		hp = auth_reverse_lookup(addr);

	if (hp != NULL) {
		nfs_client	**cpp;

		Dprintf(D_AUTH, "\tclient name is %s\n", hp->h_name);
		hname = hp->h_name;

		/*
		 * First, check for clients that couldn't be resolved during
		 * initialization.
		 */
		for (cpp = &unknown_clients; (cp = *cpp); cpp = &cp->next) {
			if (!strcmp((*cpp)->clnt_name, hname)) {
				Dprintf(D_AUTH,
					"Found previously unknown host %s\n",
					hname);
				cp->clnt_addr = addr;

				/*
				 * remove client from list of unknown and
				 * add it to list of known hosts.
				 *
				 * Wildcards clients will be checked in the
				 * next step.
				 */
				*cpp = cp->next;
				cp->next = known_clients;
				known_clients = cp;

				/* Add host to hashtable */
				auth_hash_host(cp, hp);

				ncp = cp;
				break;
			}
		}

		/*
		 * Okay, now check for wildcard names. NB the wildcard
		 * patterns are sorted from most to least specific.
		 *
		 * The pattern matching should also be applied to
		 * all names in h_aliases.
		 */
		for (cpp = &wildcard_clients; (cp = *cpp); cpp = &cp->next) {
			if (hostmatch(hname, cp->clnt_name)) {
				Dprintf(D_AUTH,
					"client %s matched pattern %s\n",
					hname, cp->clnt_name);
				if (!ncp)
					ncp = auth_create_client(hname, hp);
				auth_add_mountlist(ncp, cp->m, 0);
				/* continue, loop over all wildcards */
			}
		}

		/*
		 * Try netgroups next.
		 */
#ifdef HAVE_INNETGR
		for (cpp = &netgroup_clients; (cp = *cpp); cpp = &cp->next) {
			if (auth_match_netgroup(cp->clnt_name+1, hname)) {
				Dprintf(D_AUTH,
					"client %s matched netgroup %s\n",
					hname, cp->clnt_name+1);
				if (!ncp)
					ncp = auth_create_client(hname, hp);
				auth_add_mountlist(ncp, cp->m, 0);
				/* continue, loop over all netgroups */
			}
		}
#endif
	} else {
		hname = inet_ntoa(addr);
	}

	/*
	 * Final step: check netmask clients
	 */
	for (cp = netmask_clients; cp != NULL; cp = cp->next) {
		if (!((addr.s_addr^cp->clnt_addr.s_addr)&cp->clnt_mask.s_addr)){
			Dprintf(D_AUTH, "client %s matched %s\n",
				hname, cp->clnt_name);
			if (!ncp)
				ncp = auth_create_client(hname, hp);
			auth_add_mountlist(ncp, cp->m, 0);
			/* continue, loop over all netmasks */
		}
	}

	if ((cp = anonymous_client) || (cp = default_client)) {
		if (!ncp) {
			Dprintf(D_AUTH, "Anonymous request from %s.\n", hname);
#if 0
			ncp = auth_create_client(hname, hp);
#else
			/* If only the anon client matched, just return
			 * its info without duplicating the entry. This
			 * should streamline operations for anon NFS
			 * exports. */
			if (++nr_anonymous_clients > 1000) {
				auth_unhash_host(anonymous_client);
				auth_unhash_host(default_client);
				nr_anonymous_clients = 0;
			}
			auth_create_hashent(cp, addr);
			return cp;
#endif
		}
		auth_add_mountlist(ncp, cp->m, 0);
	}

	if (ncp)
		auth_sort_mountlist(ncp->m);
	return ncp;
}

/*
 * Look up a client by address.
 * We currently maintain a simple round-robin cache of the n most recently
 * resolved addresses. Not sure how much this improves performance, but it
 * may help the anon nfs case.
 *
 * It also implements nicely a negative lookup cache for unknown clients.
 */
nfs_client *
auth_clientbyaddr(struct in_addr addr)
{
	nfs_client	*cp;
	int		i;

	/* First, look into cache of recent clients */
	for (i = 0; i < IPCACHEMAX; i++) {
		if (cached_clients[i].addr.s_addr == addr.s_addr)
			return cached_clients[i].client;
	}

	/* Check if this is a known host ... */
	if ((cp = auth_known_clientbyaddr(addr)) == NULL) {
		/* No, it's not. Check against list of unknown hosts */
		cp = auth_unknown_clientbyaddr(addr);
	}

	/* Put in the cache */
	cached_clients[cached_next].addr   = addr;
	cached_clients[cached_next].client = cp;
	cached_next = (cached_next + 1) % IPCACHEMAX;

	return cp;
}

/*
 * Create a client struct for the given hostname. The hp parameter
 * optionally contains hostent information obtained from a previous
 * gethostbyname.
 */
nfs_client *
auth_create_client(const char *hname, struct hostent *hp)
{
	nfs_client	*cp, **cpp;
	struct in_addr	haddr, hmask;
	const char	*ename;
	int		is_wildcard, is_netgroup, is_netmask, is_hostaddr,
			is_special, namelen;

	cp = (nfs_client *) xmalloc(sizeof(nfs_client));

	cp->clnt_addr.s_addr = INADDR_ANY;
	cp->flags = 0;
	cp->m = NULL;
	cp->umap = NULL;

	if (hname == NULL) {
		if (anonymous_client != NULL) {
			free (cp);
			cp = anonymous_client;
		} else {
			anonymous_client = cp;
		}
		cp->clnt_name = strdup("<anon clnt>");
		cp->next = NULL;
		cp->flags = AUTH_CLNT_ANONYMOUS;
		return cp;
	}

	is_wildcard = (strchr(hname, '*') || strchr(hname, '?'));
	is_netgroup = (hname[0] == '@');
	is_netmask  = 0;
	is_hostaddr = 0;

	if (auth_aton(hname, &haddr, &ename)) {
		if (*ename == '\0')
			is_hostaddr = 1;
		else if (*ename == '/' &&
			 (auth_aton(ename+1, &hmask, NULL) ||
			  auth_atob(ename+1, &hmask)))
			is_netmask = 1;
	}
	is_special = is_wildcard + is_netgroup + is_netmask;

	if (hp == NULL) {
		if (is_hostaddr) {
			hp = auth_reverse_lookup(haddr);
		} else if (!is_wildcard && !is_netgroup && !is_netmask) {
			hp = auth_forward_lookup(hname);
		}
	} else if (is_special) {
		Dprintf(L_WARNING,
			"Whoa: client %s has weird/illegal name %s\n",
			inet_ntoa(*(struct in_addr *) hp->h_addr),
			hname);
	}

	/* If lookup successful, use FQDN */
	if (hp != NULL)
		hname = hp->h_name;

	cp->clnt_name = xstrdup(hname);

	if (is_wildcard) {
		/* We have a wildcard name. Wildcard names are sorted
		 * in order of descending pattern length. This way,
		 * pattern *.pal.xgw.fi is matched before *.xgw.fi.
		 */
		cp->flags = AUTH_CLNT_WILDCARD;
		cpp = &wildcard_clients;
		namelen = strlen(hname);
		while (*cpp != NULL && namelen <= strlen((*cpp)->clnt_name)) {
			cpp = &((*cpp)->next);
		}
	} else if (is_netgroup) {
		/* Netgroup name. */
		cp->flags = AUTH_CLNT_NETGROUP;
		cpp = &netgroup_clients;
	} else if (is_hostaddr) {
		/* Just an address.
		 * We deviate slightly from the rule that we should always
		 * try to resolve unknown host names: if the admin
		 * specifies an IP address in the exports file, and
		 * we're not able to resolve it the first time around,
		 * we assume that the address will never have a hostname
		 * attached to it. */
		cpp = &known_clients;
		auth_create_hashent(cp, haddr);
	} else if (is_netmask) {
		/* Address/mask pair. */
		cpp = &netmask_clients;
		cp->clnt_addr = haddr;
		cp->clnt_mask = hmask;
		cp->flags     = AUTH_CLNT_NETMASK;
	} else if (hp == NULL) {
		cpp = &unknown_clients;
	} else {
		cpp = &known_clients;
		auth_hash_host(cp, hp);
	}
	cp->next = *cpp;
	*cpp = cp;

	return cp;
}

/*
 * Create the default client.
 */
nfs_client *
auth_create_default_client(void)
{
	nfs_client	*cp;

	if (default_client == NULL) {
		cp = (nfs_client *) xmalloc(sizeof(nfs_client));
		cp->clnt_name = NULL;
		cp->next = NULL;
		cp->flags = AUTH_CLNT_DEFAULT;
		cp->m = NULL;
		default_client = cp;
	}
	auth_warn_anon();
	return default_client;
}

static void
auth_warn_anon(void)
{
	static int	warned = 0;
	struct hostent	*hp;
	char		name[257];
	char		**ap;

	if (warned)
		return;
	warned = 1;

	if (gethostname(name, sizeof(name)) < 0) {
		Dprintf(L_ERROR, "can't get local hostname");
		return;
	}
	if ((hp = gethostbyname(name)) == NULL) {
		Dprintf(L_ERROR, "can't get my own address");
		return;
	}
	if (hp->h_addrtype != AF_INET) {
		Dprintf(L_ERROR, "local host address is not AF_INET?!");
		return;
	}
	for (ap = hp->h_addr_list; *ap; ap++) {
		struct in_addr	addr;
		unsigned long	net3, net2;

		addr = *(struct in_addr *) *ap;
		net3 = ntohl(addr.s_addr) & 0xff000000;
		net2 = ntohl(addr.s_addr) & 0x00ff0000;
		if (net3 == 0x0A000000 ||
		   (net3 == 0xAC000000 && 0x100000 <= net2 && net2 < 0x200000)||
		   (net3 == 0XC0000000 && 0xA80000 == net2))
			continue;
		Dprintf(L_WARNING, "exports file has anon entries, but host\n");
		Dprintf(L_WARNING, "has non-private IP address %s!\n",
					inet_ntoa(addr));
	}
}

/*
 * Create an entry in the hashtable of known clients.
 */
static void
auth_create_hashent(nfs_client *cp, struct in_addr addr)
{
	nfs_hash_ent	*hep;
	int		hash;

	hash = IPHASH(addr.s_addr);

	hep = (nfs_hash_ent *) xmalloc(sizeof(*hep));
	hep->client = cp;
	hep->addr = addr;
	hep->next = hashtable[hash];
	hashtable[hash] = hep;
}

static void
auth_hash_host(nfs_client *cp, struct hostent *hp)
{
	char	**ap;

	for (ap = hp->h_addr_list; *ap != NULL; ap++)
		auth_create_hashent(cp, *(struct in_addr *) *ap);
}

/*
 * This is used to unhash the default/anonymous client
 */
static void
auth_unhash_host(nfs_client *cp)
{
	nfs_hash_ent	**epp, *hep;
	unsigned int	i;

	if (cp == NULL)
		return;

	for (i = 0; i < IPHASHMAX; i++) {
		epp = hashtable + i;
		while ((hep = *epp) != 0) {
			if (hep->client == cp) {
				*epp = hep->next;
				free(hep);
			} else {
				epp = &hep->next;
			}
		}
	}
}

/*
 * After reading the entire exports file, this routine checks if any
 * of the known clients match any of the patterns in wildcard_clients.
 * If one does, the wildcard's mount points are added to its list of
 * mount points.
 */
void
auth_check_all_wildcards(void)
{
	nfs_client	*cp;

	for (cp = known_clients; cp != NULL; cp = cp->next) {
		auth_check_wildcards(cp);
	}
	for (cp = unknown_clients; cp != NULL; cp = cp->next) {
		auth_check_wildcards(cp);
	}
}

static void
auth_check_wildcards(nfs_client *cp)
{
	nfs_client	*wcp;

	for (wcp = wildcard_clients; wcp != NULL; wcp = wcp->next) {
		if (hostmatch(cp->clnt_name, wcp->clnt_name)) {
			auth_add_mountlist(cp, wcp->m, 0);
		}
	}
	if (anonymous_client != NULL) {
		auth_add_mountlist(cp, anonymous_client->m, 0);
	}
}

/*
 * Check all client structs that apply to a netgroup
 */
void
auth_check_all_netgroups(void)
{
#ifdef HAVE_INNETGR
	nfs_client	*ncp, *cp;
	char		*group;
	int		match;

	for (cp = known_clients; cp != NULL; cp = cp->next) {
		for (ncp = netgroup_clients; ncp != NULL; ncp = ncp->next) {
			group = ncp->clnt_name+1;
			match = auth_match_netgroup(group, cp->clnt_name);
			Dprintf(D_AUTH, "   match %s ~ %s %s\n",
				cp->clnt_name, group,
				match? "okay" : "fail");
			if (match)
				auth_add_mountlist(cp, ncp->m, 0);
		}
	}
#endif
}

#ifdef HAVE_INNETGR
/*
 * Match a given hostname against a netgroup.
 * Never thought that netgroups could be so complicated...
 */
static int
auth_match_netgroup(const char *netgroup, const char *hostname)
{
	char	*dot;
	int	match;

	/* First, try to match the hostname without splitting 
	 * off the domain */
	if (innetgr(netgroup, hostname, NULL, NULL))
		return 1;

	/* Okay, strip off the domain (if we have one) */
	if ((dot = strchr(hostname, '.')) == NULL)
		return 0;

	*dot = '\0';
	match = innetgr(netgroup, hostname, NULL, dot + 1);
	*dot = '.';

	return match;
}
#endif /* HAVE_INNETGR */

/*
 * Check all client structs that match an addr/mask pair
 */
void
auth_check_all_netmasks(void)
{
	nfs_client	*ncp, *cp;
	nfs_hash_ent	*hp;
	int		i, match;

	for (ncp = netmask_clients; ncp != NULL; ncp = ncp->next) {
		for (i = 0; i < IPHASHMAX; i++) {
			for (hp = hashtable[i]; hp != NULL; hp = hp->next) {
				match = ((hp->addr.s_addr 
				        ^ ncp->clnt_addr.s_addr)
			                & ncp->clnt_mask.s_addr) == 0;
				Dprintf(D_AUTH,
					"   match %s ~ %s %s\n",
					inet_ntoa(hp->addr),
					ncp->clnt_name,
					match? "okay" : "fail");
				if (match) {
					cp = hp->client;
					auth_add_mountlist(cp, ncp->m, 0);
				}
			}
		}
	}
}

/*
 * Log the current export table
 */
void
auth_log_all(void)
{
	if (!logging_enabled(D_AUTH))
		return;
	auth_log_clients(known_clients);
	auth_log_clients(unknown_clients);
	auth_log_clients(wildcard_clients);
	auth_log_clients(netgroup_clients);
	auth_log_clients(netmask_clients);
	auth_log_clients(anonymous_client);
	auth_log_clients(default_client);
}

static void
auth_log_clients(nfs_client *cp)
{
	nfs_mount	*mp;

	while (cp != 0) {
		Dprintf(D_AUTH, "clnt %s exports:\n", cp->clnt_name);
		for (mp = cp->m; mp != NULL; mp = mp->next) {
			Dprintf(D_AUTH, "\t%-20s\n",
				mp->path[0]? mp->path : "/");
			if (mp->parent)
				Dprintf(D_AUTH, "\t\tparent:  %s\n",
					mp->parent->path);
			if (mp->origin != cp)
				Dprintf(D_AUTH, "\t\torigin:  %s\n",
					mp->origin->clnt_name);
			Dprintf(D_AUTH, "\t\toptions:%s%s%s\n",
				mp->o.read_only?   " ro" : " rw",
				mp->o.root_squash? " noroot" : "",
				mp->o.secure_port? " portck" : "");
		}
		cp = cp->next;
	}
}

/*
 * Add a mount point to a client. Mount points are sorted from most
 * specific to least specific.
 */
nfs_mount *
auth_add_mount(nfs_client *cp, char *path, int override)
{
	nfs_mount	*mp, **mpp;
	int		len, tmp;

	len = strlen(path);

	/* Locate position of mount point in list of mount.
	 * Insert more specific path before less specific path.
	 *
	 * /foo/bar	(ro) host1(rw,no_root_squash)
	 *
	 * do the intuitive thing.
	 */
	for (mpp = &(cp->m); (mp = *mpp) != NULL; mpp = &(*mpp)->next) {
		tmp = strcmp((*mpp)->path, path);
		if (tmp == 0 && mp->client == cp) {
			if (override)
				break;
			return 0;
		}
		if (tmp < 0) {
			mp = 0;
			break;
		}
	}

	if (mp == 0) {
		mp = (nfs_mount*) xmalloc(sizeof(nfs_mount));
		memset(mp, 0, sizeof(*mp));
		mp->origin = cp;
		mp->client = cp;
		mp->path   = xstrdup(path);
		mp->length = strlen(path);
		mp->next   = *mpp;
		while (mp->length && path[mp->length-1] == '/')
			mp->length--;
		*mpp = mp;
	}

	/* Default options used */
	if (cp->flags & AUTH_CLNT_ANONYMOUS)
		memcpy (&mp->o, &anonymous_options, sizeof(nfs_options));
	else
		memcpy (&mp->o, &default_options, sizeof(nfs_options));

	return mp;
}

/*
 * Add a list of mount points to an existing client. This code looks
 * somewhat sub-optimal, but we have to make sure the overall order
 * of mount points is preserved (i.e. most specific to least specific).
 * Few Linux machines will have more than a dozen or so paths in their
 * exports file anyway.
 */
static void
auth_add_mountlist(nfs_client *cp, nfs_mount *mp, int override)
{
	nfs_mount	*nmp;

	while (mp != NULL) {
		nmp = auth_add_mount(cp, mp->path, override);
		if (nmp) {
			memcpy(&nmp->o, &mp->o, sizeof(nfs_options));
			nmp->origin = mp->origin;
		}
		mp = mp->next;
	}
}

/*
 * Sort a client's mount list
 */
static void
auth_sort_mountlist(nfs_mount *mp)
{
	nfs_mount	*up;

	for (; mp; mp = mp->next) {
		mp->parent = NULL;
		for (up = mp->next; up; up = up->next) {
			if (!strncmp(mp->path, up->path, up->length)
			  && mp->path[up->length] == '/') {
				mp->parent = up;
				break;
			}
		}
	}
}

/*
 * Sort all mount lists
 */
void
auth_sort_all_mountlists()
{
	nfs_client	*cp;

	for (cp = known_clients; cp != NULL; cp = cp->next)
		auth_sort_mountlist(cp->m);
}

/*
 * Match a hostname against a pattern.
 */
static int
hostmatch(const char *hname, const char *pattern)
{
	int seen_dot = 0;

	Dprintf(D_AUTH, "\tmatch %s ~ %s\n", hname, pattern);

	for (;;) {
		if (*hname == '\0' || *pattern == '\0')
			return (*hname == *pattern);
		switch (*pattern) {
		case '*':
			while (*hname != '.' && *hname != '\0')
				hname++;
			seen_dot = 1;
			pattern++;
			break;
		case '?':
			if (*hname == '.')
				return (0);
			hname++;
			pattern++;
			break;
		default:
			if (seen_dot) {
				if (tolower(*hname) != tolower(*pattern))
					return (0);
			}
			else if (*hname != *pattern)
				return (0);
			if (*pattern == '.')
				seen_dot = 1;
			hname++;
			pattern++;
			break;
		}
	}
}

/*
 * Initialize hash table. If the auth module has already been initialized, 
 * free all list entries first.
 */
void
auth_init_lists(void)
{
	struct passwd	*pw;
	int		i;
	uid_t		anon_uid;
	gid_t		anon_gid;

	if (initialized) {
		nfs_hash_ent	*hep, *next;

		auth_free_list(&known_clients);
		auth_free_list(&unknown_clients);
		auth_free_list(&wildcard_clients);
		auth_free_list(&netgroup_clients);
		auth_free_list(&anonymous_client);
		auth_free_list(&default_client);

		for (i = 0; i < IPHASHMAX; i++) {
			for (hep = hashtable[i]; hep != NULL; hep = next) {
				next = hep->next;
				free (hep);
			}
			hashtable[i] = NULL;
		}
	} else {
		for (i = 0; i < IPHASHMAX; i++) {
			hashtable[i] = NULL;
		}
	}

	/* Get the default anon uid/gid */
	if ((pw = getpwnam("nobody")) != NULL) {
		anon_uid = pw->pw_uid;
		anon_gid = pw->pw_gid;
	} else {
		anon_uid = (uid_t) -2;
		anon_gid = (gid_t) -2;
	}

	/* This protects us from stomping all over the place on installations
	 * that have given nobody a uid/gid of -1. This is quite bad for
	 * systems that don't have setfsuid, because seteuid(-1) is a no-op.
	 */
	if (anon_uid == (uid_t)-1) {
		Dprintf(L_ERROR,
			"Eek: user nobody has uid -1. Using -2 instead.\n");
		anon_uid = (uid_t) -2;
	}
	if (anon_gid == (gid_t)-1) {
		Dprintf(L_ERROR,
			"Eek: user nobody has gid -1. Using -2 instead.\n");
		anon_gid = (gid_t) -2;
	}

	default_options.nobody_uid = anon_uid;
	default_options.nobody_gid = anon_gid;
	anonymous_options.nobody_uid = anon_uid;
	anonymous_options.nobody_gid = anon_gid;

	memset(cached_clients, 0, sizeof(cached_clients));
	cached_next = 0;

	initialized = 1;
}

/*
 * Free all members on a list of nfs_clients.
 */
static void
auth_free_list(nfs_client **cpp)
{
	nfs_client	*cp, *nxt_clnt;
	nfs_mount	*mp, *nxt_mp;

	for (cp = *cpp; cp != NULL; cp = nxt_clnt) {
		nxt_clnt = cp->next;
		if (cp->clnt_name != NULL) {
			free (cp->clnt_name);
		}
		for (mp = cp->m; mp != NULL; mp = nxt_mp) {
			nxt_mp = mp->next;
			free (mp->path);
			if (mp->o.clnt_nisdomain)
				free(mp->o.clnt_nisdomain);
			free (mp);
		}
		if (cp->umap != NULL) {
			ugid_free_map(cp->umap);
		}
		free (cp);
	}
	*cpp = NULL;
}

