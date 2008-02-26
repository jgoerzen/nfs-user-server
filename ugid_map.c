/* UNFSD - copyright Mark A Shand, May 1988.
 * This software maybe be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 *
 * Redone from ground up by Olaf Kirch, April 1995.
 *
 * Rewritten again October 1997, Olaf Kirch <okir@monad.swb.de>.
 *
 * TODO: 
 *  -	time out uids/gids.
 *  -	Write protocol version 2 to allow bulk transfers and
 *	some more intelligent form of authentication.
 *
 *	Authors:
 *		Mark A. Shand
 *		Olaf Kirch, <okir@monad.swb.de>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <values.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include "nfsd.h"
#include "ugid.h"

#define UGID_CHUNK		256
#define UGID_CHUNK_BITS		8
#define UGID_CHUNK_BYTES	(UGID_CHUNK * sizeof(idmap_t *))
#define UGID_CHUNK0_BYTES	(UGID_CHUNK * sizeof(idmap_t))
#define UGID_EXPIRE		300		/* 5 minutes */

/*
 * Make sure we get the right size for ugid_t
 */
#if SIZEOF_UID_T != SIZEOF_GID_T
#error Sorry, this code relies on sizeof(uid_t) == sizeof(gid_t)
#endif

#define UGID_BITS		(SIZEOF_UID_T * BITSPERBYTE)
#define BITSTOLEVEL(b)		((UGID_BITS - (b)) / UGID_CHUNK_BITS - 1)
#define UGID_LOWER(id, b)	((id) & ~((1 << (b)) - 1))
#define UGID_UPPER(id, b)	(((id + (1 << (b))) & ~((1 << (b)) - 1))-1)

/*
 * Common type for uids/gids
 */
typedef uid_t			ugid_t;
typedef struct {
	ugid_t			id;
	time_t			expire;
} idmap_t;

/*
 * This struct holds the entire uid/gid mapping.
 * Note that we don't really keep the mapping in a huge consecutive
 * list, but rather in a multi-level array.
 * See ugid_get_entry for details.
 */
typedef struct ugid_map {
	idmap_t **		map[4];
} ugid_map;

/*
 * uid/gid map indices in ugid_map.
 * Don't change the numbering unless you know what you're doing.
 */
#define MAP_UID_R2L		0
#define MAP_UID_L2R		1
#define MAP_GID_R2L		2
#define MAP_GID_L2R		3
#define MAP_REVERSE(how)	((how) ^ 1)

/*
 * Check whether requested mapping flavor is dynamic
 */
#define MAP_DYNAMIC(map)	((map) == map_ugidd || (map) == map_nis)

/*
 * ugidd client handle cache (indexed by ugidd hostaddr).
 * 
 * MAXCACHE is the number of RPC client handles cached. 
 * EXPCACHE defines (in seconds) how long invalid client handles
 * are cached. Otherwise, crashed ugidd servers would hang nfsd
 * during each lookup - a condition from which it would hardly
 * recover, because the nfs client will keep retransmitting the
 * same request over and over while nfsd still waits for ugidd
 * to reply.
 */
#define MAXCACHE	32
#define EXPCACHE	(15 * 60)

#if defined(ENABLE_UGID_DAEMON) || defined(ENABLE_UGID_NIS)
typedef struct clnt_cache {
	struct in_addr	addr;		/* NFS client host addr. */
	time_t		age, lru;	/* create and access time */
	CLIENT		*clnt;		/* the client itself */
	unsigned long	prog, vers;	/* RPC prog/version */
} clnt_cache;
static clnt_cache	cache[MAXCACHE];
static int		initialized = 0;
#endif

/*
 * Prototypes and the like
 */
static ugid_map *	ugid_get_map(nfs_mount *mountp);
static idmap_t *	ugid_get_entry(idmap_t **, ugid_t, int);
static int		rlookup(nfs_mount *, struct svc_req *, int,
					ugid_t, idmap_t *);

/* Dynamic mapping support */
static int		ugidd_lookup(char *, ugid_t *, int, struct svc_req *);
static int		nis_lookup(nfs_mount *, char *, ugid_t *, int);
/*
#if defined(ENABLE_UGID_DAEMON) || defined(ENABLE_UGID_NIS)
static CLIENT *		ugid_get_client(SVCXPRT *xprt);
static void		ugid_kill_client(CLIENT *clnt);
#endif
 */

/*
 * Define a static mapping
 */
static inline void
ugid_map_static(idmap_t **map, ugid_t from, ugid_t to)
{
	idmap_t		*ent;

	ent = ugid_get_entry(map, from, 1);
	ent->id = to;
	ent->expire = 0;
}

/*
 * Define a dynamic mapping
 */
static inline void
ugid_map_dynamic(idmap_t **map, ugid_t from, ugid_t to)
{
	idmap_t		*ent;

	ent = ugid_get_entry(map, from, 1);
	ent->id = to;
	ent->expire = nfs_dispatch_time + UGID_EXPIRE;
}

/*
 * Find the corresponding id.
 */
static inline ugid_t
ugid_find(nfs_mount *mountp, struct svc_req *rqstp,
			int how, ugid_t id, ugid_t anonid)
{
	ugid_map	*umap;
	idmap_t		*ent;

	umap = ugid_get_map(mountp);

	if (mountp->o.uidmap == map_static) {
		ent = ugid_get_entry(umap->map[how], id, 0);
		if (ent == 0
		 || ent->id == AUTH_UID_NONE
		 || ent->id == AUTH_UID_NOBODY)
			return anonid;
		return ent->id;
	}

	if (mountp->o.uidmap == identity) {
		ent = ugid_get_entry(umap->map[how], id, 0);
		if (ent == 0 || ent->id == AUTH_UID_NONE)
			return id;
		if (ent->id == AUTH_UID_NOBODY)
			return anonid;
		return ent->id;
	}

	/* Dynamic mapping flavors */
	ent = ugid_get_entry(umap->map[how], id, 1);
	if (ent->id == AUTH_UID_NONE) {
		rlookup(mountp, rqstp, how, id, ent);
		if (ent->id == AUTH_UID_NONE) {
			ent->id = anonid;
		} else {
			/* Create a dynamic entry in the reverse map */
			ugid_map_dynamic(umap->map[MAP_REVERSE(how)],
					 ent->id, id);
		}
	}

	return ent->id;
}

/*
 * Map a server uid to a client uid
 */
uid_t
ruid(uid_t uid, nfs_mount *mountp, struct svc_req *rqstp)
{
	uid_t		retuid;

#ifdef DOSHACKS
	/* Reverse effects of all_squash for DOS clients */
	if (mountp->o.all_squash && uid == mountp->o.nobody_uid)
		return cred_uid;
#endif
	if (mountp->o.uidmap == identity)
		return uid;

	retuid = ugid_find(mountp, rqstp, MAP_UID_L2R, uid, AUTH_UID_NOBODY);

	Dprintf(D_UGID, "ruid(%s, %d) = %d\n",
			inet_ntoa(mountp->client->clnt_addr), uid, retuid);
	return retuid;
}

/*
 * Map a server gid to a client gid.
 */
gid_t
rgid(gid_t gid, nfs_mount *mountp, struct svc_req *rqstp)
{
	gid_t		retgid;

#ifdef DOSHACKS
	/* Reverse effects of all_squash for DOS clients */
	if (mountp->o.all_squash && gid == mountp->o.nobody_gid)
		return cred_gid;
#endif
	if (mountp->o.uidmap == identity)
		return gid;

	retgid = ugid_find(mountp, rqstp, MAP_GID_L2R, gid, AUTH_GID_NOBODY);

	Dprintf(D_UGID, "rgid(%s, %d) = %d\n",
			inet_ntoa(mountp->client->clnt_addr), gid, retgid);
	return retgid;
}

/*
 * Map a client uid to a server uid
 */
uid_t
luid(uid_t uid, nfs_mount *mountp, struct svc_req *rqstp)
{
	uid_t		retuid = uid;

	if (mountp->o.uidmap != identity || mountp->o.some_squash)
		retuid = ugid_find(mountp, rqstp, MAP_UID_R2L, uid,
				   mountp->o.nobody_uid);

	if ((retuid == 0 && mountp->o.root_squash) || mountp->o.all_squash)
		retuid = mountp->o.nobody_uid;

	Dprintf(D_UGID, "luid(%s, %d) = %d\n",
			inet_ntoa(mountp->client->clnt_addr), uid, retuid);
	return retuid;
}

/*
 * Map a client gid to a server gid
 */
gid_t
lgid(gid_t gid, nfs_mount *mountp, struct svc_req *rqstp)
{
	gid_t		retgid = gid;

	if (mountp->o.uidmap != identity || mountp->o.some_squash)
		retgid = ugid_find(mountp, rqstp, MAP_GID_R2L, gid,
				   mountp->o.nobody_gid);

	if ((gid == 0 && mountp->o.root_squash) || mountp->o.all_squash)
		retgid = mountp->o.nobody_gid;

	Dprintf(D_UGID, "lgid(%s, %d) = %d\n",
			inet_ntoa(mountp->client->clnt_addr), gid, retgid);
	return retgid;
}

/*
 * Squash a range of uids/gids.
 */
void
ugid_squash_uids(nfs_mount *mountp, uid_t lo, uid_t hi)
{
	ugid_map	*umap;

	Dprintf(D_UGID, "%s:%s squash uids %d-%d\n",
			mountp->client->clnt_name, mountp->path, lo, hi);
	umap = ugid_get_map(mountp);
	while (lo <= hi)
		ugid_map_static(umap->map[MAP_UID_R2L], lo++, AUTH_UID_NOBODY);
}

/*
 * Squash a range of gids
 */
void
ugid_squash_gids(nfs_mount *mountp, gid_t lo, gid_t hi)
{
	ugid_map	*umap;

	Dprintf(D_UGID, "%s:%s squash gids %d-%d\n",
			mountp->client->clnt_name, mountp->path, lo, hi);
	umap = ugid_get_map(mountp);
	while (lo <= hi)
		ugid_map_static(umap->map[MAP_GID_R2L], lo++, AUTH_GID_NOBODY);
}

/*
 * Define client to server mapping records for a given uid or gid.
 */
void
ugid_map_uid(nfs_mount *mountp, uid_t from, uid_t to)
{
	ugid_map	*umap;

	Dprintf(D_UGID, "%s:%s map uid rem %d <-> loc %d\n",
			mountp->client->clnt_name, mountp->path, from, to);
	umap = ugid_get_map(mountp);
	ugid_map_static(umap->map[MAP_UID_R2L], from, to);
	ugid_map_static(umap->map[MAP_UID_L2R], to, from);
}

void
ugid_map_gid(nfs_mount *mountp, gid_t from, gid_t to)
{
	ugid_map	*umap;

	Dprintf(D_UGID, "%s:%s map gid rem %d <-> loc %d\n",
			mountp->client->clnt_name, mountp->path, from, to);
	umap = ugid_get_map(mountp);
	ugid_map_static(umap->map[MAP_GID_R2L], from, to);
	ugid_map_static(umap->map[MAP_GID_L2R], to, from);
}

/*
 * Get the pointer to a uid/gid map entry.
 */
static idmap_t *
ugid_get_entry(idmap_t **map, ugid_t id, int create)
{
	unsigned int	i, offset, bits = UGID_BITS - UGID_CHUNK_BITS;
	idmap_t		*result, *chunk;

	Dprintf(D_UGID, "ugid_get_entry(%p, %d)\n", map, id);
	while (bits > UGID_CHUNK_BITS) {
		offset = (id >> bits) & (UGID_CHUNK - 1);
		if (map[offset] == 0) {
			if (!create)
				return 0;
			chunk = (idmap_t *) xmalloc(UGID_CHUNK_BYTES);
			memset(chunk, 0, UGID_CHUNK * sizeof(*map));
			map[offset] = chunk;

			Dprintf(D_UGID, "alloc ptr map %p @ level %d "
					"(id %u-%u)\n",
					chunk, BITSTOLEVEL(bits),
					UGID_LOWER(id, bits),
					UGID_UPPER(id, bits));
		}
		map   = (idmap_t **) map[offset];
		bits -= UGID_CHUNK_BITS;
	}

	offset = (id >> bits) & (UGID_CHUNK - 1);
	if (map[offset] == 0) {
		if (!create)
			return 0;
		chunk = (idmap_t *) xmalloc(UGID_CHUNK0_BYTES);
		Dprintf(D_UGID, "alloc id  map %p @ level %d "
				"(id %u-%u)\n",
				chunk, BITSTOLEVEL(bits),
				UGID_LOWER(id, bits),
				UGID_UPPER(id, bits));
		map[offset] = chunk;

		for (i = 0; i < UGID_CHUNK; i++, chunk++) {
			chunk->id     = AUTH_UID_NONE;
			chunk->expire = 0;	/* never */
		}
	}

	result = map[offset] + (id & (UGID_CHUNK - 1));
	if (result->expire && result->expire < nfs_dispatch_time)
		result->id = AUTH_UID_NONE;
	Dprintf(D_UGID, "\tresult = %p\n", map);
	return result;
}

/*
 * Get the map for a given mount point. If it hasn't been initialized yet,
 * create it.
 */
static ugid_map *
ugid_get_map(nfs_mount *mountp)
{
	nfs_client	*clientp = mountp->client;
	struct ugid_map	*umap;
	unsigned int	how;

	if (clientp->umap == NULL) {
		clientp->umap = umap = (ugid_map *) xmalloc(sizeof(ugid_map));
		memset(umap, 0, sizeof(ugid_map));

		for (how = 0; how < 4; how++) {
			umap->map[how] = (idmap_t **) xmalloc(UGID_CHUNK_BYTES);
			memset(umap->map[how], 0, UGID_CHUNK_BYTES);
		}
	}

	return clientp->umap;
}

static void
ugid_do_free_map(idmap_t **map, ugid_t id, unsigned int bits)
{
	unsigned int	i, isptrmap;
	unsigned int	subbits = bits - UGID_CHUNK_BITS;

	isptrmap = (bits > UGID_CHUNK_BITS);

#if 0
	Dprintf(D_UGID, "free  %s map %p @ level %d "
			"(id %d-%d)\n",
		isptrmap? "ptr" : "id ",
		map, BITSTOLEVEL(bits),
		UGID_LOWER(id, bits), UGID_UPPER(id, bits));
	if (isptrmap) {
		for (i = 0; i < UGID_CHUNK; i++) {
			if (map[i]) {
				ugid_do_free_map((idmap_t **) map[i],
						 id, subbits);
			}
			id += subbits;
		}
	}
	free(map);
#else
	isptrmap = (bits > UGID_CHUNK_BITS);
	for (i = 0; i < UGID_CHUNK; i++) {
		if (map[i]) {
			Dprintf(D_UGID, "free  %s map %p @ level %d "
					"(id %u-%u)\n",
				isptrmap? "ptr" : "id ",
				map[i], BITSTOLEVEL(bits),
				UGID_LOWER(id, bits), UGID_UPPER(id, bits));
			if (isptrmap) {
				ugid_do_free_map((idmap_t **) map[i],
						 id, subbits);
			}
			free(map[i]);
			map[i] = 0;
		}
		id += (1 << bits);
	}
#endif
}

/*
 * Deallocate a uid map.
 */
void
ugid_free_map(ugid_map *umap)
{
	unsigned int	how;

	/* invalidate cache of ugidd/NIS clients */
#if defined(ENABLE_UGID_DAEMON) || defined(ENABLE_UGID_NIS)
	if (initialized) {
		int	i;

		for (i = 0; i < MAXCACHE; i++) {
			if (cache[i].clnt != NULL)
				clnt_destroy(cache[i].clnt);
			cache[i].addr.s_addr = INADDR_ANY;
			cache[i].clnt = NULL;
		}
		initialized = 0;
	}
#endif

	/* Free idmap's associated with map */
	for (how = 0; how < 4; how++) {
		idmap_t	**map;


		map = (idmap_t **) umap->map[how];
		ugid_do_free_map(map, 0, UGID_BITS - UGID_CHUNK_BITS);
		/* free(map); */
		umap->map[how] = NULL;
	}

	/* Free the map itself. */
	free(umap);
}

/*
 * The following deals with dynamic ui/gid mapping via ugidd or NIS.
 * It is only compiled in when uigdd or NIS support is requested explicitly. 
 */
#if defined(ENABLE_UGID_DAEMON) || defined(ENABLE_UGID_NIS)
/* 
 * Obtain an RPC client handle for a given client host. We cache these
 * handles on a limited scale.
 */
static CLIENT *
ugid_get_client(SVCXPRT *xprt, unsigned int prog, unsigned int vers,
			     const char *name)
{
	struct sockaddr_in	addr;
	struct timeval		wait;
	CLIENT			*clnt;
	time_t			now, age;
	int			i, empty, oldest;
	int			sock;

	if (!initialized) {
		for (i = 0; i < MAXCACHE; i++) {
			cache[i].addr.s_addr = INADDR_ANY;
			cache[i].clnt = NULL;
		}
		initialized = 1;
	}

	/* Get current time */
	now = age = nfs_dispatch_time;

	/* Check if the client is already cached */
	addr = *svc_getcaller(xprt);
	empty = oldest = -1;
	for (i = 0; i < MAXCACHE; i++) {
		if (cache[i].addr.s_addr == addr.sin_addr.s_addr
		 && cache[i].prog == prog
		 && cache[i].vers == vers)
			break;
		if (cache[i].clnt == NULL) {
			empty = i;
		} else if (cache[i].lru < age) {
			age = cache[i].lru;
			oldest = i;
		}
	}

	/* If the address was in the cache but the client was invalid,
	 * check if we should reattempt to obtain the handle
	 */
	if (i < MAXCACHE) {
		if ((clnt = cache[i].clnt) == NULL) {
			if (now - cache[i].age <= EXPCACHE) {
				Dprintf(D_UGID,
					"ugid: found invalid client %s\n",
					inet_ntoa(cache[i].addr));
				return NULL;
			}
			Dprintf(D_UGID, "ugid: found expired client %s\n",
				inet_ntoa(cache[i].addr));
			empty = i; i = MAXCACHE;	/* force lookup */
		} else {
			cache[i].lru = now;
			return clnt;
		}
	}

	/* If not found and there's no empty slot, free the oldest */
	if (i >= MAXCACHE && empty == -1) {
		Dprintf(D_UGID, "ugid: deleting oldest client %s slot %d\n",
			inet_ntoa(cache[oldest].addr), oldest);
		clnt_destroy(cache[oldest].clnt);
		cache[oldest].clnt = NULL; 
		empty = oldest;
	}

	/* Client is not in cache. Create it. */
	Dprintf(D_UGID, "ugid: create client %s slot %d\n",
		inet_ntoa(addr.sin_addr), empty);
	cache[empty].clnt = NULL;
	cache[empty].addr = addr.sin_addr;
	cache[empty].prog = prog;
	cache[empty].vers = vers;
	cache[empty].age  = now;
	cache[empty].lru  = now;

	addr.sin_port = 0;
	wait.tv_sec   = 10;
	wait.tv_usec  = 0;
	sock = RPC_ANYSOCK;

	clnt = clntudp_create(&addr, prog, vers, wait, &sock);
	if (clnt == NULL) {
		Dprintf(L_ERROR, "can't connect to %s on %s.\n", 
				name, inet_ntoa(addr.sin_addr));
		cache[empty].clnt = NULL;
		return NULL;
	}

	/* I'm not sure if we can count on addr.sin_port to contain
	 * the server's port after clntudp_create, so we fetch it
	 * explicitly.
	 */
	clnt_control(clnt, CLGET_SERVER_ADDR, (caddr_t) &addr);
	if (!SECURE_PORT(addr.sin_port)) {
		Dprintf(L_ERROR, "%s on %s runs on unprivileged port.\n",
				name, inet_ntoa(addr.sin_addr));
		clnt_destroy(clnt);
		cache[empty].clnt = NULL;
		return NULL;
	}

	cache[empty].clnt = clnt;
	return clnt;
}

static void
ugid_kill_client(CLIENT *clnt)
{
	int		i;

	for (i = 0; i < MAXCACHE; i++) {
		if (cache[i].clnt == clnt) 
			break;
	}
	if (i < MAXCACHE) {
		Dprintf(L_ERROR,
			"Call to ugidd on %s failed. Blocked for %d seconds.",
			inet_ntoa(cache[i].addr), EXPCACHE);
		clnt_destroy(clnt);
		cache[i].clnt = NULL;
		cache[i].age = cache[i].lru;
	}
}
#endif /* defined(ENABLE_UGID_DAEMON) || defined(ENABLE_UGID_NIS) */


/*
 * Lookup a given uid or gid by calling the client's ugidd.
 *
 * This incarnation of ugidd_lookup doesn't use the authenticate call
 * anymore. This authentication required the ugidd server to open
 * a priviled port and send an integer. This can be accomplished
 * much more efficiently by requiring the server to run on a privileged
 * port in the first place.
 */
#ifdef ENABLE_UGID_DAEMON
static int
ugidd_lookup(char *nam, ugid_t *id, int map, struct svc_req *rqstp)
{
	SVCXPRT		*xprt = rqstp->rq_xprt;
	CLIENT		*clnt;
	int		*pi;
	char		**sp;
	int		arg, ret = 0, retry = 0;

	if (!(clnt = ugid_get_client(xprt, UGIDPROG, UGIDVERS, "ugidd")))
		return 0;

	do {
		switch (map) {
		case NAME_UID:
			pi = name_uid_1(&nam, clnt);
			if ((ret = (pi != NULL)))
				*id = *pi;
			Dprintf(D_UGID, "ugidd_lookup(NAME_UID, %s) %s\n",
					 nam, (pi != NULL)? "OK" : "FAIL");
			break;
		case GROUP_GID:
			pi = group_gid_1(&nam, clnt);
			if ((ret = (pi != NULL)))
				*id = *pi;
			Dprintf(D_UGID, "ugidd_lookup(GROUP_GID, %s) %s\n",
					 nam, (pi != NULL)? "OK" : "FAIL");
			break;
		case UID_NAME:
			arg = (int) *id;
			sp = uid_name_1(&arg, clnt);
			if ((ret = (sp != NULL))) {
				strncpy(nam, *sp, MAXUGLEN);
				nam[MAXUGLEN-1] = '\0';
			}
			Dprintf(D_UGID, "ugidd_lookup(UID_NAME, %d) %s\n",
					*id, (sp != NULL)? "OK" : "FAIL");
			break;
		case GID_GROUP:
			arg = (int) *id;
			sp = gid_group_1(&arg, clnt);
			if ((ret = (sp != NULL))) {
				strncpy(nam, *sp, MAXUGLEN);
				nam[MAXUGLEN-1] = '\0';
			}
			Dprintf(D_UGID, "ugidd_lookup(GID_GROUP, %d) %s\n",
					*id, (sp != NULL)? "OK" : "FAIL");
			break;
		default:
			return 0;
		}

		/* RPC error - check the status. When encountering errors that
		 * are likely to persist, we clear the client to make sure 
		 * no more lookups are attempted within the next EXPCACHE 
		 * seconds.
		 */
		if (!ret) {
			struct rpc_err	err;

			Dprintf(D_UGID, "ugidd call error: %s\n",
				clnt_sperror(clnt, ""));

			clnt_geterr(clnt, &err);
			switch (err.re_status) {
			case RPC_CANTSEND:	/* Maybe network failures */
			case RPC_CANTRECV:	/* should be transient */
			case RPC_TIMEDOUT:	/* This is the worst one */
			case RPC_VERSMISMATCH:	/* Cases of general bogosity */
			case RPC_AUTHERROR:
			case RPC_PROGVERSMISMATCH:
			case RPC_PROCUNAVAIL:
				Dprintf(D_UGID, "deleting client %lx\n", clnt);
				ugid_kill_client(clnt);
				break;
			case RPC_CANTDECODEARGS:/* retry operation */
			case RPC_CANTDECODERES:
				Dprintf(D_UGID, "retrying operation (%d)\n",
							retry);
				retry++;
				break;
			default:
				break;
			}
		}
	} while (retry && retry < 3);

	return ret;
}
#else /* !ENABLE_UGID_DAEMON */
/*
 * Lookup a given uid or gid by calling the client's ugidd.
 * This is a dummy function used when ugidd support is not compiled
 * in.
 */
static int
ugidd_lookup(char *nam, ugid_t *id, int map, struct svc_req *rqstp)
{
	*id = AUTH_UID_NONE;
	return 1;
}
#endif /* ENABLE_UGID_DAEMON */

/*
 * Support lookup of remote uid/gid via client's NIS server
 */
#ifdef ENABLE_UGID_NIS
#include <rpcsvc/ypclnt.h>

static int
nis_lookup(nfs_mount *mountp, char *name, ugid_t *id, int map)
{
	char	*domain = mountp->o.clnt_nisdomain;
	char	value[64], *result, *sp;
	int	err, reslen;

	if (map == NAME_UID || map == GROUP_GID) {
		err = yp_match(domain,
			(map == NAME_UID)? "passwd.byname" : "group.byname",
			name, strlen(name), &result, &reslen);
		Dprintf(D_UGID, "nis_lookup(%s) %s\n", name,
					err? yperr_string(err) : "OK");
		if (err != 0)
			goto error;
		/* Skip name and password */
		if (!(result = strchr(result, ':'))
		 || !(result = strchr(result + 1, ':')))
			return 0;
		*id = strtoul(result + 1, 0, 10);
	} else {
		sprintf(value, "%u", *id);
		err = yp_match(domain,
			(map == UID_NAME)? "passwd.byuid" : "group.bygid",
			value, strlen(value), &result, &reslen);
		Dprintf(D_UGID, "nis_lookup(%s) %s\n", value,
					err? yperr_string(err) : "OK");
		if (err != 0)
			goto error;
		if (!(sp = strchr(result, ':')))
			return 0;
		*sp = 0;
		strncpy(name, result, MAXUGLEN-1);
		name[MAXUGLEN-1] = '\0';
	}

	return 1;

error:
	/* Do something useful */
	return 0;
}
#else /* ! ENABLE_UGID_NIS */
static int
nis_lookup(nfs_mount *mountp, char *name, ugid_t *id, int map)
{
	*id = AUTH_UID_NONE;
	return 1;
}
#endif /* ENABLE_UGID_NIS */

static int
rlookup(nfs_mount *mountp, struct svc_req *rqstp,
				int how, ugid_t loc, idmap_t *rem)
{
	if (mountp->o.uidmap != map_daemon
	 && mountp->o.uidmap != map_nis)
		return 1;

	rem->id     = AUTH_UID_NONE;
	rem->expire = nfs_dispatch_time + UGID_EXPIRE;

	if (how == MAP_UID_L2R) {
		struct passwd	*pw;

		if ((pw = getpwuid(loc)) == 0)
			return 0;

		if (mountp->o.uidmap == map_daemon)
			ugidd_lookup(pw->pw_name, &rem->id, NAME_UID, rqstp);
		else if (mountp->o.uidmap == map_nis)
			nis_lookup(mountp, pw->pw_name, &rem->id, NAME_UID);
	} else if (how == MAP_GID_L2R) {
		struct group	*gr;

		if ((gr = getgrgid(loc)) == 0)
			return 0;
		if (mountp->o.uidmap == map_daemon)
			ugidd_lookup(gr->gr_name, &rem->id, GROUP_GID, rqstp);
		else if (mountp->o.uidmap == map_nis)
			nis_lookup(mountp, gr->gr_name, &rem->id, GROUP_GID);
	} else if (how == MAP_UID_R2L) {
		struct passwd	*pw;
		char		namebuf[MAXUGLEN];

		if (mountp->o.uidmap == map_daemon) {
			if (!ugidd_lookup(namebuf, &loc, UID_NAME, rqstp))
				return 0;
		} else if (mountp->o.uidmap == map_nis) {
			if (!nis_lookup(mountp, namebuf, &loc, UID_NAME))
				return 0;
		}
		if ((pw = getpwnam(namebuf)) != NULL)
			rem->id = pw->pw_uid;
	} else if (how == MAP_GID_R2L) {
		struct group	*gr;
		char		namebuf[MAXUGLEN]; 

		if (mountp->o.uidmap == map_daemon) {
			if (!ugidd_lookup(namebuf, &loc, GID_GROUP, rqstp))
				return 0;
		} else if (mountp->o.uidmap == map_nis) {
			if (!nis_lookup(mountp, namebuf, &loc, GID_GROUP))
				return 0;
		}
		if ((gr = getgrnam(namebuf)) != NULL)
			rem->id = gr->gr_gid;
	} else {
		return 0;
	}

	return 1;
}
