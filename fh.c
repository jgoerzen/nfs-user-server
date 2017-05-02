/*
 * fh		This module handles the file-handle cache.
 *		FILE HANDLE PACKAGE FOR USER-LEVEL NFS SERVER
 *
 *		Interfaces:
 *		    pseudo_inode
 *			mostly used internally, but also called from unfsd.c
 *			when reporting directory contents.
 *		    fh_init
 *			Initializes the queues and 'flush' timer
 *		    fh_pr
 *			debugging primitive; converts file handle into a
 *			printable text string
 *		    fh_create
 *			establishes initial file handle; called from mount
 *			daemon
 *		    fh_path
 *			returns unix path corresponding to fh
 *		    fh_fd
 *			returns open file descriptor for given file handle;
 *			provides caching of open files
 *		    fd_idle
 *			provides mututal exclusion of normal file descriptor
 *			cache use, and alarm-driven cache flushing
 *		    fh_compose
 *			construct new file handle from existing file handle
 *			and directory entry
 *		    fh_psi
 *			returns pseudo_inode corresponding to file handle
 *		    fh_remove (new, by Don Becker)
 *			delete the file handle associated with PATH from the
 *			cache
 *
 * Authors:	Mark A. Shand, May 1988
 *		Donald J. Becker <becker@super.org>
 *		Rick Sladkey <jrs@world.std.com>
 *		Patrick	Sweeney <pjs@raster.Kodak.COM>
 *		Orest Zborowski <obz@raster.Kodak.COM>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 *
 * Note: the original code mistakenly assumes that the overall path
 *	length remains within the value given by PATH_MAX... that leads
 *	to interesting buffer overflows all over the place.
 */

#include <assert.h>
#include "nfsd.h"
#include "rpcmisc.h"
#include "signals.h"

#define FHTRACE

/*
 * The following hash computes the exclusive or of all bytes of
 * the pseudo-inode. This gives a reasonable distribution in most
 * cases except for disks that were filled by restoring a backup,
 * or copying another disk. The reason for this seems to be the
 * allocation pattern used by ext2fs in allocating directories on
 * pristine disks (initially, each directory gets an inode group of
 * its own until we run out of groups).
 */
#define hash_xor8(n)	(((n) ^ ((n)>>8) ^ ((n)>>16) ^ ((n)>>24)) & 0xff)

/*
 * An alternative hash would be to select just the low 8bits, but
 * this just seems to reverse the odds (good on freshly restored disks,
 * bad on others).
 *
 * The following achieved reasonable distribution on all disks I tried
 * it on:
 */
#define hash_skew(n)    (((n) + 3 * ((n) >> 8) + 5 * ((n) >> 16)) & 0xff)

/* If you wish to experiment with different algorithms, try the fh-dist
 * program included.
 *
 * For now, we'll continue to use the old xor8 algorithm
 */
#define hash_psi(psi)		hash_xor8(psi)

static mutex			ex_state = inactive;
static mutex			io_state = inactive;

#define HASH_TAB_SIZE		256
static fhcache			fh_head, fh_tail;
static fhcache *		fh_hashed[HASH_TAB_SIZE];
static fhcache *		fd_lru_head = NULL;
static fhcache *		fd_lru_tail = NULL;
static int			fh_list_size;
static time_t			curtime;

#ifndef FOPEN_MAX
#define FOPEN_MAX		256
#endif

#ifndef FHTRACE
#undef	D_FHTRACE
#define D_FHTRACE		D_FHCACHE
#endif

static fhcache *		fd_cache[FOPEN_MAX] = { NULL };
static int			fd_cache_size = 0;

#ifndef NFSERR_INVAL			/* that Sun forgot */
#define NFSERR_INVAL	22
#endif

struct {
	enum nfsstat		error;
	int			nfs_errno;
} nfs_errtbl[]= {
	{ NFS_OK,		0		},
	{ NFSERR_PERM,		EPERM		},
	{ NFSERR_NOENT,		ENOENT		},
	{ NFSERR_IO,		EIO		},
	{ NFSERR_NXIO,		ENXIO		},
	{ NFSERR_ACCES,		EACCES		},
	{ NFSERR_EXIST,		EEXIST		},
	{ NFSERR_NODEV,		ENODEV		},
	{ NFSERR_NOTDIR,	ENOTDIR		},
	{ NFSERR_ISDIR,		EISDIR		},
	{ NFSERR_INVAL,		EINVAL		},
	{ NFSERR_FBIG,		EFBIG		},
	{ NFSERR_NOSPC,		ENOSPC		},
	{ NFSERR_ROFS,		EROFS		},
	{ NFSERR_NAMETOOLONG,	ENAMETOOLONG	},
	{ NFSERR_NOTEMPTY,	ENOTEMPTY	},
#ifdef EDQUOT
	{ NFSERR_DQUOT,		EDQUOT		},
#endif
	{ NFSERR_STALE,		ESTALE		},
	{ NFSERR_WFLUSH,	EIO		},
	{ -1,			EIO		}
};

/* Forward declared local functions */
static psi_t	path_psi(char *, nfsstat *, struct stat *, int);
static int	fh_flush_fds(void);
static char *	fh_dump(svc_fh *);
static void	fh_insert_fdcache(fhcache *fhc);
static void	fh_unlink_fdcache(fhcache *fhc);

static void
fh_move_to_front(fhcache *fhc)
{
	/* Remove from current posn */
	fhc->prev->next = fhc->next;
	fhc->next->prev = fhc->prev;

	/* Insert at head */
	fhc->prev = &fh_head;
	fhc->next = fh_head.next;
	fhc->prev->next = fhc;
	fhc->next->prev = fhc;
}

static void
fh_inserthead(fhcache *fhc)
{
	register fhcache **hash_slot;

	/* Insert at head. */
	fhc->prev = &fh_head;
	fhc->next = fh_head.next;
	fhc->prev->next = fhc;
	fhc->next->prev = fhc;
	fh_list_size++;

	/* Insert into hash tab. */
	hash_slot = &(fh_hashed[fhc->h.psi % HASH_TAB_SIZE]);
	fhc->hash_next = *hash_slot;
	*hash_slot = fhc;
}

static fhcache *
fh_lookup(psi_t psi)
{
	register fhcache *fhc;

	fhc = fh_hashed[psi % HASH_TAB_SIZE];
	while (fhc != NULL && fhc->h.psi != psi)
		fhc = fhc->hash_next;
	return (fhc);
}

static void
fh_insert_fdcache(fhcache *fhc)
{
	if (fhc == fd_lru_head)
		return;
	if (fhc->fd_next || fhc->fd_prev)
		fh_unlink_fdcache(fhc);
	if (fd_lru_head)
		fd_lru_head->fd_prev = fhc;
	else
		fd_lru_tail = fhc;
	fhc->fd_next = fd_lru_head;
	fd_lru_head = fhc;

#ifdef FHTRACE
	if (fd_cache[fhc->fd] != NULL) {
		Dprintf(L_ERROR, "fd cache inconsistency!\n");
		return;
	}
#endif
	fd_cache[fhc->fd] = fhc;
	fd_cache_size++;
}

static void
fh_unlink_fdcache(fhcache *fhc)
{
	fhcache	*prev = fhc->fd_prev,
		*next = fhc->fd_next;

	fhc->fd_next = fhc->fd_prev = NULL;
	if (next) {
		next->fd_prev = prev;
	} else if (fd_lru_tail == fhc) {
		fd_lru_tail = prev;
	} else {
		Dprintf(L_ERROR, "fd cache inconsistency\n");
		return;
	}
	if (prev) {
		prev->fd_next = next;
	} else if (fd_lru_head == fhc) {
		fd_lru_head = next;
	} else {
		Dprintf(L_ERROR, "fd cache inconsistency\n");
		return;
	}

#ifdef FHTRACE
	if (fd_cache[fhc->fd] != fhc) {
		Dprintf(L_ERROR, "fd cache inconsistency!\n");
		return;
	}
#endif
	fd_cache[fhc->fd] = NULL;
	fd_cache_size--;
}

static void
fh_close(fhcache *fhc)
{
	if (fhc->fd >= 0) {
		Dprintf(D_FHCACHE,
			"fh_close: closing handle %x ('%s', fd=%d)\n",
			fhc, fhc->path ? fhc->path : "<unnamed>", fhc->fd);
		fh_unlink_fdcache(fhc);
		efs_close(fhc->fd);
		fhc->fd = -1;
	}
}

static void
fh_delete(fhcache *fhc)
{
	register fhcache **hash_slot;

#ifdef FHTRACE
	if (fhc->h.hash_path[0] == (unsigned char)-1)
		return;
#endif

	Dprintf(D_FHTRACE|D_FHCACHE,
		"fh_delete: deleting handle %x ('%s', fd=%d)\n",
		fhc, fhc->path ? fhc->path : "<unnamed>", fhc->fd);

	/* Remove from current posn */
	fhc->prev->next = fhc->next;
	fhc->next->prev = fhc->prev;
	fh_list_size--;

	/* Remove from hash tab */
	hash_slot = &(fh_hashed[fhc->h.psi % HASH_TAB_SIZE]);
	while (*hash_slot != NULL && *hash_slot != fhc)
		hash_slot = &((*hash_slot)->hash_next);
	if (*hash_slot == NULL)
		Dprintf(L_ERROR,
			"internal inconsistency -- fhc(%x) not in hash table\n",
			fhc);
	else
		*hash_slot = fhc->hash_next;

	fh_close(fhc);

	/* Free storage. */
	if (fhc->path != NULL)
		free(fhc->path);

#ifdef FHTRACE
	/* Safeguard against cache corruption */
	fhc->path = NULL;
	fhc->h.hash_path[0] = -1;
#endif

	free(fhc);
}

/* Lookup a UNIX error code and return NFS equivalent. */
enum nfsstat
nfs_errno(void)
{
	int i;

	for (i = 0; nfs_errtbl[i].error != -1; i++) {
		if (nfs_errtbl[i].nfs_errno == errno)
			return (nfs_errtbl[i].error);
	}
	Dprintf(L_ERROR, "non-standard errno: %d (%s)\n",
		errno, strerror(errno));
	return (NFSERR_IO);
}

/*
 * INODES and DEVICES.  NFS assumes that each file within an NFS mounted
 * file-system has a unique inode number.  Thus to mount an entire file
 * hierarchy, as this server sets out to do, requires mapping from inode/devs
 * to pseudo-inode.  Furthermore mount points must be detected and so that
 *	pseudo-inode("name") == pseudo-inode(direntry("name/../name"))
 * One option is to force the directory entry inode to correspond to the
 * result of the stat call, but this involves stat'ing every directory entry
 * during a readdir.  Instead we force the stat call to correspond to the
 * directory entry inode (see inner_getattr).  Of course this technique
 * requires that the parent directory is readable.  If it is not the normal
 * stat call result is used.  There is no chance of conflict because the
 * directory can never be read.
 *
 * In theory unique pseudo-inodes cannot be guaranteed, since inode/dev
 * contains 48 bits of information which must be crammed into an inode
 * number constrained to 32 bits.  Fortunately inodes numbers tend to be
 * small (often < 64k, almost always < 512k)
 *
 * On the Alpha, dev_t is 32bit. Fold the device number before hashing it.
 *
 * Implemented new scheme using a static table mapping device numbers to
 * index numbers, see devtab.c. 30 Oct 1998, --okir
 */
psi_t
pseudo_inode(ino_t inode, dev_t dev)
{
#ifndef ENABLE_DEVTAB
	psi_t		dmajor, dminor;

#if SIZEOF_DEV_T == 4
	/* This folds the upper 16 bits into bits 8..15, and
	 * the lower 16 bits into bits 0..7
	 */
	dev = (((dev >> 16) & 0xff00) ^ ((dev >> 8) & 0xff00)) | 
	      (((dev >> 8) & 0xff) ^ (dev & 0xff));
#endif

	/*
         * Assuming major and minor numbers are small integers,
         * gravitate bits of dmajor & dminor device number to
         * high-order bits of word, to avoid clash with real inode num.
	 *
	 * First, we reverse the two bytes:
	 *	out:15		dev:8	(i.e. lowest bit of major number)
	 *	out:14		dev:9
	 *	out:13		dev:10
	 *	..
	 *	out:8		dev:15	(i.e. lowest bit of minor number)
	 *	out:7		dev:0
	 *	out:6		dev:1
	 *	..
	 *	out:1		dev:6
	 *	out:0		dev:7
         */
	dmajor = ((dev & 0xf0f) << 4) | ((dev & 0xf0f0) >> 4);
	dmajor = ((dmajor & 0x3333) << 2) | ((dmajor & 0xcccc) >> 2);
	dmajor = ((dmajor & 0x5555) << 1) | ((dmajor & 0xaaaa) >> 1);

	/* Next, we spread the 16bits across 32 bits, with 0's in
	 * uneven positions (the original comment said even position,
	 * but that's obviously wrong).
	 *
	 * I.e. when we're done, we get
	 *	out:30		dev:8
	 *	out:28		dev:9
	 *	out:26		dev:10
	 *	...
	 *	out:16		dev:15
	 *	out:14		dev:0
	 *	out:12		dev:1
	 *	...
	 *	out:2		dev:6
	 *	out:0		dev:7
	 *
	 * This makes sure the `important' bits of each nibble (i.e.
	 * of major and minor number) are in the high bits of each 16bit
	 * word, and the less important ones in the low bits.
	 */
	dmajor = ((dmajor & 0xff00) << 8) | (dmajor & 0xff);
	dmajor = ((dmajor & 0xf000f0) << 4) | (dmajor & 0xf000f);
	dmajor = ((dmajor & 0xc0c0c0c) << 2) | (dmajor & 0x3030303);
	dmajor = ((dmajor & 0x22222222) << 1) | (dmajor & 0x11111111);

	/* Now we fold the result into 16 bits.
	 * Below's the original code, which results in the following
	 * permutation:
	 *	out:31		zero
	 *	out:30		dev:8
	 *	out:29		dev:0
	 *	out:28		dev:9
	 *	out:27		dev:1
	 *	out:26		dev:10
	 *	out:25		dev:2
	 *	...
	 *	out:16		dev:15
	 *	out:15		dev:7
	 *	(remainder is 0)
	 *
	 * The final PSI is computed by taking the XOR of this prefix,
	 * and the original inode number.
	 *
	 * Assuming SCSI disks, this produces the following prefixes
	 *  sda1	0x801	-> 	0x21000000	(24 bit inode)
	 *  sdb1	0x811	-> 	0x21200000	(21 bit inode)
	 *  sdc1	0x821	-> 	0x21080000	(18 bit inode)
	 *  sdd1	0x831	->	0x21280000	(18 bit inode)
	 *  sde1	0x841	->	0x21020000	(16 bit inode)
	 *
	 * Given that mke2fs allocates one inode for every 4K of disk
	 * by default, a 4G partition will have 1M inodes by default, i.e.
	 * up to 20bit inode numbers. Note that if you have two partitions,
	 * the inode number limit is the minimum of each disk's inode number
	 * limit. E.g. you can hook up an 8GB partition (21bit inums)
	 * on /dev/sda1, and a 2GB partition (19bit inums) on /dev/sdc1.
	 * Exporting just one of them works fine. Exporting both at the
	 * same time produces psi clashes, e.g.
	 *
	 * 0x21000002	== 0x21000000 ^ 0x80002 == inode 0x80002 on /dev/sda1
	 * 		== 0x21280000 ^ 0x00002 == inode 2 on /dev/sdc1
	 *
	 * IDE disks are even worse in that they dole out 64 minor numbers
	 * per disk. This means that /dev/hdb reaches the limit at
	 * 17 bit inode numbers (that's a 512M partition, using the
	 * default mke2fs inode/block ratio).
	 *
	 * A marginally better solution is given below, which
	 * left-shifts the minor number bits so that bit31 is used:
	 *	out:31		dev:0
	 *	out:30		dev:8
	 *	out:29		dev:1
	 *	...
	 * This will give you two extra bits for the inode on any device.
	 * Still, an 8G partition on /dev/sdc or more than 2G on /dev/hdb
	 * will give you heartache.
	 *
	 * NB: don't let the 0x5555 and 0x55550000 bitmasks confuse you;
	 * one could also use 0xffff and 0xffff0000 because the other
	 * bits are zero.
	 */
#ifndef MARGINALLY_IMPOROVED_VERSION
	dminor = (dmajor & 0x5555) << 15;
	dmajor = dmajor & 0x55550000;
#else
	dminor = (dmajor & 0x5555) << 17;
	dmajor = dmajor & 0x55550000;
#endif

	/*
	Dprintf(D_FHCACHE,
		"pseudo_inode: dev=0x%x, inode=%d, psi=0x%08x\n",
		(dmajor | dminor) ^ inode);
	*/
	return ((dmajor | dminor) ^ inode);
#else
	static dev_t		last_dev;
	static psi_t		prefix;
	static unsigned long	mask = 0;
	unsigned int		index;

	/* index numbers for devtab entries are mapped like this
	 *
	 *	prefix	index & 7	inode
	 * 0:	0	000		... 28 bits ...
	 * 1:   0	001
	 * 2:   0	010
	 * ...		...
	 * 7:	0	111
	 * 8:   10	000		... 27 bits ...
	 * 9:   10	001
	 * ...		...
	 * 16:  110	000		... 26 bits ...
	 * 17:  110	001
	 * ...		...
	 */
	/* fast path */
	if (last_dev == dev && (inode & ~mask) == 0)
		return (psi_t) (prefix | inode);

	/* slow path */
	last_dev = dev;
	index  = devtab_index(dev);
	prefix = ((index & 7) << 28);
	mask   = (1 << 28) - 1;
	while (index > 7) {
		prefix = (prefix >> 1) | 0x80000000;
		mask >>= 1;
		index -= 8;
	}

	/* If we have an XXL inode number, spew out warning (but at most
	 * once a second) */
	if (inode & ~mask) {
		static time_t	warned = 0;
		time_t		now;

		if ((now = time(NULL)) != warned) {
			Dprintf(L_WARNING,
				"inode number for device 0x%x too big!", dev);
			warned = now;
		}
		inode &= mask;
	}

	return (psi_t) (prefix | inode);
#endif
}

#if 1
static char *
fh_buildpath(svc_fh *h)
{
	char		pathbuf[PATH_MAX + NAME_MAX + 1], *path;
	long		cookie_stack[HP_LEN + 1];
	char		*slash_stack[HP_LEN];
	struct stat	sbuf;
	psi_t		psi;
	int		i, pathlen;

	if (h->hash_path[0] >= HP_LEN) {
		Dprintf(L_ERROR, "impossible hash_path[0] value: %s\n", 
					fh_dump(h));
		return NULL;
	}

	if (efs_stat("/", &sbuf) < 0)
		return (NULL);
	psi = pseudo_inode(sbuf.st_ino, sbuf.st_dev);
	if (h->hash_path[0] == 0) {
		if (psi != h->psi)
			return (NULL);
		return xstrdup("/");
	}

	if (hash_psi(psi) != h->hash_path[1])
		return (NULL);

	auth_override_uid(ROOT_UID);	/* for x-only dirs */
	strcpy(pathbuf, "/");
	cookie_stack[2] = 0;
	for (i = 2; i <= h->hash_path[0] + 1; i++) {
		DIR *dir;
		struct dirent *dp;

	backtrack:
		if (efs_stat(pathbuf, &sbuf) >= 0
		 && (dir = efs_opendir(pathbuf)) != NULL) {
			pathlen = strlen(pathbuf);
			if (cookie_stack[i] != 0)
				efs_seekdir(dir, cookie_stack[i]);
			while ((dp = efs_readdir(dir))) {
				char	*name = dp->d_name;
				int	n = strlen(name);

				if (pathlen + n + 1 >= NFS_MAXPATHLEN
				 || (name[0] == '.'
				  && (n == 1 || (n == 2 && name[1] == '.'))))
					continue;

				psi = pseudo_inode(dp->d_ino, sbuf.st_dev);
				if (i == h->hash_path[0] + 1) {
					if (psi != h->psi)
						continue;
					/* GOT IT */
					strcpy(pathbuf + pathlen, dp->d_name);
					path = xstrdup(pathbuf);
					efs_closedir(dir);
					auth_override_uid(auth_uid);
					return (path);
				} else {
					if (hash_psi(psi) != h->hash_path[i])
						continue;

					/* PERHAPS WE'VE GOT IT */
					cookie_stack[i] = efs_telldir(dir);
					cookie_stack[i + 1] = 0;
					slash_stack[i] = pathbuf + pathlen;
					strcpy(slash_stack[i], dp->d_name);
					strcat(pathbuf, "/");

					efs_closedir(dir);
					goto deeper;
				}
			}
			/* dp == NULL */
			efs_closedir(dir);
		}
		/* shallower */
		i--;
		if (i < 2) {
			auth_override_uid(auth_uid);
			return (NULL);	/* SEARCH EXHAUSTED */
		}

		/* Prune path */
		*(slash_stack[i]) = '\0';
		goto backtrack;
	deeper:
		;
	}
	auth_override_uid(auth_uid);
	return (NULL);		/* actually not reached */
}

#else
/* This code is somewhat more readable (and safer) but doesn't work yet */
static int fh_buildcomp(h, dev, dir, i, path)
svc_fh *h;
dev_t dev;
DIR *dir;
int i;
char *path;
{
	struct dirent *	dp;
	psi_t		psi;
	int		len;

	while ((dp = efs_readdir(dir))) {
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		psi = pseudo_inode(dp->d_ino, dev);
		if (i == h->hash_path[0] + 1) {
			if (psi != h->psi)
				continue;

			/*GOT IT*/
			len = strlen(path);
			if (len + strlen(dp->d_name) >= PATH_MAX + NAME_MAX)
				continue; /* shucks */

			strcat(path, dp->d_name);
			return 1;
		} else if (hash_psi(psi) == h->hash_path[i]) {
			/* PERHAPS WE'VE GOT IT */

			len = strlen(path);
			if (len + strlen(dp->d_name) + 1 >= PATH_MAX + NAME_MAX)
				continue;

			strcpy(path + len, dp->d_name);
			strcpy(path + len, "/");
			return 1;
		}
	}
	return 0;
}

static char *
fh_buildpath(svc_fh *h)
{
	char		pathbuf[PATH_MAX + NAME_MAX + 1], *path;
	long		cookie_stack[HP_LEN + 1];
	char		*slash_stack[HP_LEN];
	struct stat	sbuf;
	psi_t		psi;
	int		i;

	if (h->hash_path[0] >= HP_LEN) {
		Dprintf(L_ERROR, "impossible hash_path[0] value: %s\n", 
					fh_dump(h));
		return NULL;
	}

	if (efs_stat("/", &sbuf) < 0)
		return (NULL);
	psi = pseudo_inode(sbuf.st_ino, sbuf.st_dev);

	if (h->hash_path[0] == 0) {
		if (psi != h->psi)
			return (NULL);
		return xstrdup("/");
	}
	if (hash_psi(psi) != h->hash_path[1])
		return (NULL);

	auth_override_uid(ROOT_UID);
	strcpy(pathbuf, "/");
	i = 2;
	cookie_stack[i] = 0;
	while (i <= h->hash_path[0] + 1) {
		DIR *dir;

		if (efs_stat(pathbuf, &sbuf) >= 0
		    && (dir = efs_opendir(pathbuf)) != NULL) {
			if (cookie_stack[i] != 0)
				efs_seekdir(dir, cookie_stack[i]);
			if (!fh_buildcomp(h, sbuf.st_dev, dir, i, pathbuf)) {
				efs_closedir(dir);
				goto shallower;
			}
			if (i != h->hash_path[0] + 1) {
				/* more components to go */
				slash_stack[i] = pathbuf + strlen(pathbuf);
				cookie_stack[i] = efs_telldir(dir);
				cookie_stack[i + 1] = 0;
				closedir(dir);
				i++;
				continue;
			}
			path = xstrdup(pathbuf);
			efs_closedir(dir);
			auth_override_uid(auth_uid);
			return (path);
		}
	shallower:
		if (--i < 2)
			break;
		/* Prune path */
		*(slash_stack[i]) = '\0';
	}
	auth_override_uid(auth_uid);
	return (NULL);
}
#endif

static psi_t
path_psi(char *path, nfsstat *status, struct stat *sbp, int svalid)
{
	struct stat sbuf;

	if (sbp == NULL)
		sbp = &sbuf;
	if (!svalid && efs_lstat(path, sbp) < 0) {
		*status = nfs_errno();
		return (0);
	}
	if (S_ISDIR(sbp->st_mode) && strcmp(path, "/") != 0) {
		/* Special case for directories--test for mount point. */
		struct stat ddbuf;
		char *fname;

		/* Find start of last component of path. */
#if 1
		char	*dname = path;

		if ((fname = strrchr(dname, '/')) == dname) {
			dname = "/";
		}
		*fname++ = '\0';
		if (efs_lstat(dname, &ddbuf) < 0) {
			fname[-1] = '/';
			*status = nfs_errno();
			return (0);
		}
#else
		if ((sindx = strrchr(path, '/')) == path) {
			sindx++;
			fname = sindx;
		} else
			fname = sindx + 1;

		/* Remove last element of path. */
		squirrel = *sindx;
		*sindx = '\0';
		if (efs_lstat(path, &ddbuf) < 0) {
			*sindx = squirrel;
			*status = nfs_errno();
			return (0);
		}
#endif
		/* fname now points to directory entry name. */
		if (ddbuf.st_dev == sbp->st_dev) {
			fname[-1] = '/';	/* Restore path */
		} else {
			/* Directory is a mount point. */
			DIR *dirp;
			struct dirent *dp;

			errno = 0;
			dirp = efs_opendir(dname);
			fname[-1] = '/';	/* Restore path */

			if (dirp == NULL) {
				if (errno == EACCES)
					goto unreadable;
				if (errno != 0)
					*status = nfs_errno();
				else
					*status = NFSERR_NOENT;
			} else {
				*status = NFS_OK;
				do {
					if ((dp = efs_readdir(dirp)) == NULL) {
						*status = NFSERR_NOENT;
						efs_closedir(dirp);
						return (0);
					}
				} while (strcmp(fname, dp->d_name) != 0);
				sbp->st_dev = ddbuf.st_dev;
				sbp->st_ino = dp->d_ino;
				efs_closedir(dirp);
			}
		}
	unreadable:
		;
	}
	return (pseudo_inode(sbp->st_ino, sbp->st_dev));
}

fhcache *
fh_find(svc_fh *h, int mode)
{
	register fhcache *fhc, *flush;
	int		 check;

	check = (mode & FHFIND_CHECK);
	mode &= 0xF;

#ifdef FHTRACE
	if (h->hash_path[0] >= HP_LEN) {
		Dprintf(L_ERROR, "stale fh detected: %s\n", fh_dump(h));
		return NULL;
	}
#endif

	ex_state = active;
	time(&curtime);
	while ((fhc = fh_lookup(h->psi)) != NULL) {
		Dprintf(D_FHCACHE, "fh_find: psi=%lx... found '%s', fd=%d\n",
			(unsigned long) h->psi,
			fhc->path ? fhc->path : "<unnamed>",
			fhc->fd);

		/* Invalidate cached attrs */
		fhc->flags &= ~FHC_ATTRVALID;

		/* But what if hash_paths are not the same?
		 * Something is stale. */
		if (memcmp(h->hash_path, fhc->h.hash_path, HP_LEN) != 0) {
			Dprintf(D_FHTRACE, "fh_find: stale fh (path mismatch)\n");
			goto fh_discard;
		}

		/* Check whether file exists.
		 * If it doesn't try to rebuild the path.
		 */
		if (check) {
			struct stat	*s = &fhc->attrs;
			psi_t		psi;
			nfsstat		dummy;

			if (efs_lstat(fhc->path, s) < 0) {
				Dprintf(D_FHTRACE,
					"fh_find: stale fh: lstat: %m\n");
			} else {
				fhc->flags |= FHC_ATTRVALID;
				/* If pseudo-inos don't match, we fhc->path
				 * may be a mount point (hence lstat() returns
				 * a different inode number than the readdir()
				 * stuff used in path_psi)
				 */
				psi = pseudo_inode(s->st_ino, s->st_dev);
				if (h->psi == psi)
					goto fh_return;

				/* Try again by computing the path psi */
				psi = path_psi(fhc->path, &dummy, s, 1);
				if (h->psi == psi)
					goto fh_return;

				Dprintf(D_FHTRACE, "fh_find: stale fh: "
					"dev/ino %x/%lx psi %lx",
					s->st_dev, s->st_ino,
					(unsigned long) psi);
			}

		fh_discard:
#ifdef FHTRACE
			Dprintf(D_FHTRACE, "\tdata: %s\n", fh_dump(h));
#endif
			Dprintf(D_FHCACHE, "fh_find: delete cached handle\n");
			fh_delete(fhc);
			break;
		}

	fh_return:
		/* The cached fh seems valid */
		if (fhc != fh_head.next)
			fh_move_to_front(fhc);
		fhc->last_used = curtime;
		ex_state = inactive;
		return (fhc);
	}

	Dprintf(D_FHCACHE, "fh_find: psi=%lx... not found\n",
		(unsigned long) h->psi);
	if (mode == FHFIND_FCACHED) {
		ex_state = inactive;
		return NULL;
	}

	for (flush = fh_tail.prev; fh_list_size > FH_CACHE_LIMIT; flush = fhc) {
		/* Don't flush current head. */
		if (flush == &fh_head)
			break;
		fhc = flush->prev;
		fh_delete(flush);
	}
	fhc = (fhcache *) xmalloc(sizeof *fhc);
	if (mode == FHFIND_FCREATE) {
		/* File will be created */
		fhc->path = NULL;
	} else {
		/* File must exist. Attempt to construct from hash_path */
		char *path;

		if ((path = fh_buildpath(h)) == NULL) {
#ifdef FHTRACE
			Dprintf(D_FHTRACE, "fh_find: stale fh (hash path)\n");
			Dprintf(D_FHTRACE, "\tdata: %s\n", fh_dump(h));
#endif
			free(fhc);
			ex_state = inactive;
			return NULL;
		}
		fhc->path = path;
	}
	fhc->flags = 0;
	if (fhc->path && efs_lstat(fhc->path, &fhc->attrs) >= 0) {
		if (re_export && nfsmounted(fhc->path, &fhc->attrs))
			fhc->flags |= FHC_NFSMOUNTED;
		fhc->flags |= FHC_ATTRVALID;
	}
	fhc->fd = -1;
	fhc->last_used = curtime;
	fhc->h = *h;
	fhc->last_clnt = NULL;
	fhc->last_mount = NULL;
	fhc->last_uid = (uid_t)-1;
	fhc->fd_next = fhc->fd_prev = NULL;
	fh_inserthead(fhc);
	Dprintf(D_FHCACHE,
		"fh_find: created new handle %x (path `%s' psi %08x)\n",
		fhc, fhc->path ? fhc->path : "<unnamed>", fhc->h.psi);
	ex_state = inactive;
	if (fh_list_size > FH_CACHE_LIMIT)
		flush_cache(0);
#ifdef FHTRACE
	if (fhc->h.hash_path[0] == 0xFF) {
		Dprintf(L_ERROR, "newly created fh instantly flushed?!");
		return NULL;
	}
#endif
	return (fhc);
}

/*
 * This function is usually called from the debugging code, where
 * the user has not been authenticated yet. Hence, no path lookups.
 */
char *
fh_pr(nfs_fh *fh)
{
	fhcache *h;

	if ((h = fh_find((svc_fh *) fh, FHFIND_FCACHED)) == NULL)
		return fh_dump((svc_fh *) fh);
	return (h->path);
}

static char *
fh_dump(svc_fh *fh)
{
	static char	buf[65];
	char		*sp;
	int		i, n = fh->hash_path[0];

	sprintf(buf, "%08x %02x ", fh->psi, fh->hash_path[0]);
	for (i = 1, sp = buf + 12; i <= n && i < HP_LEN; i++, sp += 2)
		sprintf(sp, "%02x", fh->hash_path[i]);
	return buf;
}

/*
 * This routine is only used by the mount daemon.
 * It creates the initial file handle.
 */
int
fh_create(nfs_fh *fh, char *path)
{
	svc_fh	key;
	fhcache	*h;
	psi_t	psi;
	nfsstat	status;
	char	*s;

	memset(&key, 0, sizeof(key));
	status = NFS_OK;
	if ((psi = path_psi("/", &status, NULL, 0)) == 0)
		return ((int) status);
	s = path;
	while ((s = strchr(s + 1, '/')) != NULL) {
		if (++(key.hash_path[0]) >= HP_LEN)
			return ((int) NFSERR_NAMETOOLONG);
		key.hash_path[key.hash_path[0]] = hash_psi(psi);
		*s = '\0';
		if ((psi = path_psi(path, &status, NULL, 0)) == 0)
			return ((int) status);
		*s = '/';
	}
	if (*(strrchr(path, '/') + 1) != '\0') {
		if (++(key.hash_path[0]) >= HP_LEN)
			return ((int) NFSERR_NAMETOOLONG);
		key.hash_path[key.hash_path[0]] = hash_psi(psi);
		if ((psi = path_psi(path, &status, NULL, 0)) == 0)
			return ((int) status);
	}
	key.psi = psi;
	h = fh_find(&key, FHFIND_FCREATE);

#ifdef FHTRACE
	if (!h)
		return NFSERR_STALE;
#endif

	/* assert(h != NULL); */
	if (h->path == NULL) {
		h->fd = -1;
		h->path = xstrdup(path);
		h->flags = 0;
	}
	memcpy(fh, &key, sizeof(key));
	return ((int) status);
}

char *
fh_path(nfs_fh *fh, nfsstat *status)
{
	fhcache *h;

	if ((h = fh_find((svc_fh *) fh, FHFIND_FEXISTS)) == NULL) {
		*status = NFSERR_STALE;
		return (NULL);
	}
	*status = NFS_OK;
	return (h->path);
}

nfs_fh *
fh_handle(fhcache *h)
{
	return ((nfs_fh*)&(h->h));
}

int
path_open(char *path, int omode, int perm)
{
	int fd;
	int oerrno, ok;
	struct stat buf;

	fh_flush_fds();

	/* If the file exists, make sure it is a regular file. Opening
	 * device files might hang the server. There's still a tiny window
	 * here, but it's not very likely someone's able to exploit
	 * this.
	 */
	if ((ok = (efs_lstat(path, &buf) >= 0)) && !S_ISREG(buf.st_mode)) {
		errno = EISDIR;	/* emulate SunOS server */
		return -1;
	}

#if 1
	fd = efs_open(path, omode, perm);
#else
	/* First, try to open the file read/write. The O_*ONLY flags ored
	 * together do not yield O_RDWR, unfortunately. 
	 * Backed out for now; we have to record the new omode in
	 * h->omode to be effective, anyway.
	 */
	fd = efs_open(path, (omode & ~O_ACCMODE)|O_RDWR, perm);
	if (fd < 0)
		fd = efs_open(path, omode, perm);
#endif

	oerrno = errno;

	/* The file must exist at this point. */
	if (!ok && efs_lstat(path, &buf) < 0) {
		/*
		Dprintf(L_ERROR,
			"path_open(%s, %o, %o): failure mode 1, err=%d\n",
			path, omode, perm, errno);
		 */
		errno = oerrno;
		return -1;
	}

	/* Do some serious cheating for statelessness. The following accomp-
	 * lishes two things: first, it gives the file owner r/w access to
	 * the file whatever the permissions are, so that files are still
	 * accessible after an fchown(fd, 0). The second part of the
	 * condition allows read access to mode 0111 executables.
	 *
	 * The old conditon read like this:
	 * if (fd < 0 && oerrno == EACCES) {
	 *	if (oerrno == EACCES && (buf.st_uid == auth_uid
	 *	    || (omode == O_RDONLY && (buf.st_mode & S_IXOTH)))) {
	 *		override uid; etc...
	 *	}
	 * }
	 * This would truncate read-only files on creat() calls. Now
	 * ftruncate(fd, 0) should still be legal for the user when the
	 * file was chmoded *after* opening it, but we have no way to tell,
	 * and a semi-succeding `cp foo readonly-file' is much more
	 * unintuitive and destructive than a failing ftruncate().
	 */
	if (fd < 0 && oerrno == EACCES && !(omode & (O_CREAT|O_TRUNC))) {
		if ((buf.st_uid == auth_uid && (omode & O_ACCMODE) == omode)
		 || ((buf.st_mode & S_IXOTH) && omode == O_RDONLY)) {
			auth_override_uid(ROOT_UID);
			fd = efs_open(path, omode, perm);
			oerrno = errno;
			auth_override_uid(auth_uid);
		}
	}

	if (fd < 0) {
		Dprintf(D_FHCACHE,
			"path_open(%s, %o, %o): failure mode 2, err=%d, oerr=%d\n",
			path, omode, perm, errno, oerrno);
		errno = oerrno;
		return -1;
	}

	errno = oerrno;
	return (fd);
}

int
fh_fd(fhcache *h, nfsstat *status, int omode)
{
	if (h->fd >= 0) {
		/* If the requester's uid doesn't match that of the user who
		 * opened the file, we close the file. I guess we could work
		 * some magic with the eaccess stuff, but I don't know if
		 * this would be any faster than simply re-doing the open.
		 */
		if (h->last_uid == auth_uid && (h->omode == omode ||
		    ((omode == O_RDONLY || omode == O_WRONLY) && h->omode == O_RDWR))) {
			Dprintf(D_FHCACHE, "fh_fd: reusing fd=%d\n", h->fd);
			fh_insert_fdcache(h);	/* move to front of fd LRU */
			return (h->fd);
		}
		Dprintf(D_FHCACHE,
		    "fh_fd: uid/omode mismatch (%d/%d wanted, %d/%d cached)\n",
		     auth_uid, omode, h->last_uid, h->omode);
		fh_close(h);
	}
	errno = 0;
	if (!h->path) {
		*status = NFSERR_STALE;
		return (-1);	/* something is really hosed */
	}

	if ((h->fd = path_open(h->path, omode, 0)) >= 0) {
		io_state = active;
		h->omode = omode & O_ACCMODE;
		fh_insert_fdcache(h);
		Dprintf(D_FHCACHE, "fh_fd: new open as fd=%d\n", h->fd);
		h->last_uid = auth_uid;
		return (h->fd);
	} 
	*status = nfs_errno();
	return -1;
}

void
fd_inactive(int fd)
{
	io_state = inactive;
}

/*
 * Massage a WebNFS MCL pathname into something usable.
 */
static char *
frob_webnfs_path(char *name)
{
	char	*s1, *s2;

	if ((unsigned char) name[0] == 0x80)
		return name + 1;
	if (name[0] <= 0x1f || name[0] == 0x7f)
		return NULL;
	s1 = s2 = name;
	while (*s2) {
		/* Deal with %xx hex escapes */
		if (*s2 == '%') {
			unsigned char	c1 = tolower(s2[1]),
					c2 = tolower(s2[2]);

			if (!isxdigit(c1) || !isxdigit(c2))
				return NULL;
			c1 = (c1 <= '9')? (c1 - '0') : (c1 - 'a');
			c2 = (c2 <= '9')? (c2 - '0') : (c2 - 'a');
			*s1++ = (c1 << 4) | c2;
			s2 += 3;
		} else {
			*s1++ = *s2++;
		}
	}
	*s1++ = '\0';
	return name;
}

/*
 * Create a new file handle by composing <dirfh> and filename.
 * For webnfs lookups, this may also be the place to handle index.html
 * files. That may come in a later release, though.
 */
nfsstat
fh_compose(diropargs *dopa, nfs_fh *new_fh, struct stat *sbp,
			int fd, int omode, int public)
{
	svc_fh		*key;
	fhcache		*dirh, *h;
	char		*sindx;
	int		is_dd;
	nfsstat		ret;
	struct stat	sbuf;
	char		pathbuf[PATH_MAX + NAME_MAX + 1], *fname;

	/* should not happen */
	if (sbp == NULL)
		sbp = &sbuf;

	if ((dirh = fh_find((svc_fh *) &dopa->dir, FHFIND_FEXISTS)) == NULL)
		return NFSERR_STALE;

	/*
	 * If we operate on the public file handle, check whether we
	 * have a multiple component lookup.
	 */
	if (public) {
		Dprintf(D_FHCACHE, "fh_compose: multi-component lookup\n");
		if (!(fname = frob_webnfs_path(dopa->name)))
			return NFSERR_IO;
		/* Absolute lookups are easy: just create the
		 * FH; don't bother with setting up a cache entry for
		 * now (happens later). */
		if (fname[0] == '/') {
			/* shouldn't happen because the name's limited
			 * by NFS_MAXNAMELEN == 255 */
			if (strlen(fname) >= NFS_MAXPATHLEN)
				return NFSERR_NAMETOOLONG;
			sbp->st_nlink = 0;
			return fh_create(new_fh, fname);
		}
	} else {
		/*
		 * This allows only single directories to be looked up, could
		 * be a bit more sophisticated, but i don't know if that is
		 * neccesary. (actually, it's a security feature --okir).
		 */
		if (strchr(dopa->name, '/') != NULL)
			return NFSERR_ACCES;
		fname = dopa->name;
	}

	/* Security check */
	if (strlen(dirh->path) + strlen(fname) + 1 >= NFS_MAXPATHLEN)
		return NFSERR_NAMETOOLONG;

	/* Construct path.
	 * Lookups of "" generated by broken OS/2 clients
	 */
	if (strcmp(fname, ".") == 0 || fname[0] == '\0') {
		*new_fh = dopa->dir;
		sbp->st_nlink = 0;
		return (NFS_OK);
	}
	if (strcmp(fname, "..") == 0) {
		is_dd = 1;
		sindx = strrchr(dirh->path, '/');
		if (sindx == dirh->path)
			strcpy(pathbuf, "/");
		else {
			int len = sindx - dirh->path;
			strncpy(pathbuf, dirh->path, len);
			pathbuf[len] = '\0';
		}
	} else if (!re_export && (dirh->flags & FHC_NFSMOUNTED)) {
		return NFSERR_NOENT;
	} else {
		int len = strlen(dirh->path);

		is_dd = 0;
		if (len && dirh->path[len - 1] == '/')
			len--;
		strncpy(pathbuf, dirh->path, len);
		pathbuf[len] = '/';
		strcpy(pathbuf + (len + 1), fname);
	}

	*new_fh = dopa->dir;
	key = (svc_fh *) new_fh;
	if ((key->psi = path_psi(pathbuf, &ret, sbp, 0)) == 0)
		return (ret);

	if (is_dd) {
		/* Don't cd .. from root, or mysterious ailments will
		 * befall your fh cache... Fixed. */
		if (key->hash_path[0] > 0)
			key->hash_path[key->hash_path[0]--] = 0;
	} else {
		if (++(key->hash_path[0]) >= HP_LEN)
			return NFSERR_NAMETOOLONG;
		key->hash_path[key->hash_path[0]] = hash_psi(dirh->h.psi);
	}
	/* FIXME: when crossing a mount point, we'll find the real
	 * dev/ino in sbp and can store it in h... */
	h = fh_find(key, FHFIND_FCREATE);

#ifdef FHTRACE
	if (h == NULL)
		return NFSERR_STALE;
	if (h->h.hash_path[0] >= HP_LEN) {
		Dprintf(L_ERROR, "fh cache corrupted! file %s hplen %02x",
					h->path? h->path : "<unnamed>",
					h->h.hash_path[0]);
		return NFSERR_STALE;
	}
#endif

	/* New code added by Don Becker */
	if (h->path != NULL && strcmp(h->path, pathbuf) != 0) {
		/* We must have cached an old file under the same inode # */
		Dprintf(D_FHTRACE, "Disposing of fh with bad path.\n");
		fh_delete(h);
		h = fh_find(key, FHFIND_FCREATE);
#ifdef FHTRACE
		if (!h) return NFSERR_STALE;
#endif
		if (h->path)
			Dprintf(L_ERROR, "Internal inconsistency: double entry (path '%s', now '%s').\n",
				h->path, pathbuf);
	}
	Dprintf(D_FHCACHE, "fh_compose: using  handle %x ('%s', fd=%d)\n",
		h, h->path ? h->path : "<unnamed>", h->fd);
	/* End of new code */

	/* assert(h != NULL); */
	if (h->path == 0) {
		h->path = xstrdup(pathbuf);
		h->flags = 0;
		if (!re_export && nfsmounted(pathbuf, sbp))
			h->flags |= FHC_NFSMOUNTED;
#ifdef FHTRACE
		Dprintf(D_FHTRACE, "fh_compose: created handle %s\n", h->path);
		Dprintf(D_FHTRACE, "\tdata: %s\n", fh_dump(&h->h));
#else
		Dprintf(D_FHCACHE,
			"fh_compose: +using  handle %x ('%s', fd=%d)\n",
			h, h->path, h->fd);
#endif
	}

	if (fd >= 0) {
		Dprintf(D_FHCACHE,
			"fh_compose: handle %x using passed fd %d\n", h, fd);
		if (h->fd >= 0)
			fh_close(h);
		h->last_uid = auth_uid;
		h->fd = fd;
		fh_insert_fdcache(h);
		Dprintf(D_FHCACHE,
			"fh_compose: +using  handle %x ('%s', fd=%d)\n",
			h, h->path ? h->path : "<unnamed>", h->fd);
	}
	if (omode >= 0)
		h->omode = omode & O_ACCMODE;
	return (NFS_OK);
}

psi_t
fh_psi(nfs_fh *fh)
{
	svc_fh *h = (svc_fh *) fh;
	return (h->psi);
}

void
fh_remove(char *path)
{
	psi_t	psi;
	nfsstat status;
	fhcache *fhc;

	psi = path_psi(path, &status, NULL, 0);
	if (psi == 0)
		return;
	ex_state = active;
	fhc = fh_lookup(psi);
	if (fhc != NULL)
		fh_delete(fhc);

	ex_state = inactive;
	return;
}

/*
 * Close a file to make an fd available for a new file.
 */
static int
fh_flush_fds(void)
{
	if (io_state == active) {
		Dprintf(D_FHCACHE, "fh_flush_fds: not flushing... io active\n");
		return (-1);
	}
	while (fd_cache_size >= FD_CACHE_LIMIT)
		fh_close(fd_lru_tail);
	return (0);
}

/*
 * fh_flush() is invoked periodically from SIGALRM, and on
 * demand from fh_find.  A simple form of mutual exclusion
 * protects this routine from multiple concurrent executions.
 * Since the preemption that occurs when a signal is received
 * is one-sided, we don't need an atomic test and set.  If the
 * signal arrives between the test and the set, the first
 * invocation safely stalls until the signal-caused invocation
 * completes.
 *
 * NOTE: fh_flush is now always called from the top RPC dispatch
 * routine, and the ex_state stuff is likely to go when this proves
 * to work.
 */
void
fh_flush(int force)
{
	register fhcache *h;

#ifdef DEBUG
	time_t now;
	time(&now);
	Dprintf(D_FHTRACE, "flushing cache at %s: state = %s\n",
		ctime(&now), (ex_state == inactive) ? "inactive" : "active");
#endif

	if (ex_state == inactive) {
		int cache_size = 0;

		ex_state = active;
		time(&curtime);
		/* Single execution thread */

		/* works in empty case because: fh_tail.next = &fh_tail */
		h = fh_head.next;
		while (h != &fh_tail) {
			if (cache_size > FH_CACHE_LIMIT
			    || curtime > h->last_used + DISCARD_INTERVAL
			    || force) {
				h = h->next;
				fh_delete(h->prev);
			} else {
				if (h->fd >= 0 &&
				    curtime > h->last_used + CLOSE_INTERVAL)
					fh_close(h);
				cache_size++;
				h = h->next;
			}
		}
		if (fh_list_size != cache_size)
			Dprintf(L_ERROR,
				"internal inconsistency (fh_list_size=%d) != (cache_size=%d)\n",
				fh_list_size, cache_size);
		fh_list_size = cache_size;
		ex_state = inactive;
	}
}

RETSIGTYPE
flush_cache(int sig)
{
	static volatile int	inprogress = 0;

	if (_rpcsvcdirty) {
		alarm(BUSY_RETRY_INTERVAL);
		need_flush = 1;
		return;
	}
	if (inprogress++)
		return;
	fh_flush(0);
	if (_rpcpmstart)
		rpc_closedown();
	inprogress = 0;
	need_flush = 0;
	alarm(FLUSH_INTERVAL);
}

void
fh_init(void)
{
	static int	initialized = 0;

	if (initialized)
		return;
	initialized = 1;

	fh_head.next = fh_tail.next = &fh_tail;
	fh_head.prev = fh_tail.prev = &fh_head;
	/* last_flushable = &fh_tail; */

	install_signal_handler(SIGALRM, flush_cache);
	alarm(FLUSH_INTERVAL);

	umask(0);
}

