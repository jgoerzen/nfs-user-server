/*
 * fh.h		This module handles the file-handle cache.
 *
 * Authors:	Mark A. Shand, May 1988
 *		Don Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

/* Compatibility between mount and nfs_prot. */
#ifndef NFS_FHSIZE
#   define NFS_FHSIZE		FHSIZE
#endif

#define	FHC_XONLY_PATH		001	/* NOT USED ANYMORE */
#define	FHC_ATTRVALID		002
#define FHC_NFSMOUNTED		004

/* Modes for fh_find */
#define FHFIND_FEXISTS	0	/* file must exist */
#define FHFIND_FCREATE	1	/* file will be created */
#define FHFIND_FCACHED	2	/* fh must be in cache */
#define FHFIND_CHECK	0x10	/* Check for cached path */

/*
 * This defines the maximum number of handles nfsd will cache.
 */
#define	FH_CACHE_LIMIT		2000

/*
 * This defines the maximum number of files nfsd may keep open for NFS I/O.
 * It used to be 8...
 */
#define FD_CACHE_LIMIT		(3*FOPEN_MAX/4)

/* The following affect cache expiry.
 * CLOSE_INTERVAL applies to the closing of inactive file descriptors
 * The fd expiry interval is actually quite low because we want to have big
 * files actually go away when they have been deleted behind our back. 
 * We also want to be able to execute programs that have just been copied
 * via NFS.
 *
 * DISCARD_INTERVAL is the time in seconds nfsd will cache file handles
 * unless it's being flooded with other requests. This value is possibly
 * still too large, but the original was 2 days.		--okir
 */
#define FLUSH_INTERVAL		5			/* 5 seconds	*/
#define BUSY_RETRY_INTERVAL	2			/* 2 seconds	*/
#define CLOSE_INTERVAL		5			/* 5 seconds	*/
#define DISCARD_INTERVAL	(60*60)			/* 1 hour	*/

/*
 * Type of a pseudo inode
 */
typedef __u32		psi_t;

/*
 * Hashed search path to this file.
 * path is: hash_path[1] ... hash_path[hash_path[0]]
 *
 * hash_path[hash_path[0]+1] ... hash_path[HP_LEN-1] == 0
 */
#define	HP_LEN		(NFS_FHSIZE - sizeof(psi_t))
typedef struct {
	psi_t		psi;
	__u8		hash_path[HP_LEN];
} svc_fh;

typedef enum { inactive, active } mutex;

/*
 * Paths constructed in this system always consist of real directories
 * (excepting the last element) i.e. they do not contain symbolic links.
 * This is guaranteed by the way NFS constructs the paths.
 * As a consequence we may assume that
 *	/x/y/z/.. == /x/y
 * and	/x/y/z/. == /x/y/z
 * provided that z != . && z != ..
 * These relations are exploited in fh_compose.
 *
 * Further assumptions:
 *	All cached pathnames consist of a leading /
 *	followed by zero or more / separated names
 *	s.t.
 *		name != .
 *		name != ..
 *		index(name, '/') == 0
 */
typedef struct fhcache {
	struct fhcache *	next;
	struct fhcache *	prev;
	struct fhcache *	hash_next;
	struct fhcache *	fd_next;
	struct fhcache *	fd_prev;
	svc_fh			h;
	int			fd;
	int			omode;
	char *			path;
	time_t			last_used;
	nfs_client *		last_clnt;
	nfs_mount *		last_mount;
	uid_t			last_uid;
	int			flags;
	struct stat		attrs;
} fhcache;

/* Global FH variables. */
extern int			_rpcpmstart;
extern int			fh_initialized;

/* Global function prototypes. */
extern nfsstat	nfs_errno(void);
extern psi_t	pseudo_inode(ino_t inode, dev_t dev);
extern void	fh_init(void);
extern char	*fh_pr(nfs_fh *fh);
extern int	fh_create(nfs_fh *fh, char *path);
extern fhcache	*fh_find(svc_fh *h, int create);
extern char	*fh_path(nfs_fh *fh, nfsstat *status);
extern int	path_open(char *path, int omode, int perm);
extern int	fh_fd(fhcache *fhc, nfsstat *status, int omode);
extern void	fd_inactive(int fd);
extern nfsstat	fh_compose(diropargs *dopa, nfs_fh *new_fh,
				struct stat *sbp, int fd,
				int omode, int public);
extern psi_t	fh_psi(nfs_fh *fh);
extern void	fh_remove(char *path);
extern nfs_fh	*fh_handle(fhcache *fhc);
extern void	fh_flush(int force);
extern RETSIGTYPE flush_cache(int sig);
extern int	nfsmounted(const char *path, struct stat *sbp);

#ifdef ENABLE_DEVTAB
extern unsigned int	devtab_index(dev_t);
#endif

/* End of fh.h. */

