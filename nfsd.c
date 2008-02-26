/*
 * nfsd		This program handles RPC "NFS" data requests.
 *
 * Usage:	[rpc.]nfsd [-Fhnprv] [-f authfile] [-d debugfac]
 *
 * Authors:	Mark A. Shand, May 1988
 *		Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Eric Kasten, <tigger@tigger.cl.msu.edu>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "nfsd.h"
#include <rpc/pmap_clnt.h>
#include "getopt.h"
#include "fsusage.h"
#include "rpcmisc.h"
#include "failsafe.h"
#include "signals.h"
#ifdef __linux__ /* XXX - MvS: for UNIX sockets. */
#  include <sys/un.h>
#endif
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#define MULTIPLE_SERVERS

/* Flags for auth_fh */
#define CHK_READ	0
#define CHK_WRITE	1
#define CHK_NOACCESS	2
#define CHK_ROOT	4

/* Make larger reads possible. Without crashing the machine :-) */
#undef NFS_MAXDATA
#define NFS_MAXDATA	(16 * 1024)

static char iobuf[NFS_MAXDATA];
static char pathbuf[NFS_MAXPATHLEN + NFS_MAXNAMLEN + 1];
static char pathbuf_1[NFS_MAXPATHLEN + NFS_MAXNAMLEN + 1];

extern char version[];
static char *program_name;

/*
 * Option table
 */
static struct option longopts[] = {
      { "auth-deamon",		required_argument,	0,	'a' },
      { "debug",		required_argument,	0,	'd' },
      { "foreground",		0,			0,	'F' },
      { "exports-file",		required_argument,	0,	'f' },
      { "help",			0,			0,	'h' },
      { "log-transfers",	0,			0,	'l' },
      { "allow-non-root",	0,			0,	'n' },
      { "port",			required_argument,	0,	'P' },
      { "promiscuous",		0,			0,	'p' },
      { "re-export",		0,			0,	'r' },
      { "public-root",		required_argument,	0,	'R' },
      { "synchronous-writes",	0,			0,	's' },
      { "no-spoof-trace",	0,			0,	't' },
      { "version",		0,			0,	'v' },
      { "no-cross-mounts",	0,			0,	'x' },
      { "fail-safe",		optional_argument,	0,	'z' }, 

      { NULL,		0,	0, 0 }
};
static const char *	shortopts = "a:d:Ff:hlnP:prR:tvz::";

/*
 * Table of supported versions
 */
static int		nfsd_versions[] = {
	NFS_VERSION,
	0
};

nfs_client *		nfsclient = NULL;	/* the current client */
nfs_mount *		nfsmount = NULL;	/* the current mount point */
int			need_reinit = 0;	/* SIGHUP handling */
int			need_flush = 0;		/* flush fh cache */
int			read_only = 0;		/* Global ro forced */
int			cross_mounts = 1;	/* Transparently cross mnts */
int			log_transfers = 0;	/* Log transfers */
static svc_fh		public_fh;		/* Public NFSv2 FH */

static nfsstat	build_path(struct svc_req *rqstp, char *buf,
				diropargs *dopa, int flags);
static fhcache *auth_fh(struct svc_req *rqstp, nfs_fh *fh, 
				nfsstat *statp, int flags);
static void	usage(FILE *, int);
static void	terminate(void);
static RETSIGTYPE sigterm(int sig);
#ifdef SUPPORT_CDF
static char *	cdf_translate(char *tag);
#endif


#ifdef CALL_PROFILING
extern void	dump_stats(int sig);
#endif

/*
 * auth_fh
 *
 * This function authenticates the file handle provided by the client.
 * It also takes care of caching the client and mount point structures
 * in the fh cache entry, even though this may not be a huge benefit.
 */
static fhcache *
auth_fh(struct svc_req *rqstp, nfs_fh *fh, nfsstat *statp, int flags)
{
	static int	total = 0, cached = 0;
	fhcache		*fhc;

	/* Try to map FH. If not cached, reconstruct path with root priv */
	fhc = fh_find((svc_fh *)fh, FHFIND_FEXISTS|FHFIND_CHECK);
	if (fhc == NULL) {
		*statp = NFSERR_STALE;
		return NULL;
	}

	/* Try to retrieve last client who accessed this fh */
	if (nfsclient == NULL) {
		struct in_addr	caddr;

		caddr = svc_getcaller(rqstp->rq_xprt)->sin_addr;
		if (fhc->last_clnt != NULL &&
		    fhc->last_clnt->clnt_addr.s_addr == caddr.s_addr) {
			nfsclient = fhc->last_clnt;
		} else if ((nfsclient = auth_clnt(rqstp)) == NULL) {
			*statp = NFSERR_ACCES;
			return NULL;
		}
	}

	if (fhc->last_clnt == nfsclient) {
		nfsmount = fhc->last_mount; /* get cached mount point */
		cached++;
	} else {
		nfsmount = auth_path(nfsclient, rqstp, fhc->path);
		if (nfsmount == NULL) {
			*statp = NFSERR_ACCES;
			return NULL;
		}
		fhc->last_clnt = nfsclient;
		fhc->last_mount = nfsmount;
	}
	total++;
	/*
	if (total % 1000 == 0)
		Dprintf(D_FHCACHE, "ratio of cached client ptrs %4.1f%%\n",
			100 * (double) cached / total);
	 */

	if (nfsmount->o.noaccess &&
	    ((flags & CHK_NOACCESS) || strcmp(nfsmount->path, fhc->path))) {
		struct in_addr	addr = svc_getcaller(rqstp->rq_xprt)->sin_addr;
		Dprintf(L_WARNING, "client %s tried to access %s (noaccess)\n",
				inet_ntoa(addr), fhc->path);
		*statp = NFSERR_ACCES;
		return NULL;
	}

	if ((flags & CHK_WRITE) && (nfsmount->o.read_only || read_only)) {
		*statp = NFSERR_ROFS;
		return NULL;
	}

	if (!(flags & CHK_ROOT) || strcmp(nfsmount->path, fhc->path))
		auth_user(nfsmount, rqstp);

	*statp = NFS_OK;
	return fhc;
}

/*
 * Build the full path name for a file specified by diropargs.
 */
static inline nfsstat
build_path(struct svc_req *rqstp, char *buf, diropargs *dopa, int flags)
{
	fhcache		*fhc;
	nfsstat		status;
	char		*path = buf, *sp;

	/* Authenticate directory file handle */
	if ((fhc = auth_fh(rqstp, &dopa->dir, &status, flags)) == NULL)
		return status;

	/* Get the directory path and append "/" + dopa->filename */
	if (strlen(fhc->path) + strlen(dopa->name) + 1 >= NFS_MAXPATHLEN)
		return NFSERR_NAMETOOLONG;

	sp = fhc->path;
	while (*sp)		/* strcpy(buf, fhc->path); */
		*buf++ = *sp++;
	*buf++ = '/';		/* strcat(buf, "/");  */
	sp = dopa->name;
	while (*sp) {		/* strcat(pathbuf, argp->where.name); */
		if (*sp == '/')
			return NFSERR_INVAL;
		*buf++ = *sp++;
	}
	*buf = '\0';

	if ((nfsmount = auth_path(nfsclient, rqstp, path)) == NULL)
		return NFSERR_ACCES;
	auth_user(nfsmount, rqstp);

	return (NFS_OK);
}

/*
 * Log a transfer to syslog.
 */
static void
nfsd_xferlog(struct svc_req *rqstp, char *inout, char *pathname)
{
	struct in_addr	addr = svc_getcaller(rqstp->rq_xprt)->sin_addr;

	syslog(LOG_INFO, "%s %s %s", inet_ntoa(addr), inout, pathname);
}

/*
 * The "wrappers" of the following functions came from `rpcgen -l nfs_prot.x`.
 * This normally generates the client routines, but it provides nice
 * prototypes for the server routines also.
 */
int
nfsd_nfsproc_null_2(void *argp, struct svc_req *rqstp)
{
	return (0);
}

int
nfsd_nfsproc_getattr_2(nfs_fh *argp, struct svc_req *rqstp)
{
	nfsstat status;
	fhcache *fhc;

	fhc = auth_fh(rqstp, argp, &status, CHK_READ | CHK_ROOT);
	if (fhc == NULL)
		return status;

	return (fhc_getattr(fhc, &result.attrstat.attrstat_u.attributes,
						NULL, rqstp));
}

int
nfsd_nfsproc_setattr_2(sattrargs *argp, struct svc_req *rqstp)
{
	nfsstat status;
	fhcache *fhc;
	char *path;
	struct stat buf, *opt;

	fhc = auth_fh(rqstp, &(argp->file), &status, CHK_WRITE | CHK_NOACCESS);
	if (fhc == NULL)
		return status;
	path = fhc->path;

	errno = 0;
	/* Stat the file first and only change fields that are different. */
	if (efs_lstat(path, &buf) < 0)
		goto failure;

	status = setattr(path, &argp->attributes, &buf, rqstp, SATTR_ALL);
	if (status != NFS_OK)
		return status;

	/* Oops: Don't optimize getattr when the setattr arguments didn't
	 * contain valid mtime... */
	opt = &buf;
	if (argp->attributes.mtime.seconds == -1)
		opt = NULL;
	return (fhc_getattr(fhc, &(result.attrstat.attrstat_u.attributes),
						opt, rqstp));

failure:
	return (nfs_errno());
}

int
nfsd_nfsproc_root_2(void *argp, struct svc_req *rqstp)
{
	return (0);
}

/*
 * Look up a file by name.
 * Multi-component lookups for webnfs are handled by fh_compose.
 */
int
nfsd_nfsproc_lookup_2(diropargs *argp, struct svc_req *rqstp)
{
	diropokres	*dp = &result.diropres.diropres_u.diropres;
	nfs_fh		*fh = &argp->dir;
	fhcache		*fhc;
	nfsstat		status;
	struct stat	sbuf;
	int		ispublic = 0;

	/* First check whether this is the public FH */
	if (((svc_fh *) fh)->psi == 0 && !memcmp(fh, &public_fh, FHSIZE)) {
		if (public_root_path == NULL)
			return NFSERR_ACCES;
		memcpy(&argp->dir, &public_root, NFS_FHSIZE);
		ispublic = 1;
	}


	/* Must authenticate dir FH to set fsuid/fsgid. Thanks to
	 * Stig Venaas for his bug report.
	 * Note this also sets the FHC_PUBLIC flag on the file handle.
	 */
	if (!(fhc = auth_fh(rqstp, fh, &status, CHK_READ)))
		return status;

	status = fh_compose(argp, &dp->file, &sbuf, -1, -1, ispublic);
	if (status != NFS_OK)
		return status;

	fhc = auth_fh(rqstp, &dp->file, &status, CHK_READ);
	if (fhc == NULL)
		return status;

	status = fhc_getattr(fhc, &dp->attributes, &sbuf, rqstp);
	if (status == NFS_OK)
		Dprintf(D_CALL, "\tnew_fh = %s\n", fh_pr(&(dp->file)));

	return (status);
}

#ifdef SUPPORT_CDF
static char *
cdf_translate(char *tag)
{
	static char	buffer[512];

	if (tag[0] == 'u' && !strcmp(tag, "uid"))
		sprintf(buffer, "%d", auth_uid);
	else if (tag[0] == 'h' && !strcmp(tag, "hostaddr"))
		sprintf(buffer, "%s", inet_ntoa(nfsclient->clnt_addr));
	else
		return NULL;
	return buffer;
}
#endif

int
nfsd_nfsproc_readlink_2(nfs_fh *argp, struct svc_req *rqstp)
{
	nfsstat status;
	fhcache *fhc;
	char *path;
	int cc;

	fhc = auth_fh(rqstp, argp, &status, CHK_READ | CHK_NOACCESS);
	if (fhc == NULL)
		return status;
	path = fhc->path;

	errno = 0;
	if ((cc = efs_readlink(path, pathbuf, NFS_MAXPATHLEN)) < 0) {
		Dprintf(D_CALL, " >>> %s\n", strerror(errno));
		return (nfs_errno());
	}
	status = NFS_OK;
	pathbuf[cc] = '\0';	/* readlink() doesn't null terminate!! */
	result.readlinkres.readlinkres_u.data = pathbuf;

	if (nfsmount->o.link_relative && pathbuf[0] == '/') {
		/*
		 * We've got an absolute (locally) pathname, and we should
		 * translate to a relative pathname for the client.  We do
		 * this by prepending the correct number of "../"es to the
		 * path. This cannot work if the client does not mount the
		 * specified subtree of the filesystem.
		 */
		int slash_cnt = 0;
		char *p, *q;

		/* Count how many directories down we are. */
		for (p = path + 1; *p != '\0'; p++)
			if (*p == '/')
				slash_cnt++;

		/*
		 * Ok, now we are finished with the orginal file `path'
		 * and will only deal with the link target.
		 */
		p = &pathbuf[cc];	/* Point to the end and calculate */
		if (slash_cnt == 0)
			q = p + 1;	/* the extra space taken by a	*/
		else			/* prepended '.'  		*/
			q = p + 3 * slash_cnt - 1;	/* or '../.../..' */

		if (q >= pathbuf + NFS_MAXPATHLEN) {
			Dprintf(D_CALL, " [[NAME TOO LONG!!]]\n");
			return (NFSERR_NAMETOOLONG);
		} else {
			/* Add some space at the beginning of the string. */
			while (p >= pathbuf)
				*q-- = *p--;

			if (slash_cnt == 0)
				pathbuf[0] = '.';
			else {
				/*
				 * This overwrites the leading '/' on the
				 * last iteration.
				 */
				for (p = pathbuf; slash_cnt > 0; slash_cnt--) {
					*p++ = '.';
					*p++ = '.';
					*p++ = '/';
				}
			}
		}
	}
	Dprintf(D_CALL, " %s\n", result.readlinkres.readlinkres_u.data);
	return (NFS_OK);
}

int
nfsd_nfsproc_read_2(readargs *argp, struct svc_req *rqstp)
{
	nfsstat status;
	fhcache *fhc;
	readokres *res = &result.readres.readres_u.reply;
	int	fd, len;

	fhc = auth_fh(rqstp, &(argp->file), &status, CHK_READ | CHK_NOACCESS);
	if (fhc == NULL)
		return status;

	if ((fd = fh_fd(fhc, &status, O_RDONLY)) < 0)
		return ((int) status);

	len = -1;
	if (efs_lseek(fd, (long) argp->offset, L_SET) >= 0) {
		res->data.data_val = iobuf;
		if ((len = argp->count) > NFS_MAXDATA)
			len = NFS_MAXDATA;
		if ((len = efs_read(fd, iobuf, len)) >= 0)
			res->data.data_len = len;
	}
	fd_inactive(fd);
	if (len < 0)
		return (nfs_errno());

	/* Write record to syslog */
	if (argp->offset == 0 && log_transfers)
		nfsd_xferlog(rqstp, "<", fhc->path);

	return (fhc_getattr(fhc, &(res->attributes), NULL, rqstp));
}

int
nfsd_nfsproc_writecache_2(void *argp, struct svc_req *rqstp)
{
	return (0);
}

int
nfsd_nfsproc_write_2(writeargs *argp, struct svc_req *rqstp)
{
	nfsstat status;
	fhcache *fhc;
	int	fd, len;

	fhc = auth_fh(rqstp, &(argp->file), &status, CHK_WRITE | CHK_NOACCESS);
	if (fhc == NULL)
		return status;

	/* Check args. I've seen one client send a length of -1 */
	if (argp->data.data_len > NFS_MAXDATA) {
		Dprintf(L_NOTICE,
			"strange write req from %s: len %lu",
			nfsclient->clnt_name, argp->data.data_len);
		return NFSERR_IO;
	}

	if ((fd = fh_fd(fhc, &status, O_WRONLY)) < 0)
		return ((int) status);

	len = -1;
	if (efs_lseek(fd, (long) argp->offset, L_SET) >= 0) {
		len = efs_write(fd, argp->data.data_val, argp->data.data_len);
		if (len != argp->data.data_len)
			Dprintf(D_CALL, "Write failure, errno is %d.\n", errno);
	}
	fd_inactive(fd);
	if (len < 0)
		return nfs_errno();

	/* Write record to syslog */
	if (argp->offset == 0 && log_transfers)
		nfsd_xferlog(rqstp, ">", fhc->path);

	return (fhc_getattr(fhc, &(result.attrstat.attrstat_u.attributes),
							NULL, rqstp));
}

/* This used to be O_RDWR, but O_WRONLY is correct */
#define CREATE_OMODE O_WRONLY

int
nfsd_nfsproc_create_2(createargs *argp, struct svc_req *rqstp)
{
	nfsstat status;
	diropokres *res;
	int tmpfd, flags;
	struct stat sbuf;
	int is_borc;
	int dev;
	int exists;
#ifdef __linux__ /* XXX - MvS: to create UNIX sockets. */
	struct sockaddr_un sa;
	int s;
#endif

	/*
	 * We get the access status and file handle here, but check the
	 * status later. This is to let an "echo >/dev/null" from SunOS
	 * clients succeed on RO-filesystems.
	 */
	status = build_path(rqstp, pathbuf, &argp->where,
					CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK && status != NFSERR_ROFS)
		return ((int) status);
	Dprintf(D_CALL, "\tfullpath='%s'\n", pathbuf);
	errno = 0;

	exists = efs_lstat(pathbuf, &sbuf) == 0;

	/* Compensate for a really bizarre bug in SunOS derived clients. */
	if ((argp->attributes.mode & S_IFMT) == 0) {
		argp->attributes.mode |= exists
			? (sbuf.st_mode & S_IFMT) : S_IFREG;
		if (!S_ISREG(argp->attributes.mode)) {
			/* This branch is excuted only if the file exists
			 * and is a special file. */
			status = NFS_OK;
			argp->attributes.size = sbuf.st_rdev;
		}
	}
	if (status != NFS_OK)
		return ((int)status);

	/* First handle any unusual file-types. */
	if (!S_ISREG(argp->attributes.mode)) {
		if (S_ISBLK(argp->attributes.mode)
		    || S_ISCHR(argp->attributes.mode)) {
			is_borc = 1;
#if 0
			/* This is probably better than just using
			   the size field by itself, but not by much. */
			dev = makedev(((argp->attributes.size >> 8) & 0xff),
			    (argp->attributes.size & 0xff));
#else
			/* We must not assume anything about the layout of
			 * the client's dev_t. Either the value fits into
			 * our dev_t or not...
			 */
			dev = (dev_t) argp->attributes.size;
			if (dev != argp->attributes.size)
				return NFSERR_INVAL;
#endif

			/* MvS: Some clients use chardev 0xFFFF for a FIFO. */
#if defined(major) && defined(minor)
			if (S_ISCHR(argp->attributes.mode) &&
			    major(dev) == 0xff && minor(dev) == 0xff) {
#else
			if (S_ISCHR(argp->attributes.mode) && dev == 0xFFFF) {
#endif
				is_borc = 0;
				dev = 0;
				argp->attributes.mode &= ~S_IFMT;
				argp->attributes.mode |= S_IFIFO;
			}
		}
		else {
			is_borc = 0;
			dev = 0;
		}
		/* mknod will fail for EEXIST, we'll let it succeed. */
		if (!exists) {
#ifdef __linux__ /* XXX - MvS */
			/* Can't make UNIX sockets with mknod. */
			if (S_ISSOCK(argp->attributes.mode)) {
			  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			          return(nfs_errno());
			  sa.sun_family = AF_UNIX;
			  strncpy(sa.sun_path, pathbuf, sizeof(sa.sun_path));
			  sa.sun_path[sizeof(sa.sun_path)-1] = '\0';
			  if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
				(void) close(s);
			        return(nfs_errno());
			  }
			  (void) close(s);
			} else
#endif
			if (efs_mknod(pathbuf, argp->attributes.mode, dev) < 0)
				return (nfs_errno());
			if (efs_stat(pathbuf, &sbuf) < 0)
				return (nfs_errno());
		}
		else {
			/* But make sure it's the same kind of special file. */
			if ((argp->attributes.mode & S_IFMT)
			    != (sbuf.st_mode & S_IFMT))
				return (NFSERR_EXIST);
			/* And that the major and minor numbers agree. */
			if (is_borc && dev != sbuf.st_rdev)
				return (NFSERR_EXIST);
		}
		tmpfd = -1;
	}
	else {
		flags = (argp->attributes.size == 0 ?
			CREATE_OMODE | O_TRUNC : CREATE_OMODE);
		if (!exists)
			flags |= O_CREAT;
		tmpfd = path_open(pathbuf, flags, 
				argp->attributes.mode & ~S_IFMT);
		if (tmpfd < 0)
			goto failure;
		(void) efs_fstat(tmpfd, &sbuf);
	}

	/* creat() is equivalent to open(..., O_CREAT|O_TRUNC|O_WRONLY) */
	if (!exists) {
#ifndef ALLOW_SGIDDIR
		argp->attributes.gid = -1;
#endif
		/* Note: we ignore the size attribute because some clients
		 * create files with mode 0444. Since the file didn't exist
		 * previously, its length is zero anyway.
		 */
		status = setattr(pathbuf, &argp->attributes, &sbuf,
					rqstp, SATTR_ALL & ~SATTR_SIZE);
	} else {
		status = setattr(pathbuf, &argp->attributes, &sbuf,
					rqstp, SATTR_SIZE);
	}
	if (status != NFS_OK)
		return status;

	res = &result.diropres.diropres_u.diropres;
	status = fh_compose(&argp->where, &res->file, &sbuf,
			    tmpfd, CREATE_OMODE, 0);
	if (status != NFS_OK)
		goto failure;
	status = fh_getattr(&res->file, &res->attributes, &sbuf, rqstp);
	if (status != NFS_OK) {
		tmpfd = -1;	/* fd already stored in fh cache */
		goto failure;
	}
	Dprintf(D_CALL, "\tnew_fh = %s\n", fh_pr(&(res->file)));
	return (status);

failure:
	Dprintf(D_CALL, "\tcreate failed -- errno returned=%d.\n", errno);
	if (tmpfd != -1)
		efs_close(tmpfd);
	return (errno? nfs_errno(): status);
}

#undef CREATE_OMODE

int
nfsd_nfsproc_remove_2(diropargs *argp, struct svc_req *rqstp)
{
	nfsstat status;

	status = build_path(rqstp, pathbuf, argp, CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK)
		return ((int) status);

	Dprintf(D_CALL, "\tfullpath='%s'\n", pathbuf);

	/* Remove the file handle from our cache. */
	fh_remove(pathbuf);

	if (efs_unlink(pathbuf) != 0)
		return (nfs_errno());
	else
		return (NFS_OK);
}

int
nfsd_nfsproc_rename_2(renameargs *argp, struct svc_req *rqstp)
{
	nfsstat status;

	status = build_path(rqstp, pathbuf, &argp->from, CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK)
		return ((int) status);
	status = build_path(rqstp, pathbuf_1, &argp->to, CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK)
		return ((int) status);

	Dprintf(D_CALL, "\tpathfrom='%s' pathto='%s'\n", pathbuf, pathbuf_1);

	/* Remove any file handle from our cache. */
	fh_remove(pathbuf);
	fh_remove(pathbuf_1);

	if (efs_rename(pathbuf, pathbuf_1) != 0)
		return (nfs_errno());

	return (NFS_OK);
}

/* For now, we disallow hardlinks between different volumes for
 * security reasons. If we tried harder, we might be able to 
 * support them, but I'm not sure if it's worth it...
 */
int
nfsd_nfsproc_link_2(linkargs *argp, struct svc_req *rqstp)
{
	nfs_mount *mountp1;
	nfsstat status;
	fhcache *fhc;
	char *path;

	fhc = auth_fh(rqstp, &(argp->from), &status, CHK_WRITE | CHK_NOACCESS);
	if (fhc == NULL)
		return status;
	mountp1 = nfsmount;
	path = fhc->path;

	status = build_path(rqstp, pathbuf_1, &argp->to, CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK)
		return ((int) status);

	Dprintf(D_CALL, "\tpathfrom='%s' pathto='%s'\n", path, pathbuf_1);

	if (nfsmount != mountp1) {
		Dprintf(D_CALL, "\tdenied link between different exports\n");
		return NFSERR_ACCES;
	}

	if (efs_link(path, pathbuf_1) != 0)
		return (nfs_errno());
	return (NFS_OK);
}

int
nfsd_nfsproc_symlink_2(symlinkargs *argp, struct svc_req *rqstp)
{
	nfsstat status;

	status = build_path(rqstp, pathbuf, &argp->from, CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK)
		return ((int) status);

	Dprintf(D_CALL, "\tstring='%s' filename='%s'\n", argp->to, pathbuf);

	if (efs_symlink(argp->to, pathbuf) != 0)
		return (nfs_errno());

	/*
         * NFS version 2 documentation says "On UNIX servers the
	 * attributes are never used...". IMHO, utimes and maybe even
	 * owner may still matter.
         */
#ifndef ALLOW_SGIDDIR
	argp->attributes.gid = -1;
#endif
	status = setattr(pathbuf, &argp->attributes, NULL, rqstp,
				SATTR_CHOWN|SATTR_UTIMES);

	return status;
}

int
nfsd_nfsproc_mkdir_2(createargs *argp, struct svc_req *rqstp)
{
	nfsstat status;
	struct stat sbuf;
	diropokres *res;

	status = build_path(rqstp, pathbuf, &argp->where, CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK)
		return ((int) status);

	Dprintf(D_CALL, "\tfullpath='%s'\n", pathbuf);

	if (efs_mkdir(pathbuf, argp->attributes.mode) != 0)
		return (nfs_errno());

	res = &result.diropres.diropres_u.diropres;
	status = fh_compose(&(argp->where), &(res->file), &sbuf, -1, -1, 0);
	if (status != NFS_OK)
		return ((int) status);

#ifndef ALLOW_SGIDDIR
	argp->attributes.gid = -1;
#endif
	/* Inherit setgid bit from directory */
	argp->attributes.mode |= (sbuf.st_mode & S_ISGID);
	status = setattr(pathbuf, &argp->attributes, &sbuf, rqstp,
				SATTR_CHOWN|SATTR_CHMOD|SATTR_UTIMES);
	if (status != NFS_OK)
		return status;

	/* Note that the spb buffer is now invalid! */
	status = fh_getattr(&(res->file), &(res->attributes), NULL, rqstp);
	if (status == NFS_OK)
		Dprintf(D_CALL, "\tnew_fh = %s\n", fh_pr(&(res->file)));
	return ((int) status);
}

int
nfsd_nfsproc_rmdir_2(diropargs *argp, struct svc_req *rqstp)
{
	nfsstat status;

	status = build_path(rqstp, pathbuf, argp, CHK_WRITE | CHK_NOACCESS);
	if (status != NFS_OK)
		return ((int) status);

	Dprintf(D_CALL, "\tfullpath='%s'\n", pathbuf);

	/* Remove that file handle from our cache. */
	fh_remove(pathbuf);

	if (rmdir(pathbuf) != 0)
		return (nfs_errno());

	return (NFS_OK);
}

/* More Mark Shand code. */
static int
dpsize(struct dirent *dp)
{
#define DP_SLOP	16
#define MAX_E_SIZE sizeof(entry) + NAME_MAX + DP_SLOP
	return (sizeof(entry) + NLENGTH(dp) + DP_SLOP);
}

int
nfsd_nfsproc_readdir_2(readdirargs *argp, struct svc_req *rqstp)
{
	static readdirres oldres;
	entry		**ep, *e;
	__u32		dloc;
	DIR		*dirp;
	struct dirent	*dp;
	struct stat	sbuf;
	int		res_size, dotsonly, hidedot, first;
	fhcache		*h;
	nfsstat		status;
	ino_t		dotinum = 0;

	/* Free the previous result, since it has 'malloc'ed strings.  */
	xdr_free((xdrproc_t) xdr_readdirres, (caddr_t) &oldres);

	h = auth_fh(rqstp, &(argp->dir), &status, CHK_READ);
	if (h == NULL)
		return status;

	/* If the file system is off-limits, just return . and .. to
	 * the client.
	 * There's a little catch here that can screw up clients
	 * relying on inode numbers to be unique (when using non-mangled
	 * inode numbers), which is the inode number of the .. entry.
	 * If the directory is the top-level directory of an NFS export,
	 * and there's no NFS export above it, we return the inode number
	 * of the . entry instead (emulating the file system root, so to
	 * speak).
	 */
	dotsonly = ((!re_export && (h->flags & FHC_NFSMOUNTED))
			|| nfsmount->o.noaccess);
	hidedot  = (nfsmount->parent == NULL
			&& !strcmp(h->path, nfsmount->path));

	/* This code is from Mark Shand's version */
	errno = 0;
	if (efs_lstat(h->path, &sbuf) < 0)
		return (NFSERR_ACCES);
	if (!S_ISDIR(sbuf.st_mode))
		return (NFSERR_NOTDIR);
	if ((dirp = efs_opendir(h->path)) == NULL)
		return ((errno ? nfs_errno() : NFSERR_NAMETOOLONG));

	res_size = 0;
	memcpy(&dloc, argp->cookie, sizeof(dloc));
	if (dloc != 0)
		efs_seekdir(dirp, ntohl(dloc));

	first = 1;
	ep = &(result.readdirres.readdirres_u.reply.entries);
	while ((dp = efs_readdir(dirp)) != NULL) {
		res_size += dpsize(dp);
		if (res_size >= argp->count && !first)
			break;

		/* XXX: This code relies on . coming before .. */
		if (!strcmp(dp->d_name, "..")) {
			if (hidedot)
				dp->d_ino = dotinum;
		} else if (!strcmp(dp->d_name, ".")) {
			dotinum = dp->d_ino;
		} else if (dotsonly) {
			dp = NULL;
			break;
		}

		e = *ep = (entry *) xmalloc(sizeof(entry));
		e->fileid = pseudo_inode(dp->d_ino, sbuf.st_dev);
		e->name = xmalloc(NLENGTH(dp) + 1);
		strcpy(e->name, dp->d_name);
		dloc = htonl(efs_telldir(dirp));
		memcpy(&e->cookie, &dloc, sizeof(nfscookie));
		ep = &e->nextentry;
		first = 0;
	}
	*ep = NULL;
	result.readdirres.readdirres_u.reply.eof = (dp == NULL);
	efs_closedir(dirp);
	oldres = result.readdirres;
	return (result.readdirres.status);
}

/*
 * Only reports free space correctly for the filesystem that the
 * mount point is on.  Actually it will work fine for any file
 * handle (e.g. sub mounts) but the NFS spec calls for root_fh
 * to be used by the client when calling this.
 */
int
nfsd_nfsproc_statfs_2(nfs_fh *argp, struct svc_req *rqstp)
{
	nfsstat status;
	fhcache *fhc;
	char *path;
	struct fs_usage fs;

	fhc = auth_fh(rqstp, argp, &status, CHK_READ | CHK_NOACCESS | CHK_ROOT);
	if (fhc == NULL)
		return status;
	path = fhc->path;

	if (get_fs_usage(path, NULL, &fs) < 0)
		return (nfs_errno());
	result.statfsres.status = NFS_OK;
	result.statfsres.statfsres_u.reply.tsize = 8*1024;
	result.statfsres.statfsres_u.reply.bsize = 512;
	result.statfsres.statfsres_u.reply.blocks = fs.fsu_blocks;
	result.statfsres.statfsres_u.reply.bfree = fs.fsu_bfree;
	result.statfsres.statfsres_u.reply.bavail = fs.fsu_bavail;

	return (NFS_OK);
}

int
main(int argc, char **argv)
{
	char	*auth_file = NULL;
	int	foreground = 0;
	int	nfsport = 0;
	int	failsafe_level = 0;
	int	c;
#ifdef MULTIPLE_SERVERS
	int	i, ncopies = 1;
#endif

	program_name = argv[0];
	chdir("/");

	/* Parse the command line options and arguments. */
	opterr = 0;
	while ((c = getopt_long(argc, argv, shortopts, longopts, NULL)) != EOF)
		switch (c) {
		case 'a':
			auth_daemon = optarg;
			break;
		case 'h':
			usage(stdout, 0);
			break;
		case 'd':
			enable_logging(optarg);
			break;
		case 'F':
			foreground = 1;
			break;
		case 'f':
			auth_file = optarg;
			break;
		case 'l':
			log_transfers = 1;
			break;
		case 'n':
			allow_non_root = 1;
			break;
		case 'P':
			nfsport = atoi(optarg);
			if (nfsport <= 0) {
				fprintf(stderr, "nfsd: bad port number: %s\n",
					optarg);
				usage(stderr, 1);
			}
			break;
		case 'p':
			promiscuous = 1;
			break;
		case 'r':
			re_export = 1;
			break;
		case 'R':
			public_root_path = xstrdup(optarg);
			break;
		case 't':
			trace_spoof = 0;
			break;
		case 'v':
			printf("%s\n", version);
			exit(0);
		case 'x':
			cross_mounts = 0;
			break;
		case 'z':
			if (optarg)
				failsafe_level = atoi(optarg);
			else
				failsafe_level = 1;
			break;
		case 0:
			break;
		case '?':
		default:
			usage(stderr, 1);
		}

#ifdef MULTIPLE_SERVERS
	if (optind == argc-1 && isdigit(argv[optind][0])) {
		ncopies = atoi(argv[optind++]);
		if (ncopies <= 0) {
			fprintf(stderr, 
			    "nfsd: illegal number of servers requested: %s\n",
						argv[optind]);
			exit (1);
		}
		if (foreground) {
			fprintf(stderr, "nfsd: warning: can run only "
					"one server in debug mode\n");
			ncopies = 1;
		}
	}
#endif

	/* No more arguments allowed. */
	if (optind != argc)
		usage(stderr, 1);

	/* Get the default NFS port */
	if (!nfsport) {
		struct servent	*sp;

		if (!(sp = getservbyname("nfs", "udp"))) {
			nfsport = NFS_PORT;
		} else {
			nfsport = ntohs(sp->s_port);
		}
	}

	/* Initialize logging. */
	log_open("nfsd", foreground);

	/* Initialize RPC stuff */
	rpc_init("nfsd", NFS_PROGRAM, nfsd_versions, nfs_dispatch,
				nfsport, NFS_MAXDATA);

	/* No more than 1 copy when run from inetd */
	if (_rpcpmstart && ncopies > 1) {
		Dprintf(L_WARNING,
				"nfsd: warning: can run only "
				"one server in inetd mode\n");
		ncopies = 1;
	}

#ifndef MULTIPLE_SERVERS_READWRITE
	if (ncopies > 1)
		read_only = 1;
#endif

	/* We first fork off a child. */
	if (!foreground) {
		if ((c = fork()) > 0)
			exit(0);
		if (c < 0) {
			Dprintf(L_FATAL, "nfsd: cannot fork: %s\n",
						strerror(errno));
		}
	}

	/* Initialize the AUTH module. */
	auth_init(auth_file);

	if (failsafe_level == 0) {
		/* Start multiple copies of the server */
		for (i = 1; i < ncopies; i++) {
			Dprintf(D_GENERAL, "Forking server thread...\n");
			if ((c = fork()) < 0) {
				Dprintf(L_ERROR, "Unable to fork: %s",
					strerror(errno));
			} else if (c == 0) {
				/* Child process */
				break;
			}
		}
	} else {
		/* Init for failsafe mode */
		failsafe(failsafe_level, ncopies);
	}

	/* Now that we've done all the required forks, we make do all the
	 * session magic.
	 */
	if (!foreground) {
		/* No more logging to stderr */
		background_logging();

		/* Now we remove ourselves from the foreground. */
		close(0);
		close(1);
		close(2);
#ifdef HAVE_SETSID
		setsid();
#else
		{
			int fd;
	
			if ((fd = open("/dev/tty", O_RDWR)) >= 0) {
				ioctl(fd, TIOCNOTTY, (char *) NULL);
				close(fd);
			}
		}
#endif
	}

	/*
	 * Initialize file system extension (if any)
	 */
	efs_init();

	/*
	 * Initialize the FH module.
	 * This must happen after the fork(), otherwise the alarm timer
	 * will be reset.
	 */
	fh_init();

	/*
	 * If we have a public root, build the FH now.
	 */
	if (public_root_path) {
		if (fh_create(&public_root, public_root_path) != 0) {
			Dprintf(L_ERROR,
				"%s: Can't build public root FH\n",
				public_root_path);
			free(public_root_path);
			public_root_path = 0;
		}
	}


	/* Enable the LOG toggle with a signal. */
	install_signal_handler(SIGUSR1, toggle_logging);
#ifdef CALL_PROFILING
	install_signal_handler(SIGIOT,  dump_stats);
#endif
	install_signal_handler(SIGHUP,  reinitialize);
	install_signal_handler(SIGTERM, sigterm);
	atexit(terminate);

	/* Run the NFS server. */
	svc_run();

	Dprintf(L_ERROR, "Oh no Mr. Bill... nfs_server() returned!\n");
	exit(1);
}

static void
usage(FILE *fp, int n)
{
	fprintf(fp,
"Usage: %s [-Fhnpv] [-d kind] [-f exports-file] [-P port] [--version]\n"
"       [--debug kind] [--exports-file=file] [--port port]\n"
"       [--allow-non-root] [--promiscuous] [--version] [--foreground]\n"
"       [--re-export] [--log-transfers] [--public-root path]\n"
"       [--no-spoof-trace] [--help]\n"
						, program_name);
	exit(n);
}

static RETSIGTYPE
sigterm(int sig)
{
	/* marked as atexit--don't need to call:
	terminate();
	 */
	exit(1);
}

static void
terminate(void)
{
	rpc_exit(NFS_PROGRAM, nfsd_versions);
	efs_shutdown();
}

RETSIGTYPE reinitialize(sig)
{
	static volatile int	inprogress = 0;

	if (_rpcsvcdirty) {
		need_reinit = 1;
		return;
	}
	if (inprogress++)	/* Probably non-atomic. Yuck */
		return;
	auth_override_uid(0);	/* May need root privs to read exports */
	fh_flush(1);
	auth_init(NULL);	/* auth_init saves the exports file name */
	inprogress = 0;
	need_reinit = 0;
}

