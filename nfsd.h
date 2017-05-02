/*
 * nfsd.h	This program implements a user-space NFS server.
 *
 * Authors:	Mark A. Shand, May 1988
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "system.h"

#include "mount.h"
#include "nfs_prot.h"
#include "extensions.h"

union argument_types {
	nfs_fh			nfsproc_getattr_2_arg;
	sattrargs		nfsproc_setattr_2_arg;
	diropargs		nfsproc_lookup_2_arg;
	nfs_fh			nfsproc_readlink_2_arg;
	readargs		nfsproc_read_2_arg;
	writeargs		nfsproc_write_2_arg;
	createargs		nfsproc_create_2_arg;
	diropargs		nfsproc_remove_2_arg;
	renameargs		nfsproc_rename_2_arg;
	linkargs		nfsproc_link_2_arg;
	symlinkargs		nfsproc_symlink_2_arg;
	createargs		nfsproc_mkdir_2_arg;
	diropargs		nfsproc_rmdir_2_arg;
	readdirargs		nfsproc_readdir_2_arg;
	nfs_fh			nfsproc_statfs_2_arg;
};

union result_types {
	attrstat		attrstat;
	diropres		diropres;
	readlinkres		readlinkres;
	readres			readres;
	nfsstat			nfsstat;
	readdirres		readdirres;
	statfsres		statfsres;
};

/* Global variables. */
extern union argument_types	argument;
extern union result_types	result;
extern int			need_reinit;
extern int			need_flush;
extern time_t			nfs_dispatch_time;

/* Include the other module definitions. */
#include "auth.h"
#include "fh.h"
#include "logging.h"

/* Global Function prototypes. */
extern void	nfs_dispatch(struct svc_req *, SVCXPRT *);
extern void	mallocfailed(void);
extern nfsstat	fh_getattr(nfs_fh *fh, fattr *attr,
					struct stat *stat_optimize,
					struct svc_req *rqstp);
extern nfsstat	fhc_getattr(fhcache *fhc, fattr *attr,
					struct stat *stat_optimize,
					struct svc_req *rqstp);
extern nfsstat	fh_setattr(nfs_fh *fh, sattr *attr,
					struct stat *stat_optimize,
					struct svc_req *, int flags);
extern nfsstat	setattr(char *path, sattr *attr,
					struct stat *stat_optimize,
					struct svc_req *, int flags);
extern RETSIGTYPE reinitialize(int sig);

#define SATTR_STAT		0x01
#define SATTR_CHOWN		0x02
#define SATTR_CHMOD		0x04
#define SATTR_SIZE		0x08
#define SATTR_UTIMES		0x10
#define SATTR_ALL		(~SATTR_STAT)

#ifndef HAVE_REALPATH
extern char *	realpath(const char *path, char *resolved_path);
#endif /* HAVE_REALPATH */

#ifndef HAVE_STRERROR
extern char *	strerror(int errnum);
#endif /* HAVE_STRERROR */

extern int nfsd_nfsproc_null_2(void *, struct svc_req *);
extern int nfsd_nfsproc_getattr_2(nfs_fh *, struct svc_req *);
extern int nfsd_nfsproc_setattr_2(sattrargs *, struct svc_req *);
extern int nfsd_nfsproc_root_2(void *, struct svc_req *);
extern int nfsd_nfsproc_lookup_2(diropargs *, struct svc_req *);
extern int nfsd_nfsproc_readlink_2(nfs_fh *, struct svc_req *);
extern int nfsd_nfsproc_read_2(readargs *, struct svc_req *);
extern int nfsd_nfsproc_writecache_2(void *, struct svc_req *);
extern int nfsd_nfsproc_write_2(writeargs *, struct svc_req *);
extern int nfsd_nfsproc_create_2(createargs *, struct svc_req *);
extern int nfsd_nfsproc_remove_2(diropargs *, struct svc_req *);
extern int nfsd_nfsproc_rename_2(renameargs *, struct svc_req *);
extern int nfsd_nfsproc_link_2(linkargs *, struct svc_req *);
extern int nfsd_nfsproc_symlink_2(symlinkargs *, struct svc_req *);
extern int nfsd_nfsproc_mkdir_2(createargs *, struct svc_req *);
extern int nfsd_nfsproc_rmdir_2(diropargs *, struct svc_req *);
extern int nfsd_nfsproc_readdir_2(readdirargs *, struct svc_req *);
extern int nfsd_nfsproc_statfs_2(nfs_fh *, struct svc_req *);

/* End of nfsd.h. */
