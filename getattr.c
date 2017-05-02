/*
 * getattr	This module handles the NFS attributes.
 *
 * Authors:	Mark A. Shand, May 1988
 *		Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "nfsd.h"

/*
 * The NFS version 2 specification fails to mention all of
 * these file types, but they exist in the nfs_prot.x file.
 */
#define ftype_map(st_mode) (_ftype_map[((st_mode) & S_IFMT) >> 12])

ftype _ftype_map[16] =
{
#ifdef S_IFIFO
	NFNON, NFFIFO, NFCHR, NFBAD,
#else
	NFNON, NFBAD, NFCHR, NFBAD,
#endif
	NFDIR, NFBAD, NFBLK, NFBAD,
	NFREG, NFBAD, NFLNK, NFBAD,
	NFSOCK, NFBAD, NFBAD, NFBAD,
};

/*
 * Get file attributes based on file handle
 */
nfsstat fh_getattr(fh, attr, stat_optimize, rqstp)
nfs_fh		*fh;
fattr		*attr;
struct stat	*stat_optimize;
struct svc_req	*rqstp;
{
	fhcache *fhc;

	if ((fhc = fh_find((svc_fh*)fh, FHFIND_FEXISTS)) == NULL) {
		Dprintf(D_CALL, "getattr: failed! No such file.\n");
		return (NFSERR_STALE);
	}
	return fhc_getattr(fhc, attr, stat_optimize, rqstp);
}

/*
 * Get file attributes given the path.
 */
nfsstat fhc_getattr(fhc, attr, stat_optimize, rqstp)
fhcache		*fhc;
fattr		*attr;
struct stat	*stat_optimize;
struct svc_req	*rqstp;
{
#ifdef DEBUG
	char buff[1024];
	char *sp;
#endif
	/* nfsstat status; */
	struct stat *s;
	struct stat sbuf;

	if (stat_optimize != NULL
	 && stat_optimize->st_nlink != 0)
		s = stat_optimize;
	else if (efs_lstat(fhc->path, (s = &sbuf)) != 0) {
		Dprintf(D_CALL, "getattr(%s): failed!  errno=%d\n", 
			fhc->path, errno);
		return nfs_errno();
	}
	attr->type = ftype_map(s->st_mode);
	attr->mode = s->st_mode;
	attr->nlink = s->st_nlink;
	attr->uid = ruid(s->st_uid, nfsmount, rqstp);
	attr->gid = rgid(s->st_gid, nfsmount, rqstp);

	/* Some applications need the exact symlink size */
#if defined(S_ISLNK)
	if (S_ISLNK(s->st_mode))
		attr->size = MIN(s->st_size, NFS_MAXPATHLEN);
	else
#endif
		attr->size = s->st_size;
#ifdef HAVE_ST_BLKSIZE
	attr->blocksize = s->st_blksize;
#else /* !HAVE_ST_BLKSIZE */
#ifdef BUFSIZ
	attr->blocksize = BUFSIZ;
#else /* BUFSIZ */
	attr->blocksize = 1024;
#endif /* !BUFSIZ */
#endif /* !HAVE_ST_BLKSIZE */
	attr->rdev = s->st_rdev;
#ifdef HAVE_ST_BLOCKS
	attr->blocks = s->st_blocks;
#else
	attr->blocks = st_blocks(s);
#endif
#if 0
	if (nfsmount->o.cross_mounts) {
		attr->fsid = 1;
		attr->fileid = fh_psi((nfs_fh *)&(fhc->h));
	} else {
		attr->fsid = s->st_dev;
		attr->fileid = covered_ino(fhc->path);
	}
#else
	attr->fsid   = 1;
	attr->fileid = fh_psi((nfs_fh *)&(fhc->h));
#endif
	attr->atime.seconds = s->st_atime;
	attr->atime.useconds = 0;
	attr->mtime.seconds = s->st_mtime;
	attr->mtime.useconds = 0;
	attr->ctime.seconds = s->st_ctime;
	attr->ctime.useconds = 0;

#ifdef DEBUG
	sp = buff;
	sprintf(sp, " t=%d, m=%o, lk=%d, u/g=%d/%d, sz=%d, bsz=%d",
		attr->type, attr->mode, attr->nlink,
		attr->uid, attr->gid, attr->size,
		attr->blocksize);
	sp += strlen(sp);
	if (attr->type == NFCHR || attr->type == NFBLK) {
		sprintf(sp, " rdev=%d/%d", (attr->rdev >> 8) & 0xff, attr->rdev & 0xff);
		sp += strlen(sp);
		sprintf(sp, "\n  blks=%d, fsid=%d, psi=%d, at=%d, mt=%d, ct=%d\n",
			attr->blocks, attr->fsid, attr->fileid,
			attr->atime.seconds,
			attr->mtime.seconds,
			attr->ctime.seconds);
		sp += strlen(sp);
	}
	Dprintf(D_CALL, "%s", buff);
#endif

	return (NFS_OK);
}
