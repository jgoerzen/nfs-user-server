/*
 * mountd.h	This program implements a user-space NFS server.
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

#ifndef MOUNTD_H
#define MOUNTD_H

#include "system.h"
#include "mount.h"
#include "nfs_prot.h"
#include "extensions.h"

#define MOUNT_PORT 0

union argument_types {
	dirpath			dirpath;
};

union result_types {
	fhstatus		fstatus;
	mountlist		mountlist;
	exports			exports;
	ppathcnf		pathconf;
};

/* Global variables. */
extern union argument_types	argument;
extern union result_types	result;
extern int			need_reinit;
extern int			need_flush;

/* Include the other module definitions. */
#include "auth.h"
#include "fh.h"
#include "logging.h"

/* Global Function prototypes. */
extern void		mount_dispatch(struct svc_req *, SVCXPRT *);
extern RETSIGTYPE	reinitialize(int sig);

/* This is obsolete as we now ship the generated files */
#if 0 && !defined(HAVE_RPCGEN_C)
#define mountproc_null_1_svc		mountproc_null_1
#define mountproc_mnt_1_svc		mountproc_mnt_1
#define mountproc_dump_1_svc		mountproc_dump_1
#define mountproc_umnt_1_svc		mountproc_umnt_1
#define mountproc_umntall_1_svc		mountproc_umntall_1
#define mountproc_export_1_svc		mountproc_export_1
#define mountproc_exportall_1_svc	mountproc_exportall_1
#endif

/* End of mountd.h. */
#endif /* MOUNTD_H */
