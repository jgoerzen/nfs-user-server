/*
 * rquotad.h	This program implements a user-space NFS server.
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

#ifndef RQUOTAD_H
#define RQUOTAD_H

#include <rpc/rpc.h>
#include <rpc/svc.h>
#include <rpcsvc/nfs_prot.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "system.h"
#include "getopt.h"
#include "rquota.h"

#define VERSION		"ver 0.1 for unfsd"

union rquotad_arguments {
	getquota_args		args;
};

union rquotad_results {
	getquota_rslt		rslt;
};

/*
 * Global Function prototypes.
 */
bool_t	rquota_null_1_svc(struct svc_req *, void *, void *);
bool_t	rquota_getquota_1_svc(struct svc_req *, getquota_args *,
					getquota_rslt *);
bool_t	rquota_getactivequota_1_svc(struct svc_req *, getquota_args *,
					getquota_rslt *);
void	rquota_dispatch(struct svc_req *rqstp, SVCXPRT *transp);


#endif /* RQUOTAD_H */
