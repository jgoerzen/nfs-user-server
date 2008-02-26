/*
 * dispatch.c	This file contains the function dispatch table.
 *
 * Authors:	Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		This software may be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "mountd.h"
#include "rpcmisc.h"
#include "haccess.h"

/*
 * These are the global variables that hold all argument and result data.
 */
union argument_types 	argument;
union result_types	result;

/*
 * MOUNT versions supported by this implementation
 */
#define	MAXVERS		2

/*
 * This is a dispatch table to simplify error checking,
 * and supply return attributes for NFS functions.
 */

#ifdef __STDC__
#define CONCAT(a,b)		a##b
#define CONCAT3(a,b,c)		a##b##c
#define CONCAT5(a,b,c,d,e)	a##b##c##d##e
#define STRING(a)		#a
#else
#define CONCAT(a,b)		a/**/b
#define CONCAT3(a,b,c)		a/**/b/**/c
#define CONCAT5(a,b,c,d,e)	a/**/b/**/c/**/d/**/e
#define STRING(a)		"a"
#endif

#define table_ent(vers, res_type, arg_type, funct) {		\
	sizeof(res_type), sizeof(arg_type),			\
	(xdrproc_t) CONCAT(xdr_,res_type),			\
	(xdrproc_t) CONCAT(xdr_,arg_type),			\
	(void *(*)()) CONCAT5(mountproc_,funct,_,vers,_svc),	\
	STRING(funct), CONCAT(pr_,arg_type)			\
}

#define nil	void
#define xdr_nil	xdr_void
#define pr_nil	pr_void
#define pr_char	pr_void

struct dispatch_entry {
    int		res_size, arg_size;	/* sizeof the res/arg structs	*/
    xdrproc_t	xdr_result;
    xdrproc_t	xdr_argument;
    void	*(*funct)();		/* function handler		*/
    char	*name;			/* name of function		*/
    char	*(*log_print)();	/* ptr to debug handler		*/
};

static char *	pr_void(void);
static char *	pr_dirpath(dirpath *argp);

static struct dispatch_entry mount_1_table[] = {
	table_ent(1,nil,nil,null),			/* NULL */
	table_ent(1,fhstatus,dirpath,mnt),		/* MNT */
	table_ent(1,mountlist,void,dump),		/* DUMP */
	table_ent(1,void,dirpath,umnt),			/* UMNT */
	table_ent(1,void,void,umntall),			/* UMNTALL */
	table_ent(1,exports,void,export),		/* EXPORT */
	table_ent(1,exports,void,exportall),		/* EXPORTALL */
};

/* We cheat here and use version #1 for all except pathconf */
static struct dispatch_entry mount_2_table[] = {
	table_ent(1,nil,nil,null),			/* NULL */
	table_ent(1,fhstatus,dirpath,mnt),		/* MNT */
	table_ent(1,mountlist,void,dump),		/* DUMP */
	table_ent(1,void,dirpath,umnt),			/* UMNT */
	table_ent(1,void,void,umntall),			/* UMNTALL */
	table_ent(1,exports,void,export),		/* EXPORT */
	table_ent(1,exports,void,exportall),		/* EXPORTALL */
	table_ent(2,ppathcnf,dirpath,pathconf),		/* PATHCONF */
};

static struct dispatch_entry * dtable[MAXVERS] = {
	mount_1_table,
	mount_2_table,
};

static unsigned int		dtnrprocs[MAXVERS] = {
	sizeof(mount_1_table) / sizeof(mount_1_table[0]),
	sizeof(mount_2_table) / sizeof(mount_2_table[0]),
};

/*
 * The main dispatch routine.
 */
void
mount_dispatch(struct svc_req *rqstp, SVCXPRT *transp)
{
	unsigned int		proc_index, vers_index;
	struct dispatch_entry	*dtbl, *dent;
	union result_types	*resp;
	struct sockaddr_in	*sin;

	sin = (struct sockaddr_in *) svc_getcaller(transp);
	if (!client_checkaccess("rpc.mountd", sin, 0))
		goto done;

	proc_index = rqstp->rq_proc;
	vers_index = rqstp->rq_vers - 1;
	_rpcsvcdirty = 1;

	if (vers_index >= MAXVERS) {
		svcerr_progvers(transp, 1, MAXVERS);
		goto done;
	}
	if (proc_index >= dtnrprocs[vers_index]) {
		svcerr_noproc(transp);
		goto done;
	}
	dtbl = dtable[vers_index];
	dent = &dtbl[proc_index];

	memset(&argument, 0, dent->arg_size);
	if (!svc_getargs(transp, (xdrproc_t) dent->xdr_argument, (caddr_t) &argument)) {
		svcerr_decode(transp);
		goto done;
	}
	/* Clear the result structure. */
	memset(&result, 0, dent->res_size);

	/* Log the call. */
	if (logging_enabled(D_CALL))
		log_call(rqstp, dent->name, dent->log_print(&argument));

	/* Do the function call itself. */
	resp = (*dent->funct) (&argument, rqstp);

	if (!svc_sendreply(transp, dent->xdr_result, (caddr_t) resp)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, (xdrproc_t) dent->xdr_argument, (caddr_t) &argument)) {
		Dprintf(L_ERROR, "unable to free RPC arguments, exiting\n");
		exit(1);
	}

done:
	_rpcsvcdirty = 0;
	if (need_reinit) {
		reinitialize(0);
	}
}

/*
 * Functions for debugging output.
 */
static char *pr_void()
{
	return ("");
}

static char *pr_dirpath(argp)
dirpath *argp;
{
	return (*argp);
}

