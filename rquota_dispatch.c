/*
 * rquota_dispatch	This file contains the function dispatch table.
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

#include "rquotad.h"
#include "logging.h"
#include "rpcmisc.h"

/*
 * These are the global variables that hold all argument and result data.
 */
union rquotad_arguments argument;
union rquotad_results	result;

/*
 * This is a dispatch table to simplify error checking,
 * and supply return attributes for NFS functions.
 */

#ifdef __STDC__
#define CONCAT(a,b)	a##b
#define CONCAT3(a,b,c)	a##b##c
#define STRING(a)	#a
#else
#define CONCAT(a,b)	a/**/b
#define CONCAT3(a,b,c)	a/**/b/**/c
#define STRING(a)	"a"
#endif

#define table_ent(res_type, arg_type, funct) {			\
	sizeof(res_type), sizeof(arg_type),			\
	(xdrproc_t) CONCAT(xdr_,res_type),			\
	(xdrproc_t) CONCAT(xdr_,arg_type),			\
	(void *(*)()) CONCAT3(rquota_,funct,_1_svc),	\
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

static _PRO(char *pr_void, (void)					);
static _PRO(char *pr_getquota_args, (getquota_args *argp)		);

static struct dispatch_entry dtable[] = {
	table_ent(nil,nil,null),			/* NULL */
	table_ent(getquota_rslt,getquota_args,getquota),/* GETQUOTA */
	table_ent(getquota_rslt,getquota_args,getactivequota),
							/* GETACTIVEQUOTA */
};


/*
 * The main dispatch routine.
 */
void rquota_dispatch(rqstp, transp)
struct svc_req *rqstp;
SVCXPRT *transp;
{
	unsigned int		proc_index;
	struct dispatch_entry	*dent;
	union rquotad_results	*resp;

	proc_index = rqstp->rq_proc;
	_rpcsvcdirty = 1;

	if (proc_index >= (sizeof(dtable) / sizeof(dtable[0]))) {
		svcerr_noproc(transp);
		goto done;
	}
	dent = &dtable[proc_index];

	memset(&argument, 0, dent->arg_size);
	if (!svc_getargs(transp, dent->xdr_argument, &argument)) {
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
	if (!svc_freeargs(transp, dent->xdr_argument, &argument)) {
		Dprintf(L_ERROR, "unable to free RPC arguments, exiting\n");
		exit(1);
	}

done:
	_rpcsvcdirty = 0;
}

/*
 * Functions for debugging output.
 */
static char *pr_void()
{
	return ("");
}

static char *pr_getquota_args(argp)
getquota_args *argp;
{
	static char	buf[1200];
	char		*path = argp->gqa_pathp;

	if (strlen(path) > 1024) {
		Dprintf(L_WARNING, "giant pathname in getquota call: %s\n",
			path);
		path = "<giant path>";
	}
	sprintf(buf, "uid %d path %s", argp->gqa_uid, path);
	return buf;
}

