/*
 * rquota.h		XDR and RPC stuff for the RPC quota service.
 *
 */

#ifndef RQUOTA_H
#define RQUOTA_H

#define RQ_PATHLEN 1024

typedef struct getquota_args {
	char *		gqa_pathp;
	int		gqa_uid;
} getquota_args;


typedef struct rquota {
	int		rq_bsize;
	bool_t		rq_active;
	u_int		rq_bhardlimit;
	u_int		rq_bsoftlimit;
	u_int		rq_curblocks;
	u_int		rq_fhardlimit;
	u_int		rq_fsoftlimit;
	u_int		rq_curfiles;
	u_int		rq_btimeleft;
	u_int		rq_ftimeleft;
} rquota;


typedef enum gqr_status {
	Q_OK		= 1,
	Q_NOQUOTA	= 2,
	Q_EPERM		= 3,
} gqr_status;


typedef struct getquota_rslt {
	gqr_status status;
	union {
		rquota gqr_rquota;
	} getquota_rslt_u;
} getquota_rslt;


#define RQUOTAPROG ((u_long)100011)
#define RQUOTAVERS ((u_long)1)
#define RQUOTAPROC_GETQUOTA ((u_long)1)
#define RQUOTAPROC_GETACTIVEQUOTA ((u_long)2)

bool_t	xdr_getquota_args(XDR *, getquota_args *);
bool_t	xdr_rquota(XDR *, rquota *);
bool_t	xdr_gqr_status(XDR *, gqr_status *);
bool_t	xdr_getquota_rslt(XDR *, getquota_rslt *);

#endif /* RQUOTA_H */
