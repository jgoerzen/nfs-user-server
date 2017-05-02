/*
 * rquotad	Authenticate rquota requests and retrieve file handle.
 *
 * Copyright (C) 1995 Olaf Kirch <okir@monad.swb.de>
 */

#include <signal.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/vfs.h>
#include <stdio.h>
#include <paths.h>
#include <mntent.h>
#include "rquotad.h"
#include "logging.h"
#include "rpcmisc.h"

#ifndef _PATH_MTAB
#define _PATH_MTAB	"/etc/mtab"
#endif

#ifdef HAVE_QUOTACTL
static char *	getdevice(char *path);
#endif
static void	usage(int exitcode);

static struct option longopts[] =
{
	{ "foreground", 0, 0, 'F' },
	{ "debug", 1, 0, 'd' },
	{ "help", 0, 0, 'h' },
	{ "version", 0, 0, 'v' },
	{ NULL, 0, 0, 0 }
};

bool_t
rquota_null_1_svc(struct svc_req *rqstp, void *argp, void *resp)
{
	return 1;
}

#ifdef HAVE_QUOTACTL
bool_t
rquota_getquota_1_svc(struct svc_req *rqstp, getquota_args *argp,
					     getquota_rslt *resp)
{
	struct sockaddr_in *sin = svc_getcaller(rqstp->rq_xprt);
	char		*special;
	struct dqblk	qtinfo;
	struct statfs	fsinfo;
	struct rquota	rqot;
	uid_t		uid = (uid_t) argp->gqa_uid;

	/* The rquota.x file suggests that AUTH_UNIX be required;
	 * but since UNIX credentials can't be trusted much anyway,
	 * we use simple port checking.
	 */
	if (!SECURE_PORT(sin->sin_port)) {
		resp->status = Q_EPERM;
		return 1;
	}

	resp->status = Q_NOQUOTA;
	if (!(special = getdevice(argp->gqa_pathp)))
		return 1;

	if (statfs(argp->gqa_pathp, &fsinfo) < 0
	 || quotactl(QCMD(Q_GETQUOTA, USRQUOTA), special, uid, &qtinfo) < 0)
		return 1;

	rqot = &resp->getquota_rslt_u.gqr_rquota;
	rqot->status	    = Q_OK;
	rqot->rq_bsize	    = fsinfo.f_bsize;
	rqot->rq_active	    = 1;		/* always active */
	rqot->rq_bhardlimit = qtinfo.dqb_bhardlimit;
	rqot->rq_bsoftlimit = qtinfo.dqb_bsoftlimit;
	rqot->rq_curblocks  = qtinfo.dqb_curblocks;
	rqot->rq_fhardlimit = qtinfo.dqb_fhardlimit;
	rqot->rq_fsoftlimit = qtinfo.dqb_fsoftlimit;
	rqot->rq_curfiles   = qtinfo.dqb_curfiles;
	rqot->rq_btimeleft  = qtinfo.dqb_btimeleft;
	rqot->rq_ftimeleft  = qtinfo.dqb_ftimeleft;

	return 1;
}
#else
bool_t
rquota_getquota_1_svc(struct svc_req *rqstp, getquota_args *argp,
					     getquota_rslt *resp)
{
	resp->status = Q_NOQUOTA;
	return 1;
}
#endif

bool_t
rquota_getactivequota_1_svc(struct svc_req *rqstp, getquota_args *argp,
						   getquota_rslt *resp)
{
	/* What's the difference between these two? */
	return rquota_getquota_1_svc(rqstp, argp, resp);
}

int
main(int argc, char **argv)
{
	int	foreground = 0;
	int	c;

	rpc_init("rquotad", RQUOTAPROG, RQUOTAVERS, rquota_dispatch, 0, 0);

	/* Parse the command line options and arguments. */
	opterr = 0;
	while ((c = getopt_long(argc, argv, "Fd:hv", longopts, NULL)) != EOF) {
		switch (c) {
		case 'F':
			foreground = 1;
			break;
		case 'd':
			enable_logging(optarg);
			break;
		case 'h':
			usage(0);
			break;
		case 'v':
			printf("rquotad %s\n", VERSION);
			exit(0);
		case 0:
			break;
		case '?':
		default:
			usage(1);
		}
	}

	/* No more arguments allowed. */
	if (optind != argc)
		usage(1);

	if (!foreground) {
		/* We first fork off a child. */
		if ((c = fork()) > 0)
			exit(0);
		if (c < 0) {
			Dprintf(L_FATAL, "rquotad: cannot fork: %s\n",
						strerror(errno));
		}
		/* Now we remove ourselves from the foreground. */
		close(0);
		close(1);
		close(2);
		setsid();
	}

	/* Initialize logging. */
	log_open("rquotad", foreground);

	svc_run();

	Dprintf(L_ERROR, "Ack! Gack! svc_run returned!\n");
	exit(1);
}

#ifdef HAVE_QUOTACTL
static char *
getdevice(char *path)
{
	static char	special[PATH_MAX];
	struct mntent	*mnt;
	FILE		*fp;
	int		mlen, plen;

	if (!(fp = setmntent(_PATH_MTAB, "r")))
		return NULL;
	
	special[0] = '\0';
	mlen = 0;
	while ((mnt = getmntent(fp)) != NULL) {
		plen = strlen(mnt->mnt_dir);
		if (!strncmp(mnt->mnt_dir, path, plen) && plen > mlen) {
			strcpy(special, mnt->mnt_dir);
			mlen = plen;
		}
		if (path[plen] == '\0')
			break;
	}

	endmntent(fp);

	return mlen? special : NULL;
}
#endif

static void
usage(int n)
{
	fprintf(stderr,
		"Usage: rpc.rquotad [-Fhnpv] [-d kind]\n"
		"       [--debug kind] [--help] [--version]\n");
	exit(n);
}
