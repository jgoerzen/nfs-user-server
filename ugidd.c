/* UNFSD - copyright Mark A Shand, May 1988.
 * This software maybe be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 *
 * Authors:	Mark A. Shand
 *		Olaf Kirch <okir@monad.swb.de>
 */

#include "site.h"

/* Only compile ugidd if nfs server has support for it. */
#ifdef ENABLE_UGID_DAEMON

#include "system.h"
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include "ugid.h"
#include "logging.h"
#include "haccess.h"
#include "rpcmisc.h"
#include "signals.h"
#ifdef HAVE_LIBWRAP_BUG
#include <syslog.h>
#endif


static void	ugidprog_1(struct svc_req *rqstp, SVCXPRT *transp);
static void	usage(void);
static void	terminate(void);
static RETSIGTYPE sigterm(int sig);

#ifndef HAVE_RPCGEN_C
#define authenticate_1_svc	authenticate_1
#define name_uid_1_svc		name_uid_1
#define group_gid_1_svc		group_gid_1
#define uid_name_1_svc		uid_name_1
#define gid_group_1_svc		gid_group_1
#endif


static struct option longopts[] = {
	{ "debug", 0, 0, 'd' },
	{ "port", required_argument, 0, 'P' },
	{ NULL, 0, 0, 0 }
};

static int ugidd_versions[] = {
	UGIDVERS,
	0
};

int
main(argc, argv)
int	argc;
char	**argv;
{
	int	c, longind;
	int	foreground = 0;
	int	port = 0;

#ifndef HOSTS_ACCESS
	fprintf(stderr,
		"\n *** WARNING: This copy of ugidd has been compiled without\n"
		" *** support for host_access checking. This is very risky.\n"
		" *** Please consider recompiling it with access checking.\n");
	sleep(1);
#endif

	chdir("/");

	while ((c = getopt_long(argc, argv, "dP:", longopts, &longind)) != EOF) {
		switch (c) {
		case 'd':
			foreground = 1;
			enable_logging("ugid");
			break;
		case 'P':
			port = atoi(optarg);
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "ugidd: bad port number: %s\n",
					optarg);
				usage();
			}
			break;
		default:
			usage();
		}
	}

	log_open("ugidd", foreground);

	/* Create services and register with portmapper */
	_rpcfdtype = SOCK_DGRAM;
	rpc_init("ugidd", UGIDPROG, ugidd_versions, ugidprog_1, port, 0);

	if (!foreground && !_rpcpmstart) {
		if ((c = fork()) > 0)
			exit(0);
		if (c < 0) {
			fprintf(stderr, "ugidd: cannot fork: %s\n",
						strerror(errno));
			exit(-1);
		}
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

	install_signal_handler(SIGTERM, sigterm);
	atexit(terminate);

	svc_run();
	Dprintf(L_ERROR, "svc_run returned\n");
	return 1;
}

static void
usage()
{
	fprintf(stderr, "rpc.ugidd: [-d] [-P port]\n");
	exit (2);
}

static void
ugidprog_1(struct svc_req *rqstp, SVCXPRT *transp)
{
	union {
		int authenticate_1_arg;
		ugname name_uid_1_arg;
		ugname group_gid_1_arg;
		int uid_name_1_arg;
		int gid_group_1_arg;
	} argument;
	char		*result;
	xdrproc_t	xdr_argument, xdr_result;
	char		*(*local)();

	if (!client_checkaccess("rpc.ugidd", svc_getcaller(transp), 1))
		return;

	switch (rqstp->rq_proc) {
	case NULLPROC:
		svc_sendreply(transp, (xdrproc_t) xdr_void, (char *) NULL);
		return;

	case AUTHENTICATE:
		xdr_argument = (xdrproc_t) xdr_int;
		xdr_result   = (xdrproc_t) xdr_int;
		local = (char *(*)()) authenticate_1_svc;
		break;

	case NAME_UID:
		xdr_argument = (xdrproc_t) xdr_ugname;
		xdr_result   = (xdrproc_t) xdr_int;
		local = (char *(*)()) name_uid_1_svc;
		break;

	case GROUP_GID:
		xdr_argument = (xdrproc_t) xdr_ugname;
		xdr_result = (xdrproc_t) xdr_int;
		local = (char *(*)()) group_gid_1_svc;
		break;

	case UID_NAME:
		xdr_argument = (xdrproc_t) xdr_int;
		xdr_result = (xdrproc_t) xdr_ugname;
		local = (char *(*)()) uid_name_1_svc;
		break;

	case GID_GROUP:
		xdr_argument = (xdrproc_t) xdr_int;
		xdr_result = (xdrproc_t) xdr_ugname;
		local = (char *(*)()) gid_group_1_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	bzero((char *)&argument, sizeof(argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t) &argument)) {
		svcerr_decode(transp);
		return;
	}
	result = (*local)(&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t) &argument)) {
		(void)fprintf(stderr, "unable to free arguments\n");
		exit(1);
	}
}

int *
authenticate_1_svc(argp, rqstp)
	int *argp;
	struct svc_req *rqstp;
{
	static int res;
	int	s;
	struct sockaddr_in	sendaddr, destaddr;
	int	dummy;
	short	lport;

	bzero(&res, sizeof res);
	destaddr = *svc_getcaller(rqstp->rq_xprt);
	destaddr.sin_port = htons(*argp);
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		goto bad;
	setsockopt(s, SOL_SOCKET, SO_LINGER, 0, 0);
	bzero((char *) &sendaddr, sizeof sendaddr);
	/* find a reserved port */
	lport = IPPORT_RESERVED - 1;
	sendaddr.sin_family = AF_INET;
	sendaddr.sin_addr.s_addr = INADDR_ANY;
	for (;;)
	{
		sendaddr.sin_port = htons((u_short)lport);
		if (bind(s, (struct sockaddr *)&sendaddr, sizeof sendaddr) >= 0)
			break;
		if (errno != EADDRINUSE && EADDRNOTAVAIL)
			goto bad;
		lport--;
		if (lport <= IPPORT_RESERVED / 2)
			/* give up */
			break;
	}
	if (sendto(s, &dummy, sizeof dummy, 0,
			(struct sockaddr *)&destaddr, sizeof destaddr) < 0)
		goto bad;

	close(s);
	res = 0;
	return (&res);
    bad:
	close(s);
	res = errno == 0 ? -1 : errno;
	return (&res);
}

int *
name_uid_1_svc(argp, rqstp)
	ugname *argp;
	struct svc_req *rqstp;
{
	static int res;
	struct passwd	*pw;

	bzero(&res, sizeof(res));
	if ((pw = getpwnam(*argp)) == NULL)
		res = NOBODY;
	else
		res = pw->pw_uid;

	return (&res);
}


int *
group_gid_1_svc(argp, rqstp)
	ugname *argp;
	struct svc_req *rqstp;
{
	static int res;
	struct group	*gr;

	bzero(&res, sizeof(res));
	if ((gr = getgrnam(*argp)) == NULL)
		res = NOBODY;
	else
		res = gr->gr_gid;

	return (&res);
}


ugname *
uid_name_1_svc(argp, rqstp)
	int *argp;
	struct svc_req *rqstp;
{
	static ugname res;
	struct passwd	*pw;

	bzero(&res, sizeof(res));
	if ((pw = getpwuid(*argp)) == NULL)
		res = "";
	else
		res = pw->pw_name;

	return (&res);
}


ugname *
gid_group_1_svc(argp, rqstp)
	int *argp;
	struct svc_req *rqstp;
{
	static ugname res;
	struct group	*gr;

	bzero(&res, sizeof(res));
	if ((gr = getgrgid(*argp)) == NULL)
		res = "";
	else
		res = gr->gr_name;

	return (&res);
}


static RETSIGTYPE
sigterm(int sig)
{
	exit(0);
}

static void
terminate(void)
{
	rpc_exit(UGIDPROG, ugidd_versions);
}



#else /* ENABLE_UGID_DAEMON */

#include <stdio.h>

int
main(argc, argv)
	int	argc;
	char	**argv;
{
	fprintf(stderr, 
	"\nThis copy of the Universal NFS server has been compiled without\n");
	fprintf(stderr, "support for the ugidd RPC uid/gid map daemon.\n");
	fprintf(stderr, "This is a dummy program.\n");
	return 1;
}

#endif /* ENABLE_UGID_DAEMON */
