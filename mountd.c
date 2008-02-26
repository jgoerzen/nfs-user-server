/*
 * mountd	This program handles RPC "NFS" mount requests.
 *
 * Usage:	[rpc.]mountd [-dhnpv] [-f authfile]
 *
 * Authors:	Mark A. Shand, May 1988
 *		Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */
 
 /*

    WANT_LOG_MOUNTS guarded patch is added Aug 18, 1995 by Alex Yuriev
    		   (alex@bach.cis.temple.edu), CIS Laboratories, 
    		   TEMPLE UNIVERSITY, USA
    
    This version is ugly and can be really improved but it actually
    pinpointed a couple of intruders :)
    		       		   
*/    		   


#include "mountd.h"
#include "getopt.h"
#include "rpcmisc.h"
#include "rmtab.h"
#include "haccess.h"
#include "failsafe.h"
#include "signals.h"
#include <rpc/pmap_clnt.h>


static void	usage(FILE *, int);
static void	terminate(void);
static RETSIGTYPE sigterm(int sig);

/*
 * Option table for mountd
 */
static struct option longopts[] =
{
      { "debug",		required_argument,	0,	'd' },
      { "exports-file",		required_argument,	0,	'f' },
      { "help",			0,			0,	'h' },
      { "allow-non-root",	0,			0,	'n' },
      { "port",			required_argument,	0,	'P' },
      { "promiscous",		0,			0,	'p' },
      { "re-export",		0,			0,	'r' },
      {	"no-spoof-trace",	0,			0,	't' },
      { "version",		0,			0,	'v' },
      { "fail-safe",		optional_argument,	0,	'z' },

      { NULL,			0,			0,	0 }
};
static const char *	shortopts = "Fd:f:hnpP:rtvz::";

/*
 * Table of supported versions
 */
static int	mountd_versions[] = {
	MOUNTVERS,
	MOUNTVERS_POSIX,
	0
};

char		argbuf[PATH_MAX + 1];
char		*auth_file = NULL;
static char	*program_name;
int		need_reinit = 0;
int		need_flush = 0;
extern char	version[];

/*
 * NULL
 * Do nothing
 */
void *
mountproc_null_1_svc(void *argp, struct svc_req *rqstp)
{
	return ((void *) &result);
}

/*
 * MOUNT
 * This is what the whole protocol is all about
 *
 * Note: librpc gets us MNTPATHLEN length strings, but realpath
 * needs a PATH_MAX length output buffer.
 */
fhstatus *
mountproc_mnt_1_svc(dirpath *argp, struct svc_req *rqstp)
{
	fhstatus	*res;
	struct stat	stbuf;
	nfs_client	*cp;
	nfs_mount	*mp;
	char		nargbuf[PATH_MAX + 1];
	int		saved_errno = 0;
#ifdef WANT_LOG_MOUNTS
	struct in_addr	addr;
#endif	/* WANT_LOG_MOUNTS */

	res = (struct fhstatus *)&result;

	if (**argp == '\0') {
		strcpy(argbuf, "/");
	} else {
		/* don't trust librpc */
		strncpy(argbuf, *argp, MNTPATHLEN);
		argbuf[MNTPATHLEN] = '\0';
	}

	/* It is important to resolve symlinks before checking permissions. */
	if (efs_realpath(argbuf, nargbuf) == NULL) {
		saved_errno = errno;
	} else {
		strcpy(argbuf, nargbuf);
	}

#ifdef WANT_LOG_MOUNTS
	addr = svc_getcaller(rqstp->rq_xprt)->sin_addr;
	Dprintf(L_NOTICE, "NFS mount of %s attempted from %s\n",
				argbuf, inet_ntoa(addr));
#endif /* WANT_LOG_MOUNTS */

	/* Now authenticate the intruder... */
	if (((cp = auth_clnt(rqstp)) == NULL) 
	  || (mp = auth_path(cp, rqstp, argbuf)) == NULL
	  || mp->o.noaccess) {
		res->fhs_status = NFSERR_ACCES;
#ifdef WANT_LOG_MOUNTS
		Dprintf(L_WARNING, "Blocked attempt of %s to mount %s\n",
			             inet_ntoa(addr), argbuf);		
#endif /* WANT_LOG_MOUNTS */
		Dprintf (D_CALL, "\tmount res = %d\n", res->fhs_status);
		return (res);
	}

	/* Check the file. We can now return valid results to the
	 * client. */
	if ((errno = saved_errno) != 0 || stat(argbuf, &stbuf) < 0) {
		res->fhs_status = nfs_errno();
		Dprintf (D_CALL, "\tmount res = %d\n", res->fhs_status);
		return (res);
	}

	if (!S_ISDIR(stbuf.st_mode) && !S_ISREG(stbuf.st_mode)) {
		res->fhs_status = NFSERR_NOTDIR;
	} else if (!re_export && nfsmounted(argbuf, &stbuf)) {
		res->fhs_status = NFSERR_ACCES;
	} else {
		res->fhs_status = fh_create((nfs_fh *)
			&(res->fhstatus_u.fhs_fhandle), argbuf);
		rmtab_add_client(argbuf, rqstp);
#ifdef WANT_LOG_MOUNTS
		Dprintf(L_NOTICE, "%s has been mounted by %s\n",
					argbuf, inet_ntoa(addr));
#endif /* WANT_LOG_MOUNTS */
	}
	Dprintf (D_CALL, "\tmount res = %d\n", res->fhs_status);
	return (res);
}

/*
 * DUMP
 * Dump the contents of rmtab on the caller.
 */
mountlist *
mountproc_dump_1_svc(void *argp, struct svc_req *rqstp)
{
	return (rmtab_lst_client());
}

/*
 * UMNTALL
 * Remove a mounted fs's rmtab entry, FWIW.
 */
void *
mountproc_umnt_1_svc(dirpath *argp, struct svc_req *rqstp)
{
	rmtab_del_client(*argp, rqstp);
	return ((void*) &result);
}

/*
 * UMNTALL
 * Remove a client's rmtab entry.
 */
void *
mountproc_umntall_1_svc(void *argp, struct svc_req *rqstp)
{
	rmtab_mdel_client(rqstp);
	return ((void*) &result);
}

/*
 * EXPORT
 * Return list of all exported file systems.
 */
exports *
mountproc_export_1_svc(void *argp, struct svc_req *rqstp)
{
	return (&export_list);
}

/*
 * EXPORTALL
 * Same as EXPORT
 */
exports *
mountproc_exportall_1_svc(void *argp, struct svc_req *rqstp)
{
	return (&export_list);
}

/*
 * PATHCONF
 * Since the protocol doesn't include a status field, Sun apparently
 * considers it good practice to let anyone snoop on your system, even if
 * it's pretty harmless data such as pathconf. We don't.
 *
 * Besides, many of the pathconf values don't make much sense on NFS volumes.
 * FIFOs and tty device files represent devices on the *client*, so there's
 * no point in getting the *server's* buffer sizes etc. Wonder what made the
 * Sun people choose these.
 */
ppathcnf *
mountproc_pathconf_2_svc(dirpath *argp, struct svc_req *rqstp)
{
	ppathcnf	*res = (ppathcnf *) &result;
	struct stat	stbuf;
	nfs_client	*cp;
	nfs_mount	*mp;
	char		nargbuf[MNTPATHLEN + 1], *dir;
#ifdef WANT_LOG_MOUNTS
	struct in_addr	addr;
#endif	/* WANT_LOG_MOUNTS */

	memset(res, 0, sizeof(*res));

	if (**argp == '\0') {
		strcpy(argbuf, "/");
	} else {
		/* don't trust librpc */
		strncpy(argbuf, *argp, MNTPATHLEN);
		argbuf[MNTPATHLEN] = '\0';
	}

	/* It is important to resolve symlinks before checking permissions. */
	if (realpath(argbuf, nargbuf) == NULL) {
		Dprintf (D_CALL, "\tpathconf failure 1\n");
		return (res);
	}
	strcpy(argbuf, nargbuf);
	dir = argbuf;

	if (stat(dir, &stbuf) < 0) {
		Dprintf (D_CALL, "\tpathconf failure 2\n");
		return (res);
	}

	/* Now authenticate the intruder... */
	if (((cp = auth_clnt(rqstp)) == NULL) 
	  || (mp = auth_path(cp, rqstp, dir)) == NULL
	  || mp->o.noaccess) {
#ifdef WANT_LOG_MOUNTS
		Dprintf(L_WARNING, "Blocked attempt of %s to pathconf(%s)\n",
			             inet_ntoa(addr), dir);		
#endif /* WANT_LOG_MOUNTS */
	} else if (!re_export && nfsmounted(dir, &stbuf)) {
		Dprintf (D_CALL, "\tpathconf failure 3\n");
	} else {
		/* You get what you ask for */
#if 1
		res->pc_link_max  = pathconf(dir, _PC_LINK_MAX);
		res->pc_max_canon = pathconf(dir, _PC_MAX_CANON);
		res->pc_max_input = pathconf(dir, _PC_MAX_INPUT);
		res->pc_name_max  = pathconf(dir, _PC_NAME_MAX);
		res->pc_path_max  = pathconf(dir, _PC_PATH_MAX);
		res->pc_pipe_buf  = pathconf(dir, _PC_PIPE_BUF);
		res->pc_vdisable  = pathconf(dir, _PC_VDISABLE);
#else
		res->pc_link_max  = _POSIX_LINK_MAX;
		res->pc_max_canon = _POSIX_MAX_CANON;
		res->pc_max_input = _POSIX_MAX_INPUT;
		res->pc_name_max  = MIN(_POSIX_NAME_MAX, NFS_MAXNAMLEN);
		res->pc_path_max  = MIN(_POSIX_PATH_MAX, NFS_MAXPATHLEN);
		res->pc_pipe_buf  = _POSIX_PIPE_BUF;
		res->pc_vdisable  = _POSIX_VDISABLE;
#endif

		/* Can't figure out what to do with pc_mask */
		res->pc_mask[0]   = 0;
		res->pc_mask[1]   = 0;
		Dprintf (D_CALL, "\tpathconf OK\n");
	}
	return (res);
}

int
main(int argc, char **argv)
{
	int foreground = 0;
	int failsafe_level = 0;
	int port = 0;
	int c;

	program_name = argv[0];
	chdir("/");

	/* Parse the command line options and arguments. */
	opterr = 0;
	while ((c = getopt_long(argc, argv, shortopts, longopts, NULL)) != EOF)
		switch (c) {
		case 'F':
			foreground = 1;
			break;
		case 'h':
			usage(stdout, 0);
			break;
		case 'd':
			enable_logging(optarg);
			break;
		case 'f':
			auth_file = optarg;
			break;
		case 'n':
			allow_non_root = 1;
			break;
		case 'P':
			port = atoi(optarg);
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "mountd: bad port number: %s\n",
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
		case 't':
			trace_spoof = 0;
			break;
		case 'v':
			printf("%s\n", version);
			exit(0);
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

	/* No more arguments allowed. */
	if (optind != argc)
		usage(stderr, 1);

	/* Get the default mount port */
	if (!port) {
		struct servent	*sp;

		if (!(sp = getservbyname("mount", "udp"))) {
			port = MOUNT_PORT;
		} else {
			port = ntohs(sp->s_port);
		}
	}

	/* Initialize logging. */
	log_open("mountd", foreground);

	/* Create services and register with portmapper */
	rpc_init("mountd", MOUNTPROG, mountd_versions, mount_dispatch, port, 0);

	if (!foreground && !_rpcpmstart) {
#ifndef RPC_SVC_FG
		/* We first fork off a child. */
		if ((c = fork()) > 0)
			exit(0);
		if (c < 0) {
			Dprintf(L_FATAL, "mountd: cannot fork: %s\n",
						strerror(errno));
		}
		/* No more logging to stderr */
		background_logging();

		/* Now we remove ourselves from the foreground. */
		(void) close(0);
		(void) close(1);
		(void) close(2);
#ifdef TIOCNOTTY
		if ((c = open("/dev/tty", O_RDWR)) >= 0) {
			(void) ioctl(c, TIOCNOTTY, (char *) NULL);
			(void) close(c);
		}
#else
		setsid();
#endif
#endif /* not RPC_SVC_FG */
	}

	/* Initialize the FH module. */
	fh_init();

	/* Initialize the AUTH module. */
	auth_init(auth_file);

	/* Failsafe mode */
	if (failsafe_level)
		failsafe(failsafe_level, 1);

	/* Enable the LOG toggle with a signal. */
	install_signal_handler(SIGUSR1, toggle_logging);

	/* Enable rereading of exports file */
	install_signal_handler(SIGHUP, reinitialize);

	/* Graceful shutdown */
	install_signal_handler(SIGTERM, sigterm);

	atexit(terminate);

	svc_run ();

	Dprintf (L_ERROR, "Ack! Gack! svc_run returned!\n");
	exit (1);
}

static void
usage(FILE *fp, int n)
{
	fprintf(fp, "Usage: %s [-Fhnpv] [-d kind] [-f exports-file] [-P port]\n",
				program_name);
	fprintf(fp, "       [--debug kind] [--help] [--allow-non-root]\n");
	fprintf(fp, "       [--promiscuous] [--version] [--port portnum]\n");
	fprintf(fp, "       [--exports-file=file]\n");
	exit(n);
}

static RETSIGTYPE
sigterm(int sig)
{
	terminate();
	exit(1);
}

static void
terminate(void)
{
	rpc_exit(MOUNTPROG, mountd_versions);
}

RETSIGTYPE
reinitialize(int sig)
{
	static volatile int	inprogress = 0;

	if (_rpcsvcdirty) {
		need_reinit = 1;
		return;
	}
	if (inprogress++)
		return;
	fh_flush(1);
	auth_init(NULL);
	inprogress = 0;
	need_reinit = 0;

	/* Flush the hosts_access table */
	client_flushaccess();
}

/*
 * Don't look. This is an awful hack to overcome a link problem with
 * auth_clnt temporarily.
 */
uid_t
luid(uid_t uid, nfs_mount *mp, struct svc_req *rqstp)
{
	return -2;
}

gid_t
lgid(gid_t gid, nfs_mount *mp, struct svc_req *rqstp)
{
	return -2;
}

void
ugid_free_map(struct ugid_map *map)
{
	/* NOP */
}

void
ugid_map_uid(nfs_mount *mp, uid_t from, uid_t to)
{
	/* NOP */
}

void
ugid_map_gid(nfs_mount *mp, gid_t from, gid_t to)
{
	/* NOP */
}

void
ugid_squash_uids(nfs_mount *mp, uid_t from, uid_t to)
{
	/* NOP */
}

void
ugid_squash_gids(nfs_mount *mp, gid_t from, gid_t to)
{
	/* NOP */
}
