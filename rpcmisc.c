/*
 * rpcmisc	Miscellaneous functions for RPC startup and shutdown.
 *		This code is partially snarfed from rpcgen -s tcp -s udp,
 *		partly written by Mark Shand, Donald Becker, and Rick 
 *		Sladkey. It was tweaked slightly by Olaf Kirch to be
 *		useable by both nfsd and mountd.
 *
 *		This software may be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 *
 *		Auth daemon code by Olaf Kirch.
 */

#include "system.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h> 
#include <string.h> 
#include <signal.h>
#include <sys/ioctl.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <fcntl.h> 
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "rpcmisc.h"
#include "logging.h"

/* Another undefined function in RPC */
extern SVCXPRT *svcfd_create(int sock, u_int ssize, u_int rsize);

static int	makesock(int port, int proto, int socksz);

#define _RPCSVC_CLOSEDOWN	120
time_t		closedown = 0;
int		_rpcpmstart = 0;
int		_rpcfdtype = 0;
int		_rpcsvcdirty = 0;
const char *	auth_daemon = 0;

#ifdef AUTH_DAEMON
static bool_t	(*tcp_rendevouser)(SVCXPRT *, struct rpc_msg *);
static bool_t	(*tcp_receiver)(SVCXPRT *, struct rpc_msg *);
static bool_t	auth_rendevouser(SVCXPRT *, struct rpc_msg *);
static bool_t	auth_receiver(SVCXPRT *, struct rpc_msg *);
static void	auth_handler(int sock);
#endif

void
rpc_init(const char *name, int prog, int *verstbl, void (*dispatch)(),
			int defport, int bufsiz)
{
	struct sockaddr_in saddr;
	SVCXPRT	*transp;
	int	sock, i, vers;
	int	asize;

	/* When started from inetd, initialize only once */
	if (_rpcpmstart)
		return;

	asize = sizeof(saddr);
	sock = 0;
	if (getsockname(0, (struct sockaddr *) &saddr, &asize) == 0) {
		int	ssize = sizeof (i);

		if (saddr.sin_family != AF_INET)
			goto not_inetd;
		if (getsockopt(0, SOL_SOCKET, SO_TYPE, &i, &ssize) < 0)
			goto not_inetd;
		_rpcfdtype = i;
		background_logging();	/* no more logging to stderr */
		closedown = time(NULL) + _RPCSVC_CLOSEDOWN;
		_rpcpmstart = 1;
	} else {
not_inetd:
		for (i = 0; (vers = verstbl[i]) != 0; i++)
			pmap_unset(prog, vers);
		sock = RPC_ANYSOCK;
	}

	if ((_rpcfdtype == 0) || (_rpcfdtype == SOCK_DGRAM)) {
		if (_rpcpmstart == 0 && defport != 0)
	    		sock = makesock(defport, IPPROTO_UDP, bufsiz);
		transp = svcudp_create(sock);
		if (transp == NULL)
			Dprintf(L_FATAL, "cannot create udp service.");
		for (i = 0; (vers = verstbl[i]) != 0; i++) {
			if (!svc_register(transp, prog, vers, dispatch, IPPROTO_UDP)) {
				Dprintf(L_FATAL,
					"unable to register (%s, %d, udp).",
					name, vers);
			}
		}
	}

	if ((_rpcfdtype == 0) || (_rpcfdtype == SOCK_STREAM)) {
		if (_rpcpmstart == 0 && defport != 0)
			sock = makesock(defport, IPPROTO_TCP, bufsiz);
		transp = svctcp_create(sock, 0, 0);
		if (transp == NULL)
			Dprintf(L_FATAL, "cannot create tcp service.");
#ifdef AUTH_DAEMON
		tcp_rendevouser = transp->xp_ops->xp_recv;
		transp->xp_ops->xp_recv = auth_rendevouser;
#endif
		for (i = 0; (vers = verstbl[i]) != 0; i++) {
			if (!svc_register(transp, prog, vers, dispatch, IPPROTO_TCP)) {
				Dprintf(L_FATAL,
					"unable to register (%s, %d, tcp).",
					name, vers);
			}
		}
	}

	/* We ignore SIGPIPE. SIGPIPE is being sent to a daemon when trying
	 * to do a sendmsg() on a TCP socket whose peer has disconnected.
	 */
	if (!_rpcpmstart) {
		struct sigaction pipeact;

		memset(&pipeact, 0, sizeof(pipeact));
		pipeact.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &pipeact, NULL);
	}
}

void
rpc_exit(int prog, int *verstbl)
{
	int	i, vers;

	if (_rpcpmstart)
		return;
	for (i = 0; (vers = verstbl[i]) != 0; i++)
		pmap_unset(prog, vers);
}

void
rpc_closedown(void)
{
	struct sockaddr_in	sin;
	static int		size = 0;
	time_t			now = time(NULL);
	int			i, len;

	if (!_rpcpmstart || now < closedown)
		return;
	if (_rpcsvcdirty == 0) {
		if (_rpcfdtype == SOCK_DGRAM)
			exit(0);

		/* Okay, this is a TCP socket. Check whether we're still
		 * connected */
		if (size == 0) {
			size = getdtablesize();
		}
		for (i = 0; i < size; i++) {
			if (!FD_ISSET(i, &svc_fdset))
				continue;
			len = sizeof(sin);
			if (getpeername(i, (struct sockaddr *) &sin, &len) >= 0)
				exit(0);
		}
	}
	closedown = now + _RPCSVC_CLOSEDOWN;
}

static int
makesock(int port, int proto, int socksz)
{
	struct sockaddr_in sin;
	const char	*prot_name;
	int		s;
	int		sock_type;

	switch (proto) {
	case IPPROTO_UDP:
		sock_type = SOCK_DGRAM;
		prot_name = "UDP";
		break;
	case IPPROTO_TCP:
		sock_type = SOCK_STREAM;
		prot_name = "TCP";
		break;
	default:
		Dprintf(L_FATAL, "Invalid protocol in makesock\n");
		return -1; /* NOTREACHED */
	}

	s = socket(AF_INET, sock_type, proto);
	if (s < 0)
		Dprintf(L_FATAL, "Could not make a %s socket: %s\n",
					prot_name, strerror(errno));

	memset((char *) &sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

#ifdef DEBUG
	{
	int	val = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
		Dprintf(L_ERROR, "setsockopt failed: %s\n", strerror(errno));
	}
#endif

#ifdef SO_SNDBUF
	if (socksz != 0) {
		int sblen, rblen;

		/* 1024 for rpc & transport overheads */
		sblen = rblen = 8 * (socksz + 1024);
		if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sblen, sizeof sblen) < 0 ||
		    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rblen, sizeof rblen) < 0)
			Dprintf(L_ERROR, "setsockopt failed: %s\n", strerror(errno));
	}
#endif				/* SO_SNDBUF */

	if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
		Dprintf(L_ERROR, "Could not bind %s socket to %s:%d: %s\n",
					prot_name, inet_ntoa(sin.sin_addr), 
					ntohs(sin.sin_port),
					strerror(errno));
		close(s);
		s = RPC_ANYSOCK;
	}

	return (s);
}

#ifdef AUTH_DAEMON
static bool_t
auth_rendevouser(SVCXPRT *xprt, struct rpc_msg *rpcmsg)
{
	struct sockaddr_in	sin;
	int			sock, slen = sizeof(sin);

	do {
		sock = accept(xprt->xp_sock, (struct sockaddr *) &sin, &slen);
	} while (sock < 0 && errno == EINTR);

	if (sock >= 0) {
		xprt = svcfd_create(sock, 0, 0);
		xprt->xp_raddr   = sin;
		xprt->xp_addrlen = slen;

		/* Swap the receive handler */
		if (auth_daemon) {
			tcp_receiver = xprt->xp_ops->xp_recv;
			xprt->xp_ops->xp_recv = auth_receiver;
		}
	}

	/* Always return false -- there's never an rpcmsg to be processed */
	return 0;
}

static bool_t
auth_receiver(SVCXPRT *xprt, struct rpc_msg *rpcmsg)
{
	__u32		buffer[10];
	struct msghdr	msg;
	struct iovec	iov;
	int		len;

	msg.msg_name	= 0;
	msg.msg_namelen	= 0;
	msg.msg_iov	= &iov;
	msg.msg_iovlen	= 1;
	msg.msg_control	= 0;
	msg.msg_controllen = 0;

	iov.iov_base	= buffer;
	iov.iov_len	= sizeof(buffer);

	len = recvmsg(xprt->xp_sock, &msg, MSG_PEEK);
	if (len < 16			/* Initial packet too small */
	 || buffer[2] != htonl(2)	/* RPC version 2 */
	 || buffer[3] != htonl(0)) {	/* CALL */
		auth_handler(xprt->xp_sock);
		svc_destroy(xprt);
		return (0);
	}

	/* Okay--convert this back into an ordinary TCP socket */
	xprt->xp_ops->xp_recv = tcp_receiver;
	return svc_recv(xprt, rpcmsg);
}

static void
auth_handler(int sock)
{
	int	fds[2], pid, fd;

	if (socketpair(AF_INET, SOCK_STREAM, IPPROTO_TCP, fds) < 0) {
		Dprintf(L_ERROR, "Cannot create socket pair: %m");
		return;
	}

	if ((pid = fork()) < 0) {
		Dprintf(L_ERROR, "cannot fork: %m");
		return;
	}
	if (pid == 0) {
		/* Parent: create a new transport for this socket */
		svcfd_create(fds[0], 0, 0);
		return;
	}

	/* We're the child process. Set up the server socket on fd 0,
	 * and the client socket on fd 1.
	 */
	if (dup2(fds[1], 0) < 0 || dup2(sock, 1) < 0) {
		Dprintf(L_ERROR, "unable to dup: %m");
		exit(1);
	}

	log_close();
	for (fd = 2; fd < OPEN_MAX; fd++)
		close(fd);

	execl(auth_daemon, auth_daemon, 0);

	log_open(auth_daemon, 0);
	Dprintf(L_ERROR, "unable to execute: %m");
	exit(1);
}
#endif
