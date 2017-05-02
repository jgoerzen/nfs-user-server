/*
 * rpcmisc	Support for RPC startup and shutdown.
 *
 */

#ifndef RPCMISC_H
#define RPCMISC_H

extern int		_rpcpmstart;
extern int		_rpcfdtype;
extern int		_rpcsvcdirty;
extern const char *	auth_daemon;

extern void		rpc_init(const char *name, int prog, int *verstbl,
					void (*dispatch)(),
					int defport, int bufsize);
extern void		rpc_exit(int prog, int *verstbl);
extern void		rpc_closedown(void);

#endif /* RPCMISC_H */
