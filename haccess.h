/*
 * haccess.h
 *
 * Wrapper for tcp_wrapper library
 */

#ifndef HACCESS_H
#define HACCESS_H

#ifdef HOSTS_ACCESS
extern int 	  client_checkaccess(char *, struct sockaddr_in *, int);
extern void	  client_flushaccess(void);
#else
#define client_checkaccess(a, b, c)	1
#define client_flushaccess()		do { } while (0)
#endif

#endif /* HACCESS_H */
