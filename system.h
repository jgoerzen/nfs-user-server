/*
 * system.h -- this header consolidates many of the system dependencies
 * Public Domain.
 */

#ifndef SYSTEM_H
#define SYSTEM_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "site.h"

#include <sys/types.h>

/* unistd.h defines _POSIX_VERSION on POSIX.1 systems.  */
#if defined(HAVE_UNISTD_H) || defined(STDC_HEADERS)
# include <unistd.h>
#endif

#ifdef STDC_HEADERS
# include <stdlib.h>
#endif

#ifdef _POSIX_VERSION
# include <limits.h>
#else
# include <sys/param.h>
#endif

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>

#include <rpc/rpc.h>
#ifndef HAVE_XDRPROC_T
#ifdef __STDC__
typedef bool_t	(*xdrproc_t)(XDR *, void *, ...);
#else
typedef bool_t	(*xdrproc_t)();
#endif
#endif

#include <ctype.h>
#include <errno.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <netdb.h>			/* needed for gethostbyname */
#include <netinet/in.h>
#undef NOERROR				/* blasted sysv4 */
#include <arpa/nameser.h>		/* needed for <resolv.h> */
#include <arpa/inet.h>			/* for inet_ntoa(3) */
#include <resolv.h>			/* needed for h_errno */
#include <signal.h>

#ifdef __STDC__
# include <stdarg.h>			/* needed for va_arg et al */
#else
# include <varargs.h>
#endif

#ifdef _POSIX_VERSION
# include <pwd.h>			/* for getpwuid */
# include <grp.h>			/* for setgroups */
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else /* not TIME_WITH_SYS_TIME */
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else /* not HAVE_SYS_TIME_H */
#  include <time.h>
struct timeval {
	long tv_sec;
	long tv_usec;
};
# endif /* not HAVE_SYS_TIME_H */
#endif /* not TIME_WITH_SYS_TIME */
#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#endif
#ifdef MAJOR_IN_SYSMACROS
# include <sys/sysmacros.h>
#endif

#if defined(STDC_HEADERS) || defined(HAVE_STRING_H)
# include <string.h>
/* An ANSI string.h and pre-ANSI memory.h might conflict.  */
# if !defined(STDC_HEADERS) && defined(HAVE_MEMORY_H)
#  include <memory.h>
# endif /* not STDC_HEADERS and HAVE_MEMORY_H */
#else /* not STDC_HEADERS and not HAVE_STRING_H */
# include <strings.h>
/* memory.h and strings.h conflict on some systems.  */
# ifndef strchr
#  define strchr(s, c) index((s), (c))
# endif
# ifndef strrchr
#  define strrchr(s, c) rindex((s), (c))
# endif
# ifndef memcpy
#  define memcpy(d, s, n) bcopy((s), (d), (n))
# endif
# ifndef memcmp
#  define memcmp(s1, s2, n) bcmp((s1), (s2), (n))
# endif
# ifndef memset
#  define memset(s, c, n) \
	do {						\
		char *_s = (s);				\
		int _c = (c);				\
		int _n = (n);				\
		int _i;					\
							\
		if (_c == 0)				\
			bzero(_s, _n);			\
		else					\
			for (_i = 0; _i < _n; _i++)	\
				*_s++ = _c;		\
	} while (0)
# endif
#endif /* not STDC_HEADERS and not HAVE_STRING_H */

extern void *	xmalloc(unsigned n);
extern void *	xrealloc(void *ptr, unsigned n);
extern char *	xstrdup(const char *str);

#if HAVE_DIRENT_H || defined(_POSIX_VERSION)
# include <dirent.h>
# define NLENGTH(dirent) (strlen((dirent)->d_name))
#else /* not (HAVE_DIRENT_H or _POSIX_VERSION) */
# define dirent direct
# define NLENGTH(dirent) ((dirent)->d_namlen)
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* not (HAVE_DIRENT_H or _POSIX_VERSION) */

#ifdef __GNUC__
# ifndef __STDC__
#  define inline __inline__
# endif
#else
# define inline
#endif

#ifndef S_IFMT
# define S_IFMT 0170000
#endif

#ifdef STAT_MACROS_BROKEN
# undef S_ISBLK
# undef S_ISCHR
# undef S_ISDIR
# undef S_ISREG
# undef S_ISFIFO
# undef S_ISLNK
# undef S_ISSOCK
#endif /* STAT_MACROS_BROKEN */

#if !defined(S_ISBLK) && defined(S_IFBLK)
# define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#endif
#if !defined(S_ISCHR) && defined(S_IFCHR)
# define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif
#if !defined(S_ISDIR) && defined(S_IFDIR)
# define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#if !defined(S_ISREG) && defined(S_IFREG)
# define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#if !defined(S_ISFIFO) && defined(S_IFFIFO)
# define S_ISFIFO(m) (((m) & S_IFMT) == S_IFFIFO)
#endif
#if !defined(S_ISLNK) && defined(S_IFLNK)
# define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
#if !defined(S_ISSOCK) && defined(S_IFSOCK)
# define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif

#ifndef S_ISLNK
# define lstat stat
#endif

#ifndef HAVE_LCHOWN
# define lchown chown
#endif

#ifndef F_OK
# define F_OK 0
# define X_OK 1
# define W_OK 2
# define R_OK 4
#endif

#if !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
# define seteuid(e) setreuid(((uid_t) -1), (e))
# define setegid(e) setregid(((gid_t) -1), (e))
#endif

#if !defined(getdtablesize) && !defined(HAVE_GETDTABLESIZE)
# ifdef FILE_MAX
#  define getdtablesize() FILE_MAX
# else
#  define getdtablesize() 20
# endif
#endif

#ifndef HAVE_ST_RDEV
# define st_rdev st_size
#endif

#ifndef PATH_MAX
# ifdef _POSIX_VERSION
#  define PATH_MAX _POSIX_PATH_MAX
# else
#  ifdef MAXPATHLEN
#   define PATH_MAX MAXPATHLEN
#  else
#   define PATH_MAX 1024
#  endif
# endif
#endif

#ifndef NAME_MAX
# ifdef _POSIX_VERSION
#  define NAME_MAX _POSIX_NAME_MAX
# else
#  ifdef MAXNAMLEN
#   define NAME_MAX MAXNAMLEN
#  else
#   define NAME_MAX 255
#  endif
# endif
#endif

#ifdef linux
# ifdef __GLIBC__
   typedef u_int32_t		__u32;
   typedef u_int8_t		__u8;
# endif
#else
# if SIZEOF_UNSIGNED_LONG == 4
   typedef unsigned long	__u32;
# elsif SIZEOF_UNSIGNED_INT == 4
   typedef unsigned int		__u32;
# else
#  error "Don't know how to define unsigned 32bit quantity!"
# endif
   typedef unsigned char	__u8;
#endif

#ifndef MIN
# define MIN(a, b)		(((a) < (b))? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b)		(((a) > (b))? (a) : (b))
#endif

#define SECURE_PORT(p)		(IPPORT_RESERVED/2 <= ntohs(p) \
				 && ntohs(p) < IPPORT_RESERVED)

#endif /* SYSTEM_H */
