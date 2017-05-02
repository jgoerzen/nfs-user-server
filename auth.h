/*
 * auth.h	This module takes care of request authorization.
 *
 * Authors:	Mark A. Shand, May 1988
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch <okir@monad.swb.de>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

/* Global AUTH variables. */
extern int			allow_non_root;
extern int			promiscuous;
extern int			re_export;
extern int			trace_spoof;
extern struct exportnode	*export_list;
extern uid_t			cred_uid, auth_uid;
extern gid_t			cred_gid, auth_gid;
extern char *			public_root_path;
extern struct nfs_fh		public_root;

#if defined(linux) && defined(i386) && !defined(HAVE_SETFSUID)
#   define MAYBE_HAVE_SETFSUID
#endif

#ifdef MAYBE_HAVE_SETFSUID
extern int			have_setfsuid;
#endif

/*
 * These externs are set in the dispatcher (dispatch.c) and auth_fh
 * (nfsd.c) so that we can determine access rights, export options,
 * etc. pp.
 */		
extern struct nfs_client *	nfsclient;
extern struct nfs_mount	*	nfsmount;

/*
 * These are the structures used by the authentication module.
 */
typedef enum {
	identity,
	map_static,
	map_daemon,
	map_nis
}	ugid_mapping_t;

typedef struct nfs_options {
	ugid_mapping_t		uidmap;		/* uid/gid mapping behavior */
	int			root_squash;
	int			all_squash;
	int			some_squash;	/* speed up luid() etc. */
	int			secure_port;
	int			read_only;
	int			link_relative;
	int			noaccess;
	int			cross_mounts;
	uid_t			nobody_uid;
	gid_t			nobody_gid;
	char *			clnt_nisdomain;
} nfs_options;

typedef struct nfs_mount {
	struct nfs_mount *	next;
	struct nfs_mount *	parent;
	struct nfs_client *	client;
	int			length;
	char *			path;
	nfs_options		o;
	/* Original NFS client */
	struct nfs_client *	origin;
} nfs_mount;

typedef struct nfs_client {
	struct nfs_client *	next;
	struct in_addr		clnt_addr;
	struct in_addr		clnt_mask;
	char *			clnt_name;
	unsigned short		flags;
	nfs_mount *		m;

	/*
	 * This is the uid/gid map.
	 * See ugid_map.c for details
	 */
	struct ugid_map *	umap;
} nfs_client;

#define AUTH_CLNT_WILDCARD	0x0001
#define AUTH_CLNT_ANONYMOUS	0x0002
#define AUTH_CLNT_NETGROUP	0x0004
#define AUTH_CLNT_NETMASK	0x0008
#define AUTH_CLNT_DEFAULT	0x0010
#define AUTH_CLNT_AUTOMATIC	0x0020

#ifndef ROOT_UID
#define ROOT_UID		0
#endif

#define AUTH_UID_NONE		((uid_t)-1)
#define AUTH_GID_NONE		((uid_t)-1)
#define AUTH_UID_NOBODY		((uid_t)-2)
#define AUTH_GID_NOBODY		((uid_t)-2)

/* Global Function prototypes. */
extern void       auth_init(char *fname);
extern void       auth_init_lists(void);
extern void	  auth_free_lists(void);
extern nfs_client *auth_clnt(struct svc_req *rqstp);
extern nfs_mount  *auth_path(nfs_client *, struct svc_req *, char *);
extern void       auth_user(nfs_mount *, struct svc_req *);

extern nfs_client *auth_get_client(char *);
extern nfs_mount  *auth_match_mount(nfs_client *, char *);
extern nfs_client *auth_known_clientbyname(char *);
extern nfs_client *auth_known_clientbyaddr(struct in_addr);
extern nfs_client *auth_unknown_clientbyaddr(struct in_addr);
extern nfs_client *auth_clientbyaddr(struct in_addr);
extern nfs_client *auth_create_client(const char *, struct hostent *);
extern nfs_client *auth_create_default_client(void);
extern nfs_mount  *auth_add_mount(nfs_client *, char *, int);
extern void       auth_check_all_wildcards(void);
extern void       auth_check_all_netgroups(void);
extern void       auth_check_all_netmasks(void);
extern void	  auth_sort_all_mountlists(void);
extern void	  auth_log_all(void);

/* This function lets us set our euid/fsuid temporarily */
extern void       auth_override_uid(uid_t);

/* Prototypes for ugidd mapping */
extern uid_t	  ruid(uid_t, nfs_mount *, struct svc_req *);
extern gid_t	  rgid(gid_t, nfs_mount *, struct svc_req *);
extern uid_t	  luid(uid_t, nfs_mount *, struct svc_req *);
extern gid_t	  lgid(gid_t, nfs_mount *, struct svc_req *);
extern void	  ugid_free_map(struct ugid_map *);
extern void	  ugid_squash_uids(nfs_mount *, uid_t lo, uid_t hi);
extern void	  ugid_squash_gids(nfs_mount *, gid_t lo, gid_t hi);
extern void	  ugid_map_uid(nfs_mount *, uid_t fm, uid_t to);
extern void	  ugid_map_gid(nfs_mount *, gid_t fm, gid_t to);

/* End of auth.h. */
