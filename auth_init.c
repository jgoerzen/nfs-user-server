/*
 * auth_init.c	This module takes care of request authorization.
 *
 * Authors:	Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *		Alexander O. Yuriev, <alex@bach.cis.temple.edu>
 *
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "nfsd.h"
#include "fakefsuid.h"
#include <pwd.h>

#define LINE_SIZE	1024
#define CHUNK_SIZE	1024	/* the 'typical' maximum line length	*/

#ifndef EXPORTSFILE
#define EXPORTSFILE	"/etc/exports"
#endif

#if 0
/* Support for file access control on /etc/exports by Alex Yuriev. */
#include "faccess.h"
#ifndef EXPORTSOWNERUID
#define EXPORTSOWNERUID		((uid_t) 0)
#endif
#ifndef EXPORTSOWNERGID
#define EXPORTSOWNERGID		((gid_t) 0)
#endif
#endif

exportnode *	export_list = NULL;
int		allow_non_root = 0;
int		promiscuous = 0;
int		re_export = 0;
int		trace_spoof = 1;
int		auth_initialized = 0;
int		have_setfsuid = 0;
char *		public_root_path = 0;
nfs_fh		public_root;

static int	filt_getc(FILE *);
static int	export_getline(char **, FILE *);
static char *	parse_opts(char *, char, nfs_mount *, char *);
static void	parse_squash(nfs_mount *mp, int uidflag, char **cpp);
static int	parse_num(char **cpp);
static void	free_exports(void);

static int
filt_getc(FILE *f)
{
	int c;

	c = getc(f);
	if (c == '\\') {
		c = getc(f);
		if (c == '\n')
			return (' ');
		if (c != EOF)
			ungetc(c, f);
		return ('\\');
	} else if (c == '#') {
		int lastc = c;
		do {
			while ((c = getc(f)) != '\n' && c != EOF)
				lastc = c;
		} while (c == '\n' && lastc == '\\');
	}
	return (c);
}

static int
export_getline(char **lbuf, FILE *f)
{
	int	c, sz = CHUNK_SIZE;
	char	*p, *buf;

	buf = (char *) xmalloc(sz);
	p = buf;
	while ((c = filt_getc(f)) != '\n' && c != EOF) {
		if (p - buf == sz - 2) {
			buf = (char *) xrealloc(buf, sz * 2);
			p = buf + sz - 2;
			sz *= 2;
		}
		*p++ = c;
	}
	if (c == EOF && p == buf) {
		free(buf);
		*lbuf = NULL;
		return (0);
	}
	*p++ = '\0';
	*lbuf = buf;
	return (1);
}

/*
 * Parse number.
 */
static int
parse_num(char **cpp)
{
	char	*cp = *cpp, c;
	int	num = 0;

	if (**cpp == '-')
		(*cpp)++;
	while (isdigit(**cpp))
		(*cpp)++;
	c = **cpp; **cpp = '\0'; num = atoi(cp); **cpp = c;
	return num;
}

/*
 * Install uid mapping records for a specified list of uids/gids.
 * We first map these ids to the compile-time value AUTH_[UG]ID_NOBODY,
 * which is later (in luid/lgid) mapped to the current nobody_uid/nobody_gid.
 * We take these contortions because users may define option lists like this:
 *
 *	/foo		foo.bar.edu(squash=0-20,anonuid=32767)
 *
 * In this example, the squash list is parsed before we know what the anonuid
 * really is.
 */
static void
parse_squash(nfs_mount *mp, int uidflag, char **cpp)
{
	char	*cp = *cpp;
	int	id0, id1;

	do {
		id0 = parse_num(&cp);
		if (*cp == '-') {
			cp++;
			id1 = parse_num(&cp);
		} else {
			id1 = id0;
		}
		if (uidflag)
			ugid_squash_uids(mp, id0, id1);
		else
			ugid_squash_gids(mp, id0, id1);
		if (*cp != ',' || !isdigit(cp[1]))
			break;
		cp++;
	} while(1);
	*cpp = cp;
	mp->o.some_squash = 1;
}

/*
 * Parse a static uid/gid mapping
 * 
 * Entries in the file look like this:
 *
 * u[id]      100	200	# maps remote uid 100 to local uid 200
 * g[id]    50-99	500	# maps remote gids 50-99 to 500-549
 * uid	     0-99	  -	# squash remote uids 0-99
 */
static void
parse_static_uidmap(nfs_mount *mp, char **cpp)
{
	char	*cp = *cpp, keep;
	FILE	*fp;

	cp += strcspn(cp, ",()");
	keep = *cp;
	*cp = '\0';

	if (!(fp = fopen(*cpp, "r"))) {
		Dprintf(L_ERROR, "Failed to open uid/gid map file %s. "
				 "Forcing all_squash.", *cpp);
		mp->o.all_squash = 1;
	} else {
		unsigned int	low, high, to;
		char		buffer[128], *sp;
		int		uidflag;

		while (fgets(buffer, sizeof(buffer), fp) != NULL) {
			if ((sp = strchr(buffer, '#')) != NULL)
				*sp = '\0';
			if (!(sp = strtok(buffer, " \t\n")))
				continue;	/* empty line */
			uidflag = (*sp == 'u' || *sp == 'U');
			if (!(sp = strtok(NULL, " \t\n")))
				goto error;
			high = low = strtoul(sp, &sp, 10);
			if (*sp == '-')
				high = strtoul(sp + 1, &sp, 10);
			if (*sp != '\0')
				goto error;
			if (!(sp = strtok(NULL, " \t\n"))
			 || !strcmp(sp, "-")) {
				/* Okay, squash these uids */
				if (uidflag)
					ugid_squash_uids(mp, low, high);
				else
					ugid_squash_gids(mp, low, high);
			} else {
				to = strtoul(sp, &sp, 10);
				if (*sp != '\0')
					goto error;
				if (uidflag) {
					while (low <= high)
						ugid_map_uid(mp, low++, to++);
				} else {
					while (low <= high)
						ugid_map_gid(mp, low++, to++);
				}
			}
		}
		fclose(fp);
		mp->o.uidmap = map_static;
	}
	*cp = keep;
	*cpp = cp;

	return;

error:
	Dprintf(L_ERROR, "%s: parse error.", *cpp);
	mp->o.all_squash = 1;
	fclose(fp);
	*cp = keep;
	*cpp = cp;
}

/*
 * Parse arguments for NIS uid maps
 * Currently, this is just the client's NIS domain
 */
static void
parse_nis_uidmap(nfs_mount *mp, char **cpp)
{
	char	*cp = *cpp, keep;

	cp += strcspn(cp, ",()");
	keep = *cp;
	*cp = '\0';
	if (mp->o.clnt_nisdomain)
		free(mp->o.clnt_nisdomain);
	mp->o.clnt_nisdomain = xstrdup(*cpp);
	mp->o.uidmap = map_nis;
	*cp = keep;
	*cpp = cp;
}

/*
 * Parse option string pointed to by s and set mount options accordingly.
 */
static char *
parse_opts(char *cp, char terminator, nfs_mount *mp, char *client_name)
{
	char *kwd;
	int  klen;

	/* skip white */
	while (isspace(*cp))
		cp++;
	while (*cp != terminator) {
		kwd = cp;
		while (isalpha(*cp) || *cp == '_' || *cp == '=') {
			/* break out of loop after = sign */
			if (*cp++ == '=')
				break;
		}
		klen = cp - kwd;

		/* process keyword */
		if (strncmp(kwd, "secure", 6) == 0)
			mp->o.secure_port = 1;
		else if (strncmp(kwd, "insecure", 8) == 0)
			mp->o.secure_port = 0;
		else if (strncmp(kwd, "root_squash", 11) == 0)
			mp->o.root_squash = 1;
		else if (strncmp(kwd, "no_root_squash", 14) == 0)
			mp->o.root_squash = 0;
		else if (strncmp(kwd, "ro", 2) == 0)
			mp->o.read_only = 1;
		else if (strncmp(kwd, "rw", 2) == 0)
			mp->o.read_only = 0;
		else if (strncmp(kwd, "link_relative", 13) == 0)
			mp->o.link_relative = 1;
		else if (strncmp(kwd, "link_absolute", 13) == 0)
			mp->o.link_relative = 0;
		else if (strncmp(kwd, "map_daemon", 10) == 0)
			mp->o.uidmap = map_daemon;
		else if (strncmp(kwd, "map_nis=", 8) == 0)
			parse_nis_uidmap(mp, &cp);
		else if (strncmp(kwd, "map_static=", 11) == 0)
			parse_static_uidmap(mp, &cp);
		else if (strncmp(kwd, "map_identity", 12) == 0)
			mp->o.uidmap = identity;
		else if (strncmp(kwd, "all_squash", 10) == 0)
			mp->o.all_squash = 1;
		else if (strncmp(kwd, "no_all_squash", 13) == 0)
			mp->o.all_squash = 0;
		else if (strncmp(kwd, "noaccess", 8) == 0)
			mp->o.noaccess = 1;
		else if (strncmp(kwd, "squash_uids=", 12) == 0)
			parse_squash(mp, 1, &cp);
		else if (strncmp(kwd, "squash_gids=", 12) == 0)
			parse_squash(mp, 0, &cp);
		else if (strncmp(kwd, "anonuid=", 8) == 0)
			mp->o.nobody_uid = parse_num(&cp);
		else if (strncmp(kwd, "anongid=", 8) == 0)
			mp->o.nobody_gid = parse_num(&cp);
		else if (strncmp(kwd, "async", 5) == 0)
			/* knfsd compatibility, ignore */;
		else if (strncmp(kwd, "sync", 4) == 0)
			/* knfsd compatibility, ignore */;
		else {
			Dprintf(L_ERROR,
				"Unknown keyword \"%.*s\" in export file\n",
				klen, kwd);
			mp->o.all_squash = 1;
			mp->o.read_only = 1;
		}
		while (isspace(*cp))
			cp++;
		if (*cp == terminator)
			break;
		if (*cp == ',')
			cp++;
		else if (!isalpha(*cp) && *cp != '_' && *cp != '\0') {
			if (client_name == NULL)
				Dprintf(L_ERROR,
					"Comma expected in opt list for "
					"default clnt (found '%c')\n", *cp);
			else
				Dprintf(L_ERROR,
					"Comma expected in opt list for "
					"clnt %s (found '%c')\n",
					client_name, *cp);
			cp++;
		}
		while (isspace(*cp))
			cp++;

		if (*cp == '\0' && *cp != terminator) {
			Dprintf(L_ERROR,
				"missing terminator \"%c\" on option list\n",
				terminator);
			return (cp);
		}
	}
	if (*cp != terminator)
		Dprintf(L_ERROR, "Trouble in parser, character '%c'.\n", *cp);

	cp++;			/* Skip past terminator */
	while (isspace(*cp))
		cp++;
	return (cp);
}

static nfs_client *
get_client(char *hname)
{
	nfs_client *cp;

	if (hname && *hname == '\0')
		hname = NULL;
	if ((cp = auth_get_client(hname)) == NULL)
		cp = auth_create_client(hname, NULL);

	return cp;
}

void
auth_init(char *fname)
{
	exportnode	*resex;		/* export data for showmount -x */
	groupnode	*resgr;
	static char	*auth_file = NULL;
	FILE		*ef;
	char		*cp;		/* Current line position */
	char		*sp;		/* Secondary pointer */
	char		*fs_name;
	char		path[PATH_MAX];
	char		resolved_path[PATH_MAX];

	if (auth_initialized) {
		free_exports();
		fname = auth_file;
	}

	auth_init_lists();

	if (fname == NULL)
		fname = EXPORTSFILE;
	auth_file = fname;	/* Save for re-initialization */

	/* Check protection of exports file. */
#if 0	/* A man's house is his castle. */
	switch(iCheckAccess(auth_file, EXPORTSOWNERUID, EXPORTSOWNERGID)) {
	case FACCESSWRITABLE:
		Dprintf(L_ERROR,
			"SECURITY: A user with uid != %d can write to %s!\n",
				EXPORTSOWNERUID, fname);
		Dprintf(L_ERROR, "exiting because of security violation.\n");
		exit(1);
	case FACCESSBADOWNER:
		Dprintf(L_ERROR,
			"SECURITY: File %s not owned by uid %d/gid %d!\n",
				fname, EXPORTSOWNERUID, EXPORTSOWNERGID);
		Dprintf(L_ERROR, "exiting because of security violation.\n");
		exit(1);
	}
#endif

	if ((ef = fopen(fname, "r")) == NULL) {
		Dprintf(L_ERROR, "Could not open exports file %s: %s\n",
			fname, strerror(errno));
		exit(1);
	}
	while (export_getline(&cp, ef)) {
		char		*saved_line = cp;
		char		*mount_point, *host_name, cc;
		nfs_client	*clnt;
		nfs_mount	*mnt;
		int		len, has_anon = 0;

		while (isspace(*cp))
			cp++;

		/* Check for "empty" lines. */
		if (*cp == '\0')
			goto nextline;

		/* Get the file-system name. */
		fs_name = cp;
		while (*cp != '\0' && !isspace(*cp))
			cp++;
		for (len = cp-fs_name; len > 1 && fs_name[len-1] == '/'; len--)
			;
		memcpy(path, fs_name, len);
		path[len] = '\0';

		/* Make sure it's symlink-free, if possible. */
		if (realpath(path, resolved_path) == NULL)
			strcpy(resolved_path, path);

		/* Copy it into a new string. */
		mount_point = xstrdup(resolved_path);

		while (isspace(*cp))
			cp++;

		/* Check for the magic hostname =public to set the public
		 * root directory */
		if (!strncmp(cp, "=public", 7)) {
			for (sp = cp + 7; isspace(*sp); sp++)
				;
			if (*sp != '\0') {
				Dprintf(L_ERROR,
					"Malformed =public entry, ignoring\n");
			} else
			if (public_root_path) {
				Dprintf(L_ERROR,
					"Duplicate public root path given\n");
			} else {
				public_root_path = mount_point;
			}
			continue;
		}

		/* Build the RPC mount export list data structure. */
		resex = (exportnode *) xmalloc(sizeof *resex);
		resex->ex_dir = xstrdup(path);
		resex->ex_groups = NULL;

#ifndef NEW_STYLE_EXPORTS_FILE
		/* Special case for anononymous NFS. */
		if (*cp == '\0') {
			clnt = get_client(NULL);
			mnt = auth_add_mount(clnt, mount_point, 1);
			has_anon = 1;
		}
		while (*cp != '\0') {
			host_name = cp;

			/* Host name. */
			while (*cp != '\0' && !isspace(*cp) && *cp != '(')
				cp++;
			cc = *cp; *cp = '\0';
			clnt = get_client(host_name);
			*cp = cc;

			mnt = auth_add_mount(clnt, mount_point, 1);

			/* Finish parsing options. */
			while (isspace(*cp))
				cp++;
			if (*cp == '(')
				cp = parse_opts(cp + 1, ')', mnt,
						clnt->clnt_name);

			/* Don't enter noaccess entries to the overall list
			 * of exports */
			if (!mnt->o.noaccess) {
				resgr = (groupnode *) xmalloc(sizeof(*resgr));
				resgr->gr_name = clnt->clnt_name;
				resgr->gr_next = resex->ex_groups;
				resex->ex_groups = resgr;
			}

			if (clnt->clnt_name == NULL)
				has_anon = 1;

#ifndef ENABLE_UGID_DAEMON
			if (mnt->o.uidmap == map_daemon) {
				Dprintf(L_ERROR,
					"Error: %s:%s specifies map_daemon, "
					"but ugidd support not compiled in. "
					"Forcing all_squash option.",
					clnt->clnt_name? clnt->clnt_name : "world",
					mount_point);
				mnt->o.all_squash = 1;
			}
#endif /* ENABLE_UGID_DAEMON */
		}
#endif
		/* If the group contains an anon export, resex->ex_groups
		 * should be NULL */
		if (has_anon) {
			while((resgr = resex->ex_groups) != NULL) {
				resex->ex_groups = resgr->gr_next;
				free(resgr);
			}
		}

		resex->ex_next = export_list;
		export_list = resex;

	nextline:
		free(saved_line);
	}
	fclose(ef);

	if (promiscuous)
		auth_create_default_client();

#if 0 /* can't do that here-- fh module isn't initialized yet  */
	/*
	 * If we have a public root, build the FH now.
	 */
	if (public_root_path) {
		if (fh_create(&public_root, public_root_path) != 0) {
			Dprintf(L_ERROR,
				"%s: Can't build public root FH\n",
				public_root_path);
			free(public_root_path);
			public_root_path = 0;
		}
	}
#endif

	/*
	 * Finally, resolve any mount points for netgroup and wildcard
	 * hosts that apply to known hosts as well.
	 */
	auth_check_all_netmasks();
	auth_check_all_netgroups();
	auth_check_all_wildcards();
	auth_sort_all_mountlists();
	auth_log_all();

#if defined(MAYBE_HAVE_SETFSUID) && !defined(HAVE_SETFSUID)
	/* check if the a.out setfsuid syscall works on this machine */
	have_setfsuid = (setfsuid(0) >= 0);
#endif

	auth_initialized = 1;
}

/* 
 * Clear the export list.
 */
static void
free_exports()
{
	exportnode	*ex, *nex;
	groupnode	*gr, *ngr;

	for (ex = export_list; ex != NULL; ex = nex) {
		nex = ex->ex_next;
		free (ex->ex_dir);
		for (gr = ex->ex_groups; gr != NULL; gr = ngr) {
			ngr = gr->gr_next;
			/* gr->gr_name has already been freed in auth.c */
			free (gr);
		}
		free (ex);
	}
	export_list = NULL;
}

#if 0
static char *h_strerror(errnum)
int errnum;
{
	char *reason;

	switch (h_errno) {
#ifdef HOST_NOT_FOUND		/* Only on BSD 4.3 and compatible systems. */
	case HOST_NOT_FOUND:
		reason = "Authoritative -- the host exists only in your imagination.";
		break;
	case TRY_AGAIN:
		reason = "Non-Authoritative -- the host might exist.";
		break;
	case NO_RECOVERY:
		reason = "Non-recoverable error.";
		break;
	case NO_ADDRESS:
		reason = "Valid host name, but no address.";
		break;
#endif
	default:
		reason = "Unknown reason.";
	}
	return reason;
}
#endif
