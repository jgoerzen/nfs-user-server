/*
 * A set of support routines for /etc/rmtab file managment. These routines
 * are called from mountd.c.
 *
 * Written and Copyright by Dariush Shirazi, <dshirazi@uhl.uiowa.edu>
 *
 */

#include "nfsd.h"
#include "rmtab.h"

static char *	rmtab_gethost(struct svc_req *);
static int	rmtab_insert(char *, char *);
static void	rmtab_file(char);

/*
 * global top to linklist
 */

static mountlist rmtablist = NULL;

/*
 * rmtab_add_client -- if client+path not in the list, add them.
 */

void
rmtab_add_client(dirpath path, struct svc_req *rqstp)
{
	char		*hostname;

	hostname = rmtab_gethost(rqstp);
	if (hostname != NULL) {
		rmtab_file('r');
		if (rmtab_insert(hostname, path))
			rmtab_file('w');
	}
}

/*
 * rmtab_lst_client -- return the top pointer.
 */

mountlist *
rmtab_lst_client(void)
{
	rmtab_file('r');
	return(&rmtablist);
}

/*
 * rmtab_del_client -- delete a client+path
 */

void
rmtab_del_client(dirpath path, struct svc_req *rqstp)
{
	int		p0, p1, changed;
	char		*hostname;
	mountlist	cur, prv;

	hostname = rmtab_gethost(rqstp);
	Dprintf(D_RMTAB, "\trmtab_del path='%s' host='%s'\n", path, hostname);
	if (hostname == NULL)
		return;

	rmtab_file('r');
	changed = 0;

	for (cur = rmtablist, prv = NULL; cur; cur = cur->ml_next) {
		p0 = strcmp(cur->ml_hostname, hostname);
		p1 = strcmp(cur->ml_directory, path);
		if (p0 == 0 && p1 == 0)
			break;				/* already exists */
		prv = cur;
	}

	if (cur) {
		/*
		 * don't free both ml_hostname & ml_directory.
		 * See rmtab_insert for details.
		 */
		free(cur->ml_hostname);
		if (prv)
			prv->ml_next = cur->ml_next;
		else
			rmtablist    = cur->ml_next;
		free(cur);

		changed = 1;
	}

	if (changed)
		rmtab_file('w');
}

/*
 * rmtab_mdel_client -- delete all the entry points for a client
 */

void
rmtab_mdel_client(struct svc_req *rqstp)
{
	int		p0, changed;
	char		*hostname;
	mountlist	cur, prv, tmp;

	hostname = rmtab_gethost(rqstp);
	Dprintf(D_RMTAB, "\trmtab_mdel host='%s'\n", hostname);
	if (hostname == NULL)
		return;

	rmtab_file('r');
	changed = 0;

	prv     = NULL;
	cur     = rmtablist;
	while (cur) {
		p0 = strcmp(cur->ml_hostname, hostname);
		if (p0 == 0) {
			/*
			 * don't free both ml_hostname & ml_directory.
			 * See rmtab_insert for details.
			 */
			tmp = cur;
			cur = cur->ml_next;
			if (prv)
				prv->ml_next = cur;
			else
				rmtablist    = cur;
			free(tmp->ml_hostname);
			free(tmp);

			changed = 1;
		} else if (p0 < 0) {
			prv = cur;
			cur = cur->ml_next;
		} else
			break;				/* not found */
	}

	if (changed)
		rmtab_file('w');
}

/*
 * rmtab_gethost -- return the hostname
 */

static char *
rmtab_gethost(struct svc_req *rqstp)
{
	struct hostent *hp;
        struct in_addr addr;

	addr = svc_getcaller(rqstp->rq_xprt)->sin_addr;
	hp   = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET);

	if (hp)
		return((char *) hp->h_name);

	return((char *) NULL);
}

/*
 * rmtab_insert -- a sorted link list
 */

static int
rmtab_insert(char *hostname, char *path)
{
	int		hostlen, p0, p1;
	mountlist	cur, prv;

	Dprintf(D_RMTAB, "\trmtab_insert path='%s' host='%s'\n",
				path, hostname);

	for (cur = rmtablist, prv = NULL; cur; cur = cur->ml_next) {
		p0 = strcmp(cur->ml_hostname, hostname);
		p1 = strcmp(cur->ml_directory, path);
		if (p0 > 0 || (p0 == 0 && p1 > 0))
			break;				/* insert here */
		else if (p0 == 0 && p1 == 0)
			return(0);			/* already exists */
		prv = cur;
	}

	if ((cur = (mountlist) malloc(sizeof(mountbody))) == NULL) {
		Dprintf(L_ERROR, "failed to allocate memory for mountbody\n");
		return(0);
	}
	/*
	 * since the data we are storing is really small (ie. h.x.y.z:/cur),
	 * allocate one memory unit for both and split it.
	 */
	hostlen = strlen(hostname);
	if ((cur->ml_hostname = (char *) malloc(hostlen+strlen(path)+2)) == NULL) {
		Dprintf(L_ERROR, "failed to allocate memory for mountlist buffer\n");
		free(cur);
		return(0);
	}
	cur->ml_directory = cur->ml_hostname + (hostlen + 1);

	strcpy(cur->ml_hostname, hostname);
	strcpy(cur->ml_directory, path);

	if (prv) {
		cur->ml_next = prv->ml_next;
		prv->ml_next = cur;
	} else {
		cur->ml_next = rmtablist;
		rmtablist    = cur;
	}
	return(1);
}

/*
 * rmtab_file -- read/write the mount list from/to rmtab file.
 */

static void
rmtab_file(char op)
{
	register int	c, len;
	register char	*p;
	char		buff[256], *host, *path;
	FILE		*fp;
	mountlist	cur;
	struct stat	newstat;

	static time_t 	old_st_mtime = 0;

	if (op == 'r') {				/* read&update llist */

		/*
		 * get a new stat; if file not there, create it
		 */
		if (stat(_PATH_RMTAB, &newstat)) {
			int	zappa;

			if ((zappa = creat(_PATH_RMTAB, 0644)) < 0) {
				Dprintf(L_ERROR, "failed to create '%s'\n",
								_PATH_RMTAB);
				umask(0);
				return;
			}
			close(zappa);
			umask(0);

			if (stat(_PATH_RMTAB, &newstat)) {
				Dprintf(L_ERROR, "failed to stat '%s'\n",
								_PATH_RMTAB);
				return;
			}
			old_st_mtime = newstat.st_mtime;
			return;
		}

		if (old_st_mtime == newstat.st_mtime)
			return;				/* no change */

		if ((fp = fopen(_PATH_RMTAB, "r")) == NULL) {
			Dprintf(L_ERROR, "failed to open '%s'\n", _PATH_RMTAB);
			return;
		}

		while (rmtablist) {			/* free the old list */
			cur       = rmtablist;
			rmtablist = rmtablist->ml_next;
			/*
			 * don't free both ml_hostname & ml_directory.
			 * See rmtab_insert for details.
			 */
			free(cur->ml_hostname);
			free(cur);
		}

		while (! feof(fp)) {
			/*
			 * the reason this looks worse than it should is so
			 * we don't have to do bunch of passes on the buff.
			 * (fgets,strlen,strchr...)
			 */
			p    = buff;
			host = buff;
			path = NULL;
			len  = c = 0;
			while (!feof(fp) && (c = fgetc(fp))!='\n' && len<255) {
				if (c == ':') {
					c    = '\0';
					path = p+1;
				}
				*p++ = (char) c;
				len++;
			}
			*p = '\0';

			while (!feof(fp) && c != '\n')	/* skip if line > 255 */
				c = fgetc(fp);

			if (path)			/* skip bad input */
				if (*host && *path)
					rmtab_insert(host, path);
		}
		fclose(fp);
		old_st_mtime = newstat.st_mtime;

	} else if (op == 'w') {				/* write from llist */

		if ((fp = fopen(_PATH_RMTAB, "w")) == NULL) {
			Dprintf(L_ERROR, "failed to open '%s'\n", _PATH_RMTAB);
			return;
		}
		for (cur = rmtablist; cur; cur = cur->ml_next)
			fprintf(fp, "%s:%s\n", cur->ml_hostname,
					       cur->ml_directory);
		fclose(fp);

		if (stat(_PATH_RMTAB, &newstat)) {
			Dprintf(L_ERROR, "failed to stat '%s'\n", _PATH_RMTAB);
			fclose(fp);
			return;
		}
		old_st_mtime = newstat.st_mtime;

	} else
		Dprintf(L_ERROR, "rmtab_file bad flag '%c'\n", op);
}
