/*
 * logging	This module handles the logging of requests.
 *
 * TODO:	Merge the two "XXX_log() calls.
 *
 * Authors:	Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "nfsd.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#define LOG_FILE	"/var/tmp/%s.log"
#endif

static int  logging = 0;		/* enable/disable DEBUG logs	*/
static int  dbg_mask = D_GENERAL;	/* What will be logged		*/
static char log_name[256];		/* name of this program		*/
static FILE *log_fp = (FILE *)NULL;	/* fp for the log file		*/

void
log_open(char *progname, int foreground)
{
#ifdef HAVE_SYSLOG_H
	openlog(progname, LOG_PID | LOG_NDELAY, LOG_DAEMON );
	if (foreground)
		log_fp = stderr;
#else
	if (foreground) {
		log_fp = stderr;
	} else {
		char path[1024];

		sprintf(path, LOG_FILE, progname);
		logfile = path;
		if ((log_fp = fopen(path, "a")) == NULL)
			return;
	}
#endif
	if (log_fp != NULL)
		setbuf(log_fp, (char *) NULL);

	sprintf(log_name, "%s[%d]", progname, getpid());
}

void
log_close(void)
{
	if (log_fp) {
		fclose(log_fp);
		log_fp = 0;
	}
}


void
background_logging(void)
{
	if (log_fp == stderr)
		log_fp = NULL;
}

void
toggle_logging(int sig)
{
	Dprintf(D_GENERAL, "turned off logging\n");
	logging = 1 - logging;
	Dprintf(D_GENERAL, "turned on logging\n");
}

void
enable_logging(char *kind)
{
	if ('a' == *kind && !strcmp(kind, "auth"))
		dbg_mask |= D_AUTH;
	else if ('a' == *kind && !strcmp(kind, "all"))
		dbg_mask |= D_ALL;
	else if ('c' == *kind && !strcmp(kind, "call"))
		dbg_mask |= D_CALL;
	else if ('d' == *kind && !strcmp(kind, "devtab"))
		dbg_mask |= D_DEVTAB;
	else if ('f' == *kind && !strcmp(kind, "fhcache"))
		dbg_mask |= D_FHCACHE;
	else if ('f' == *kind && !strcmp(kind, "fhtrace"))
		dbg_mask |= D_FHTRACE;
	else if ('g' == *kind && !strcmp(kind, "general"))
		dbg_mask |= D_GENERAL;
	else if ('r' == *kind && !strcmp(kind, "rmtab"))
		dbg_mask |= D_RMTAB;
	else if ('s' == *kind && !strcmp(kind, "stale"))
		dbg_mask |= D_AUTH | D_CALL | D_FHCACHE | D_FHTRACE;
	else if ('u' == *kind && !strcmp(kind, "ugid"))
		dbg_mask |= D_UGID;
	else
		fprintf (stderr, "Invalid debug facility: %s\n", kind);
	logging = 1;
}

int
logging_enabled(int level)
{
	return (logging && (level & dbg_mask));
}


/* Write something to the system logfile. */
void
Dprintf(int kind, const char *fmt, ...)
{
	char buff[2048];
	va_list args;
	time_t now;
	struct tm *tm;

	if (!(kind & (L_FATAL | L_ERROR | L_WARNING | L_NOTICE))
	 && !(logging && (kind & dbg_mask)))
		return;

	va_start(args, fmt);
#ifdef HAVE_VPRINTF
	vsnprintf(buff, sizeof(buff)-1, fmt, args);
#else
	/* Figure out how to use _doprnt here. */
#endif
	va_end(args);

#ifdef HAVE_SYSLOG_H
	if (kind & (L_FATAL | L_ERROR)) {
		(void) syslog(LOG_ERR, "%s", buff);
	} else if (kind & L_WARNING) {
		(void) syslog(LOG_WARNING, "%s", buff);
	} else if (kind & L_NOTICE) {
		(void) syslog(LOG_NOTICE, "%s", buff);
	} else if (log_fp == NULL) {
		(void) syslog(LOG_DEBUG, "%s", buff);
	}
#endif
	if (log_fp != (FILE *) NULL) {
		(void) time(&now);
		tm = localtime(&now);
		fprintf(log_fp, "%s %02d/%02d/%02d %02d:%02d %s",
		      log_name, tm->tm_mon + 1, tm->tm_mday, tm->tm_year,
			tm->tm_hour, tm->tm_min, buff);
		if (strchr(buff, '\n') == NULL)
			fputc('\n', log_fp);
	}

	if (kind & L_FATAL)
		exit(1);
}

/*
 * Log an incoming call.
 */
void
log_call(struct svc_req *rqstp, char *xname, char *arg)
{
	char	buffer[4096];
	int	i, len, total;

	if (!logging || !(dbg_mask & D_CALL))
		return;

	total = sizeof(buffer);
	snprintf(buffer, total,
		"%s [%d ", xname, rqstp->rq_cred.oa_flavor);
	len = strlen(buffer);

	if (rqstp->rq_cred.oa_flavor == AUTH_UNIX) {
		struct authunix_parms *unix_cred;
		struct tm *tm;

		unix_cred = (struct authunix_parms *) rqstp->rq_clntcred;
		tm = localtime(&unix_cred->aup_time);
		snprintf(buffer + len, total - len,
			"%d/%d/%d %02d:%02d:%02d %s %d.%d",
			tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec,
			unix_cred->aup_machname,
			unix_cred->aup_uid,
			unix_cred->aup_gid);
		len = strlen(buffer);
		if ((int) unix_cred->aup_len > 0) {
			snprintf(buffer + len, total - len,
				"+%d", unix_cred->aup_gids[0]);
			len = strlen(buffer);
			for (i = 1; i < unix_cred->aup_len; i++) {
				snprintf(buffer + len, total - len,
					",%d", unix_cred->aup_gids[i]);
				len = strlen(buffer);
			}
		}
	}
	Dprintf(D_CALL, "%s]\n", buffer);
	if (arg && *arg)
		Dprintf(D_CALL, "\t%s\n", arg);
}
