/*
 * failsafe.c
 *
 * Copyright (C) 1998, <okir@monad.swb.de>
 *
 * Implements fail-safe mode for nfsd/mountd.
 */

#include "system.h"
#include "logging.h"
#include "signals.h"
#include <sys/wait.h>
#ifdef HAVE_STRSIGNAL
#include <string.h>
#else

static const char *	get_signame(int signo);
#endif

void
failsafe(int level, int ncopies)
{
	int	*servers, running, child, i;
	int	pid, signo, status;
	time_t	last_restart = 0, now;
	int	restarts = 0, backoff = 60;

	servers = (int *) xmalloc(ncopies * sizeof(int));
	memset(servers, 0, ncopies * sizeof(int));

	/* Loop forever, until we get SIGTERM */
	running = 0;
	while (1) {
		while (running < ncopies) {
			if ((now = time(NULL)) == last_restart) {
				if (++restarts > 2 * ncopies) {
					Dprintf(L_ERROR,
						"Servers restarting too "
						"quickly, backing off.");
					if (backoff < 60 * 60)
						backoff <<= 1;
					sleep(backoff);
				}
			} else {
				last_restart = now;
				restarts = 0;
				backoff = 60;
			}

			/* Locate a free pid slot */
			for (i = 0, child = -1; i < ncopies; i++) {
				if (servers[i] == 0) {
					child = i;
					break;
				}
			}

			if (child < 0)
				Dprintf(L_FATAL, "failsafe: no pid slot?!");

			Dprintf(D_GENERAL,
				"starting server thread %d...\n", child + 1);

			pid = fork();
			if (pid < 0)
				Dprintf(L_FATAL,
					"Unable to fork for failsafe: %s",
					strerror(errno));

			if (pid == 0) {
				/* Child process: continue with execution. */
				return;
			}

			servers[child] = pid;
			running++;
		}

		/* Ignore some signals */
		ignore_signal(SIGTERM);
		ignore_signal(SIGHUP);
		ignore_signal(SIGINT);
		ignore_signal(SIGCHLD);

		if ((pid = wait(&status)) < 0) {
			Dprintf((errno == ECHILD)? L_FATAL : L_WARNING,
				"failsafe: wait(): %s", strerror(errno));
			continue;
		}

		/* Locate the child */
		for (i = 0, child = -1; i < ncopies; i++) {
			if (servers[i] == pid) {
				child = i;
				break;
			}
		}

		if (child < 0) {
			Dprintf(L_WARNING,
				"failsafe: unknown child (pid %d) terminated",
				pid);
			continue;
		}

		/* Book-keeping */
		servers[child] = 0;
		running--;

		if (WIFSIGNALED(status)) {
			signo = WTERMSIG(status);
			if (signo == SIGTERM) {
				Dprintf(L_NOTICE, "failsafe: "
					"child %d terminated by SIGTERM. %s.",
					pid, running? "Continue" : "Exit");
			} else {
				Dprintf(L_WARNING, "failsafe: "
#ifdef HAVE_STRSIGNAL
					"child %d terminated by: %s. "
#else
					"child %d terminated by %s. "
#endif
					"Restarting.",
#ifdef HAVE_STRSIGNAL
					pid, strsignal(signo));
#else
					pid, get_signame(signo));
#endif
				child = -1; /* Restart */
			}
		} else if (WIFEXITED(status)) {
			Dprintf(L_NOTICE, "failsafe: "
				"child %d exited, status %d.",
				pid, WEXITSTATUS(status));
		} else {
			Dprintf(L_ERROR, "failsafe: "
				"abnormal child termination, "
				"pid=%d status=%d. Restarting.",
				pid, status);
			child = -1; /* Restart */
		}

		/* If child >= 0, we should not restart */
		if (child >= 0) {
			if (!running) {
				Dprintf(D_GENERAL,
					"No more children, exiting.");
				exit(0);
			}
			for (i = child; i < ncopies-1; i++)
				servers[i] = servers[i+1];
			ncopies--; /* Make sure we start no new servers */
		}
	}
}

/*
 * Failsafe session, catch core file.
 *
 * Not yet implemented.
 * General outline: we need to fork first, because nfsd changes
 * uids frequently, and the kernel won't write out a core file after
 * that. The forked proc starts out with a clean dumpable flag though.
 *
 * After the fork, we might want to make sure we end up in some common
 * directory that the failsafe loop knows about.
 */
void
failsafe_loop(int level, void (*function)(void))
{
	/* NOP */
}

#ifndef HAVE_STRSIGNAL
static const char *
get_signame(int signo)
{
	static char	namebuf[30];

	switch (signo) {
	case SIGHUP:	return "SIGHUP";
	case SIGINT:	return "SIGINT";
	case SIGQUIT:	return "SIGQUIT";
	case SIGILL:	return "SIGILL";
	case SIGTRAP:	return "SIGTRAP";
	case SIGIOT:	return "SIGIOT";
	case SIGBUS:	return "SIGBUS";
	case SIGFPE:	return "SIGFPE";
	case SIGKILL:	return "SIGKILL";
	case SIGUSR1:	return "SIGUSR1";
	case SIGSEGV:	return "SIGSEGV";
	case SIGUSR2:	return "SIGUSR2";
	case SIGPIPE:	return "SIGPIPE";
	case SIGALRM:	return "SIGALRM";
	case SIGTERM:	return "SIGTERM";
	case SIGCHLD:	return "SIGCHLD";
	case SIGCONT:	return "SIGCONT";
	case SIGSTOP:	return "SIGSTOP";
	case SIGTSTP:	return "SIGTSTP";
	case SIGTTIN:	return "SIGTTIN";
	case SIGTTOU:	return "SIGTTOU";
	case SIGURG:	return "SIGURG";
	case SIGXCPU:	return "SIGXCPU";
	case SIGXFSZ:	return "SIGXFSZ";
	case SIGVTALRM:	return "SIGVTALRM";
	case SIGPROF:	return "SIGPROF";
	case SIGWINCH:	return "SIGWINCH";
	case SIGIO:	return "SIGIO";
	case SIGPWR:	return "SIGPWR";
	}

	sprintf(namebuf, "signal #%d", signo);
	return namebuf;
}
#endif
