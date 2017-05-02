/*
 * Signal handling
 *
 * Copyright (C) 1998, Olaf Kirch <okir@monad.swb.de>
 */

#include "system.h"
#include "signals.h"

#ifdef HAVE_BSD_SIGNALS
/*
 * BSD signal semantics, i.e. no need to reinstall signal handler
 */
void
install_signal_handler(int signo, RETSIGTYPE (*handler)(int))
{
	(void) signal(signo, handler);
}
#else
/*
 * Hopefully we have POSIX signals...
 */
void
install_signal_handler(int signo, RETSIGTYPE (*handler)(int))
{
	struct sigaction	act;

	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_handler = handler;

	sigaction(signo, &act, NULL);
}
#endif

/*
 * Currently, common for both flavors
 */
void
ignore_signal(int signo)
{
	(void) signal(signo, SIG_IGN);
}
