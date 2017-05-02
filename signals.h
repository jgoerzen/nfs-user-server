/*
 * signals.h
 *
 * Signal handling
 */

#ifndef SIGNALS_H
#define SIGNALS_H

extern void install_signal_handler(int signo, RETSIGTYPE (*handler)(int));
extern void ignore_signal(int signo);

#endif /* SIGNALS_H */
