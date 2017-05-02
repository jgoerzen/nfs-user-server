/*
 *  resched (Roman Drahtmueller <draht@uni-freiburg.de>
 *
 *  delivers a process to another scheduling class policy.
 *
 *  CAUTION: Handle with care and read the manpage before you use it.
 *           CPU-intesive processes will not return before they are
 *           finished or blocked on I/O. (This means that it could 
 *           hang your machine, luser!)
 *
 *  Use as you wish. The author is not responsible for
 *  damages that could result from using this software.
 *  Permission granted to distribute at will.
 *
 */

#ifdef linux
# include <getopt.h>
#else
/* Solaris: cc -lposix4 -o resched resched.c */
# include <stdlib.h>
#endif

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

static void
usage(int exitcode)
{
	fprintf(stderr,
		"\nUsage: resched -p <priority> [-s|-f|-r] <pid>\n"
		"\t-s     use SCHED_OTHER scheduling (default queue)\n"
		"\t-f     use SCHED_FIFO\n"
		"\t-r     use SCHED_RR\n"
		"\t-s == SCHED_OTHER, -f == SCHED_FIFO, -r SCHED_RR\n"
		"\n"
		"Handle with care and read the documentation\n"
		"about scheduling classes before you use this program!\n\n");
	exit(exitcode);
}

int
main(int argc, char ** argv)
{
	struct sched_param priority;
	char		c;
	int		pid = -1, policy = SCHED_OTHER;

	priority.sched_priority = 1;
	while ((c = getopt(argc, argv, "fhp:rs")) != EOF) {
		switch (c) {
		case 'p':
			priority.sched_priority = atoi(optarg);
			break;
		case 's':
			policy = SCHED_OTHER;
			break;
		case 'f':
			policy = SCHED_FIFO;
			break;
		case 'r':
			policy = SCHED_RR;
			break;
		case 'h':
			usage(1);
		default:
			policy = SCHED_OTHER;
			break;
		}
	}

	if (argc - optind == 1) {
		pid = atoi(argv[optind]);
	} else if (argc - optind != 0) {
		usage(1);
	}

	if (policy == SCHED_OTHER)
		priority.sched_priority = 0;

	printf("calling sched_setscheduler: "
		"pid: %i priority: %i policy = %i \n",
		pid, priority.sched_priority, policy);

	if (sched_setscheduler(pid, policy, &priority) < 0) {
		perror("sched_setscheduler");
		usage(-1);
	}

	exit(0);
}
