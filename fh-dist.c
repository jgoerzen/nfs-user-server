/*
 * fh-dist.c
 *
 * Gauge the deviation in different 8bit hash algorithms for
 * unfsd file handles.
 *
 * Usage:
 *	fh-dist [options] pathname
 *		Traverse pathname, processing inode numbers
 *	fh-dist [options] -
 *		Read inode number list (produced via fh-dist -p)
 *		from stdin.
 *
 * Options:
 *	-s	print statistics about inode hash distribution
 *	-d	print statistics for directories only
 *	-p	print out inode information usable by a later fh-dist run
 *	-x	print inode numbers in hex
 *	-X	don't cross mount points
 *	-D	turn on debugging messages.
 *		Repeating this option increases verbosity.
 *	
 * If neither -s nor -p is used, -s is assumed.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>

#define PSI_STYLE_ANY		-1
enum {
	PSI_MANGLE_XOR8 = 0,
	PSI_DEVTAB_XOR8,
	PSI_MANGLE_LOW8,
	PSI_DEVTAB_LOW8,
	PSI_MANGLE_SUM8,
	PSI_DEVTAB_SUM8,
	PSI_MANGLE_SKEW,
	PSI_DEVTAB_SKEW,

	PSI_STYLE_MAX
};

static int	opt_print = 0,
		opt_stats = 0,
		opt_debug = 0,
		opt_dironly = 0,
		opt_fileonly = 0,
		opt_onedev = 0,
		opt_histogram = 0;
static char *	psi_fmt = "%s 0x%x %lu\n";
static char *	psi_style_name[] = {
	"mangle/xor8",
	"devtab/xor8",
	"mangle/low8",
	"devtab/low8",
	"mangle/sum8",
	"devtab/sum8",
	"mangle/skew",
	"devtab/skew",
};

struct istat {
	unsigned long	count;
	unsigned long	freq[PSI_STYLE_MAX][256];
};

static void		parse(FILE *, struct istat *, struct istat *);
static void		find(const char *, struct istat *, struct istat *);
static void		collect(struct istat *stats, dev_t dev, ino_t ino);
static void		print_stats(const char *what, struct istat *stats);
static void		print_hist(const char *what, struct istat *stats,
				const char *style, unsigned int fold);
static unsigned long	psi_mangle(dev_t dev, ino_t ino);
static int		psi_style(const char *);

#define hash_low8(n)	((n) & 0xff)
#define hash_xor8(n)	(((n) ^ ((n)>>8) ^ ((n)>>16) ^ ((n)>>24)) & 0xff)
#define hash_sum8(n)	(((n) + ((n)>>8) + ((n)>>16) + ((n)>>24)) & 0xff)
#define hash_skew(n)	(((n) + 3 * ((n) >> 8) + 5 * ((n) >> 16)) & 0xff)

int
main(int argc, char **argv)
{
	struct istat	dirs, files;
	unsigned int	hist_fold = 1;
	const char	*style = 0;
	int		c;

	while ((c = getopt(argc, argv, "Ddfh:H:psXx")) != -1) {
		switch (c) {
		case 'D':
			opt_debug++;
			break;
		case 'd':
			opt_dironly = 1;
			break;
		case 'f':
			opt_fileonly = 1;
			break;
		case 'h':
			opt_histogram = 1;
			hist_fold = atoi(optarg);
			break;
		case 'H':
			if (psi_style(optarg) < 0) {
				fprintf(stderr,
					"invalid PSI style %s\n", optarg);
				exit(1);
			}
			style = optarg;
			break;
		case 'p':
			opt_print = 1;
			break;
		case 's':
			opt_stats = 1;
			break;
		case 'X':
			opt_onedev = 1;
			break;
		case 'x':
			psi_fmt = "%s 0x%x 0x%08lx\n";
			break;
		default:
			fprintf(stderr, "invalid argument.\n");
			exit(1);
		}
	}

	switch (opt_stats + opt_print + opt_histogram) {
	case 0:
		opt_stats = 1;
		break;
	case 1:
		break;
	default:
		fprintf(stderr, "you can specify only one of -s, -p, -h\n");
		exit(1);
	}

	if (optind != argc - 1) {
		fprintf(stderr, "path name missing.\n");
		exit(1);
	}

	memset(&dirs, 0, sizeof(dirs));
	memset(&files, 0, sizeof(files));
	if (!strcmp(argv[optind], "-"))
		parse(stdin, &files, &dirs);
	else
		find(argv[optind], &files, &dirs);

	if (opt_stats) {
		if (!opt_dironly)
			print_stats("files", &files);
		if (!opt_fileonly)
			print_stats("directories", &dirs);
	} else if (opt_histogram) {
		if (!opt_dironly)
			print_hist("files", &files, style, hist_fold);
		if (!opt_fileonly)
			print_hist("directories", &dirs, style, hist_fold);
	}

	return 0;
}

static void
print_hist(const char *what, struct istat *stats,
		const char *style, unsigned int fold)
{
	unsigned int	i, j, k, max;
	unsigned long	hist[256];
	int		y, m;

	if (style == 0) {
		for (m = 0; m < PSI_STYLE_MAX; m++)
			print_hist(what, stats, psi_style_name[m], fold);
		return;
	}

	m = psi_style(style);
	for (i = 0, max = 0; i < 256; i += fold) {
		for (j = 0, k = 0; j < fold; j++) {
			k += stats->freq[m][i+j];
		}
		hist[i / fold] = k;
		if (k > max)
			max = k;
	}

	printf("%s: %lu total, histogram for %s style hash\n\n",
		what, stats->count, style);

	for (y = 23; y >= 0; y--) {
		for (j = 0; j < 256 / fold; j++) {
			k = hist[j];
			if ((k * 23 + (max >> 1)) / max >= y)
				putc('*', stdout);
			else
				putc(' ', stdout);
		}
		putc('\n', stdout);
	}

	putc('\f', stdout);
}

static int
cmpbucket(const void *ap, const void *bp)
{
	unsigned long	a, b;

	a = *(unsigned long *) ap;
	b = *(unsigned long *) bp;
	return (a > b)? -1 : ((a < b)? 1 : 0);
}

static void
print_stats(const char *what, struct istat *stats)
{
	double		avg, ssq, delta, sigma, top5, top10;
	unsigned long	total;
	int		i, j;

	total = stats->count;
	avg   = (double) total / 256;

	printf("%s: %lu total, avg %4.2f per hash bucket.\n",
			what, total, avg);
	printf("   psi style     sum of squares   mean deviation  Top5      Top10\n");

	for (i = 0; i < PSI_STYLE_MAX; i++) {
		ssq = sigma = 0;
		for (j = 0; j < 256; j++) {
			delta = (double) stats->freq[i][j] - avg;
			ssq += delta * delta;
		}
		if (total > 1)
			sigma = ssq / (total - 1);

		if (opt_debug) {
			printf("    buckets:       ");
			for (j = 0; j < 256; j++) {
				printf(" %3ld", stats->freq[i][j]);
				if ((j & 15) == 15 && j != 255)
					printf("\n                   ");
			}
			printf("\n");
		}

		/* Compute top5 and top10 percentage */
		qsort(stats->freq[i], 256,
				sizeof(stats->freq[i][0]), cmpbucket);
		for (j = 0, top5 = 0; j < 5; j++)
			top5 += stats->freq[i][j];
		for (top10 = top5; j < 10; j++)
			top10 += stats->freq[i][j];
		top5  = 100 * top5  / (total? total : 1);
		top10 = 100 * top10 / (total? total : 1);

		printf("  %-10s      %10.2f       %6.2f       %5.2f%%     %5.2f%%\n",
				psi_style_name[i], ssq, sigma, top5, top10);
	}
}

static void
parse(FILE *fp, struct istat *files, struct istat *dirs)
{
	char		buffer[512], *sp, type;
	unsigned long	dev, ino;

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		sp = buffer;
		type = *sp++;
		while (isspace(*sp)) sp++;
		dev = strtoul(sp, &sp, 0);
		if (!isspace(*sp))
			goto bad;
		while (isspace(*sp)) sp++;
		ino = strtoul(sp, &sp, 0);
		if (!isspace(*sp) && *sp != '\0')
			goto bad;

		if (type == 'd') {
			collect(dirs,  dev, ino);
			files->count++;
		} else {
			collect(files, dev, ino);
		}
	}

	return;

bad:
	fprintf(stderr, "unable to parse: %s\n", buffer);
	exit(1);
}

static void
find(const char *path, struct istat *files, struct istat *dirs)
{
	DIR		*dir;
	struct dirent	*dp;
	struct stat	s;
	ino_t		ino;
	dev_t		cwd_dev;

	if (stat(path, &s) < 0 || chdir(path) < 0) {
		perror(path);
		return;
	}
	if ((dir = opendir(".")) == NULL) {
		perror(path);
		goto out;
	}

	cwd_dev = s.st_dev;

	while ((dp = readdir(dir)) != NULL) {
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (lstat(dp->d_name, &s) < 0) {
			perror(dp->d_name);
			continue;
		}

		/* We use the dirent ino rather than the one returned
		 * by lstat. For mount points, the former will refer to
		 * the ino on the directory's partition, while the latter
		 * will return the root of the mount point. */
		ino = dp->d_ino;

		if (S_ISDIR(s.st_mode)) {
			collect(dirs, cwd_dev, ino);
			files->count++;
			if (!opt_onedev || s.st_dev == cwd_dev)
				find(dp->d_name, files, dirs);
		} else {
			collect(files, cwd_dev, ino);
		}

		if (opt_print)
			printf(psi_fmt, S_ISDIR(s.st_mode)? "d" : "-",
				cwd_dev, ino);
	}
	closedir(dir);

out:
	chdir("..");
}

static void
collect(struct istat *stats, dev_t dev, ino_t ino)
{
	unsigned long	psi;

	psi = psi_mangle(dev, ino);
	stats->freq[PSI_MANGLE_XOR8][hash_xor8(psi)]++;
	stats->freq[PSI_DEVTAB_XOR8][hash_xor8(ino)]++;
	stats->freq[PSI_MANGLE_LOW8][hash_low8(psi)]++;
	stats->freq[PSI_DEVTAB_LOW8][hash_low8(ino)]++;
	stats->freq[PSI_MANGLE_SUM8][hash_sum8(psi)]++;
	stats->freq[PSI_DEVTAB_SUM8][hash_sum8(ino)]++;
	stats->freq[PSI_MANGLE_SKEW][hash_skew(psi)]++;
	stats->freq[PSI_DEVTAB_SKEW][hash_skew(ino)]++;
	stats->count++;

	if (opt_debug >= 2) {
		printf("%04x %08lx %08lx %3ld %3ld %3ld %3ld %3ld %3ld\n",
			dev, (unsigned long) ino, psi,
			hash_xor8(psi), hash_low8(psi), hash_sum8(psi),
			hash_xor8(ino), hash_low8(ino), hash_sum8(ino));
	}
}

static unsigned long
psi_mangle(dev_t dev, ino_t ino)
{
	unsigned long		dmajor, dminor;

	/*
         * Assuming major and minor numbers are small integers,
         * gravitate bits of dmajor & dminor device number to
         * high-order bits of word, to avoid clash with real inode num.
         */
	/* reverse (byte-wise) */
#if SIZEOF_DEV_T == 4
	dev = (((dev >> 16) & 0xff00) ^ ((dev >> 8) & 0xff00)) | 
	      (((dev >> 8) & 0xff) ^ (dev & 0xff));
#endif
	dmajor = ((dev & 0xf0f) << 4) | ((dev & 0xf0f0) >> 4);
	dmajor = ((dmajor & 0x3333) << 2) | ((dmajor & 0xcccc) >> 2);
	dmajor = ((dmajor & 0x5555) << 1) | ((dmajor & 0xaaaa) >> 1);

	/* spread low-16 -> 32 with 0's in even posn */
	dmajor = ((dmajor & 0xff00) << 8) | (dmajor & 0xff);
	dmajor = ((dmajor & 0xf000f0) << 4) | (dmajor & 0xf000f);
	dmajor = ((dmajor & 0xc0c0c0c) << 2) | (dmajor & 0x3030303);
	dmajor = ((dmajor & 0x22222222) << 1) | (dmajor & 0x11111111);
	dminor = (dmajor & 0x5555) << 15;
	dmajor = dmajor & 0x55550000;

	return ((dmajor | dminor) ^ ino);
}

static int
psi_style(const char *style)
{
	unsigned int	m;

	for (m = 0; m < PSI_STYLE_MAX; m++) {
		if (!strcmp(psi_style_name[m], style))
			return m;
	}
	return -1;
}
