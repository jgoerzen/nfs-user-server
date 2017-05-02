/*
 * devtab.c
 *
 * Mapping of disk device numbers to ids used in pseudo inode numbers.
 *
 * Pseudo inode numbers (psi's) are made up of a combination of an index,
 * representing a device number, and the inode. Generation of psi's
 * happens like this:
 *
 *   bit prefix		index		inode #		inode max
 *   0			3bits		28bits		268435456
 *   10			3bits		27bits		134217728
 *   110		3bits		26bits		67108864
 *   1110		3bits		25bits		33554432
 *   ...
 *
 * Even for people exporting 24 different partitions, the smallest
 * range of inode numbers we can represent is 25bits.
 *
 * For mapping device numbers to indices, we use a file
 * (/var/state/nfs/devtab), containing the names of the device files.
 * The reason to make this a human-readable file is that this allows
 * the administrator to reorder entries so that the biggest partitions
 * are named first, and thus receive a 28bit inode range.
 *
 * Beware that when modifying the device table, you must first kill
 * mountd and nfsd. Also make sure that no client has mounted a file
 * system from your server, otherwise they might be accessing random
 * files, with the possibility of hosing your entire system.
 *
 * Copyright (C) 1998, Olaf Kirch <okir@monad.swb.de>
 */

#include "system.h"
#include "logging.h"
#include "auth.h"

#ifdef ENABLE_DEVTAB

#ifndef PATH_DEVTAB
# define PATH_DEVTAB		"/var/state/nfs/devtab"
#endif
#define PATH_DEVTAB_LOCK	PATH_DEVTAB ".lock"


static void			devtab_read(void);
static void			devtab_lock(void);
static void			devtab_unlock(void);
static FILE *			devtab_open(const char *mode, struct stat *sbp);
static unsigned int		devtab_add(dev_t dev);
static const char *		devtab_getname(dev_t dev);

static dev_t *			devtab;
static unsigned int		nrdevs;
static time_t			devtab_mtime;
static int			devtab_locked = 0;

/*
 * Locate the index associated with the given device number
 */
unsigned int
devtab_index(dev_t dev)
{
	unsigned int	index;
	struct stat	stb;
	FILE		*fp;
	int		oldmask;

	/* First, try to find entry in device table */
	for (index = 0; index < nrdevs; index++) {
		if (devtab[index] == dev)
			return index;
	}

	if (logging_enabled(D_DEVTAB)) {
		Dprintf(D_DEVTAB, "Can't find device 0x%x (%s) in devtab.",
			dev, devtab_getname(dev));
	}

	/* Entry not found. We need to create a new entry. */

	/* Set proper credentials and umask */
	auth_override_uid(ROOT_UID);
	oldmask = umask(0);

	/* First, lock devtab file */
	devtab_lock();

	fp = devtab_open("a", &stb);
	if (stb.st_mtime != devtab_mtime) {
		Dprintf(D_DEVTAB, "%sreading devtab file.\n",
			devtab_mtime? "re" : "");
		fclose(fp);
		devtab_read();
		for (index = 0; index < nrdevs; index++) {
			if (devtab[index] == dev)
				goto done;
		}
		/* re-open devtab */
		fp = devtab_open("a", &stb);
	}

	/* Add the device to the in-core table */
	index = devtab_add(dev);

	/* Find the device name and append to devtab file */
	fprintf(fp, "%s\n", devtab_getname(dev));
	fclose(fp);

done:
	devtab_unlock();
	auth_override_uid(auth_uid);
	umask(oldmask);
	return index;
}

static void
devtab_lock(void)
{
	char		tempname[sizeof(PATH_DEVTAB)+16], buffer[64];
	unsigned int	retry = 0, maxretry = 10;
	int		fd, n;
	int		pid = getpid();

	if (devtab_locked)
		return;

	/* Create temporary lock file, and write our PID to it. */
	sprintf(tempname, "%s.%d", PATH_DEVTAB, pid);
	if ((fd = open(tempname, O_WRONLY|O_EXCL|O_CREAT, 0600)) < 0) {
		Dprintf(L_FATAL, "Unable to create %s: %s",
			tempname, strerror(errno));
		/* notreached */
	}
	sprintf(buffer, "%d", pid);
	write(fd, buffer, strlen(buffer));
	close(fd);

	while (1) {
		Dprintf(D_DEVTAB, "Trying to lock %s", PATH_DEVTAB);
		if (link(tempname, PATH_DEVTAB_LOCK) >= 0) {
			devtab_locked = 1;
			break;
		}
		if (errno != EEXIST) {
			Dprintf(L_ERROR, "Unable to lock %s: %s",
				PATH_DEVTAB, strerror(errno));
			break;
		}
		if ((fd = open(PATH_DEVTAB_LOCK, O_RDONLY)) < 0) {
			Dprintf(L_ERROR, "Unable to open %s: %s",
				PATH_DEVTAB_LOCK, strerror(errno));
			break;
		}
		if ((n = read(fd, buffer, sizeof(buffer))) < 0) {
			Dprintf(L_ERROR,
				"unable to read pid from %s: %s",
				PATH_DEVTAB_LOCK, strerror(errno));
			break;
		}
		close(fd);

		buffer[n] = '\0';
		pid = atoi(buffer);
		if (kill(pid, 0) < 0 && errno == ESRCH) {
			Dprintf(L_WARNING,
				"removing stale lock for %s by pid=%d",
				PATH_DEVTAB, pid);
			unlink(PATH_DEVTAB_LOCK);
			continue;
		}

		if (retry == 1)
			Dprintf(L_ERROR, "%s already locked by pid=%d.",
				PATH_DEVTAB, pid);
		if (retry >= maxretry) {
			if ((maxretry <<= 1) >= 10 * 60)
				maxretry = 10 * 60;
			retry = 0;
		}
		retry++;
		sleep(1);
	}

	unlink(tempname);
	if (!devtab_locked)
		Dprintf(L_FATAL, "Aborting.");

	Dprintf(D_DEVTAB, "Successfully locked %s", PATH_DEVTAB);
}

static void
devtab_unlock(void)
{
	if (devtab_locked) {
		Dprintf(D_DEVTAB, "Unlocking %s", PATH_DEVTAB);
		unlink(PATH_DEVTAB_LOCK);
	}
	devtab_locked = 0;
}

static FILE *
devtab_open(const char *mode, struct stat *sbp)
{
	FILE	*fp;

	if ((fp = fopen(PATH_DEVTAB, mode)) == NULL) {
		devtab_unlock();
		Dprintf(L_FATAL,
			"unable to open %s for %s: %s", PATH_DEVTAB,
			(mode[0] == 'r')? "reading" : "writing",
			strerror(errno));
	}
	if (sbp && fstat(fileno(fp), sbp) < 0) {
		devtab_unlock();
		Dprintf(L_FATAL,
			"unable to stat %s: %s", PATH_DEVTAB,
			strerror(errno));
	}

	return fp;
}

static unsigned int
devtab_add(dev_t dev)
{
	Dprintf(D_DEVTAB, "Mapping dev 0x%x to index %u\n", dev, nrdevs);

	/* Grow device table if needed */
	if ((nrdevs % 8) == 0)
		devtab = (dev_t *) xrealloc(devtab,
				(nrdevs + 8) * sizeof(dev_t));
	devtab[nrdevs++] = dev;
	return nrdevs-1;
}

static void
devtab_read(void)
{
	struct stat	stb;
	char		buffer[1024], *sp;
	FILE		*fp;

	if (devtab)
		free(devtab);
	devtab = NULL;
	nrdevs = 0;

	fp = devtab_open("r", &stb);
	devtab_mtime = stb.st_mtime;

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		/* shouldn't be there, but try to be nice to
		 * admins */
		if (buffer[0] == '#')
			continue;
		if ((sp = strchr(buffer, '\n')) != NULL)
			*sp = '\0';
		if (!strncmp(buffer, "devnum-", 7)) {
			stb.st_rdev = strtoul(buffer+7, &sp, 16);
			if (*sp) {
				Dprintf(L_FATAL,
					"invalid device name %s in %s",
					buffer, PATH_DEVTAB);
			}
		} else if (stat(buffer, &stb) < 0) {
			Dprintf(L_FATAL,
				"can't stat device name %s in %s: %s",
				buffer, PATH_DEVTAB,
				strerror(errno));
		}
		devtab_add(stb.st_rdev);
	}

	fclose(fp);
	return;
}

/*
 * Search all of /dev for a device file matching the given device number
 *
 * This routine works recursively in order to accomodate systems
 * that keep their device names in something like /dev/dsk
 */
static const char *
devtab_find(const char *dirname, dev_t dev, unsigned int depth)
{
	static char	fullname[1024];
	const char	*result = NULL;
	unsigned int	dirlen;
	struct dirent	*dp;
	struct stat	stb;
	DIR		*dir;

	/* Safeguard against infinite recursion (/dev may contain
	 * strange things like /dev/fd) */
	if (depth > 4)
		return NULL;

	Dprintf(D_DEVTAB, "Looking for dev 0x%x in %s\n", dev, dirname);
	if (dirname != fullname)
		strcpy(fullname, dirname);
	dirlen = strlen(fullname);
	fullname[dirlen++] = '/';
	fullname[dirlen] = '\0';

	if ((dir = opendir(fullname)) == NULL) {
		Dprintf(L_WARNING,
			"can't open %s for reading: %s",
			fullname, strerror(errno));
		return NULL;
	}

	while (!result && (dp = readdir(dir)) != NULL) {
		/* skip . and .. */
		if (!strcmp(dp->d_name, "..") || !strcmp(dp->d_name, "."))
			continue;
		/* skip long file names */
		if (strlen(dp->d_name) + dirlen + 1 >= sizeof(fullname))
			continue;
		strcpy(fullname + dirlen, dp->d_name);
		if (lstat(fullname, &stb) < 0) {
			Dprintf(L_WARNING,
				"unable to stat %s: %s (huh?!)",
				fullname, strerror(errno));
			continue;
		}
		if (S_ISDIR(stb.st_mode)) {
			result = devtab_find(fullname, dev, depth + 1);
		} else if (S_ISBLK(stb.st_mode) && stb.st_rdev == dev) {
			result = fullname;
		}
	}
	closedir(dir);
	return result;
}

static const char *
devtab_getname(dev_t dev)
{
	static char	fakename[64];
	const char	*result;

	if ((result = devtab_find("/dev", dev, 0)) == NULL) {
		/* Uh-oh... fake name */
		sprintf(fakename, "devnum-0x%lx", (unsigned long) dev);
		result = fakename;
	}

	return result;
}

#endif /* ENABLE_DEVTAB */
