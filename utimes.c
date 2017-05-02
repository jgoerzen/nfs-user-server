/*
 * utimes.c -- emulate BSD utimes with SYSV utime
 * Copyright (C) 1993 Rick Sladkey <jrs@world.std.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Library Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#if defined(STDC_HEADERS) || defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
struct timeval {
	long tv_sec;
	long tv_usec;
};
#endif

int utimes(char *path, struct timeval *tvp)
{
	struct utimbuf buf, *times;

	if (tvp) {
		times = &buf;
		times->actime = tvp[0].tv_sec;
		times->modtime = tvp[1].tv_sec;
	}
	else {
#ifdef HAVE_UTIME_NULL
		times = NULL;
#else
		times = &buf;
		times->actime = times->modtime = time(NULL);
#endif
	}
	return utime(path, times);
}

