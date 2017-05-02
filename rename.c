/* rename.c -- rename a file
   Copyright (C) 1988, 1992 Free Software Foundation
 
This file is part of GNU Tar.
 
GNU Tar is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.
 
GNU Tar is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with GNU Tar; see the file COPYING.  If not, write to
the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/stat.h>
#include <errno.h>
#ifndef
#ifndef STD_HEADERS
extern int errno;
#endif

/* Rename file FROM to file TO.
   Return 0 if successful, -1 if not. */

int
rename (from, to)
     char *from;
     char *to;
{
  struct stat from_stats;

  if (stat (from, &from_stats))
    return -1;

  if (unlink (to) && errno != ENOENT)
    return -1;

  if (link (from, to))
    return -1;

  if (unlink (from) && errno != ENOENT)
    {
      unlink (to);
      return -1;
    }

  return 0;
}

