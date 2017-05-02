/* xmalloc.c -- malloc with out of memory checking
   Copyright (C) 1990, 1991 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#else
char *malloc ();
char *realloc ();
void free ();
#endif

#include "system.h"
#include "logging.h"

static void
mallocfailed()
{
  Dprintf(L_FATAL, "malloc failed -- exiting\n");
}

/* Allocate N bytes of memory dynamically, with error checking.  */

void *
xmalloc (n)
     unsigned n;
{
  char *p;

  p = malloc (n);
  if (p == 0)
    mallocfailed();
  return p;
}

/* Change the size of an allocated block of memory P to N bytes,
   with error checking.
   If P is NULL, run xmalloc.
   If N is 0, run free and return NULL.  */

void *
xrealloc (p, n)
     void *p;
     unsigned n;
{
  if (p == 0)
    return xmalloc (n);
  if (n == 0)
    {
      free (p);
      return 0;
    }
  p = realloc (p, n);
  if (p == 0)
    mallocfailed();
  return p;
}
