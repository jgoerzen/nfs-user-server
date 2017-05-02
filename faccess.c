/*
 *
 * faccess.c
 * Version 0.00.03
 * June 16, 1995
 * Copyright (C) 1995 Alexander O. Yuriev, CIS Laboratories, TEMPLE UNIVERSITY
 * GNU General Public License terms apply.
 * 
 * Modified by Olaf Kirch.
 */

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "faccess.h"
#include "extensions.h"

int
iCheckAccess(pchFilename, uidOwner, gidOwner)
	char *pchFilename;
	uid_t uidOwner;
	gid_t gidOwner;
{
  struct stat statData;
  int status = FACCESSOK;
  
  if (efs_stat(pchFilename,&statData) == -1) {
      if (errno == ENOENT)
        status = FACCESSNOTFOUND;
      else status = FACCESSIOERR;
  } else {
       if ((statData.st_mode & S_IWOTH) ||
  	   (statData.st_mode & S_IWGRP) ||
  	   ((statData.st_uid != uidOwner) && (statData.st_mode & S_IWUSR))) {
  	     status = FACCESSWRITABLE;
       } else if ((statData.st_uid != uidOwner) ||
       		(statData.st_gid != gidOwner)) {
       	     status = FACCESSBADOWNER;
       } else if ((statData.st_mode & S_IROTH)) {
	     status = FACCESSWARN;
       }
  }
  return status;
}
