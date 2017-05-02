/* 
   faccess.h
   Version 0.00.02
   Created: June 15, 1995
   Copyright (C) 1995 Alexander O. Yuriev <alex@bach.cis.temple.edu>
                      CIS Laboratories, TEMPLE UNIVERSITY
   GNU General Public License Terms apply. All other rights reserved.
*/
    
#ifndef __FACCESS_INCLUDED__
#define __FACCESS_INCLUDED__

#include "system.h"

#define FACCESSOK	0
#define FACCESSWARN	1
#define FACCESSVIOL	2
#define	FACCESSNOTFOUND	3
#define FACCESSIOERR	4
#define FACCESSBADOWNER	5
#define FACCESSWRITABLE	6

extern int	iCheckAccess(char *, uid_t, gid_t);

#endif
