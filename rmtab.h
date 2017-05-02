/*
 * rmtab.h	Support for rmtab manipulations.
 *
 */


#ifndef RMTAB_H
#define RMTAB_H

/*
 * Location of rmtab file. /etc/rmtab is the standard on most systems.
 */
#include <paths.h>
#ifndef _PATH_RMTAB
#define _PATH_RMTAB	"/etc/rmtab"
#endif

extern void 		rmtab_add_client(dirpath, struct svc_req *);
extern mountlist *	rmtab_lst_client(void);
extern void		rmtab_del_client(dirpath, struct svc_req *);
extern void		rmtab_mdel_client(struct svc_req *rqstp);

#endif /* RMTAB_H */

