/*
 * This file maps the `extension' macros for various system calls
 * to their standard meaning. People wishing to test their own file
 * system concepts (like Pavel Machek, who originally submitted this
 * patch :), just have to replace this header file with the appropriate
 * function declarations and link nfsd against their code...
 */

#ifndef EXTENSIONS_H
#define EXTENSIONS_H

/* Initialize/shut down */
#define efs_init()		efs_noop
#define efs_shutdown()		efs_noop
#define efs_timeout_handler()	efs_noop

/* Propagate changes of uid/gid */
#define efs_setfsuid(u)		setfsuid(u)
#define efs_setfsgid(g)		setfsgid(g)

/* VFS operations */
#define efs_mkdir	mkdir
#define efs_rmdir	rmdir
#define efs_rename	rename

#define efs_open	open
#define efs_close	close
#define efs_read	read
#define efs_write	write
#define efs_lseek	lseek

#define efs_opendir	opendir
#define efs_readdir	readdir
#define efs_closedir	closedir
#define efs_seekdir	seekdir
#define efs_telldir	telldir

#define efs_stat	stat
#define efs_fstat	fstat
#define efs_lstat	lstat

#define efs_realpath	realpath
#define efs_readlink	readlink
#define efs_symlink	symlink

#define efs_utimes	utimes
#define efs_chmod	chmod
#define efs_lchown	lchown
#define efs_mknod	mknod
#define efs_unlink	unlink
#define efs_link	link

/* do nothing */
#define efs_noop		do { } while (0)

#endif /* EXTENSIONS_H */
