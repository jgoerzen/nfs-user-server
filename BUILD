#!/bin/bash
# 
#  Universal NFS Server 2.2 configuration file
#  Aug 18, 1995
#  Copyright (C) 1995 Alexander O. Yuriev   <alex@bach.cis.temple.edu>  
#                                CIS Laboratories, TEMPLE UNIVERSITY.
#  GNU General Public License 2 or above terms apply.
#
#  Modified by Olaf Kirch.
#
#  Feb 1997 - added batch configuration via command line options.
#	--batch		don't ask questions
#	--multi		enable multiple server processes
#	--devtab=yes/no	enable new devtab inode numbers for big disks
#	--ugidd=yes/no	enable/disable support for ugidd
#	--nis=yes/no	enabled NIS-based uid mapping
#	--hosts-access=yes/no
#			Use hosts.allow/hosts.deny to limit access
#			to ugidd and mountd to certain hosts.
#	--libwrap-directory=pathname
#			Specify the directory where libwrap.a can
#			be found, if not in the default lib path.
#	--exports-uid=uid
#	--exports-gid=gid
#			Define uid and gid of the exports file owner.
#			Whenever mountd accesses /etc/exports, it
#			will make sure the file owner hasn't changed.
#	--log-mounts=yes/no
#			Enable/disable logging of all mount requests.
#

if [ -f .version ]; then
	VERSION=`cat .version`
else
	VERSION=2.2
fi
batch=false

while [ $# -ne 0 ]; do
	case $1 in
	--batch)	batch=true;;
	--*)		what=`expr $1 : '--\(.*\)=' | tr -s - _`
			value=`expr $1 : '.*=\(.*\)'`
			echo $what=$value
			eval $what=$value;;
	*)		echo "Invalid option $1" >&2;;
	esac
	shift
done

read_yesno() {
	ans=""
	echo >&2
	default=$2
	override=$3
	case $default in
	y)	prompt="$1 [Y/n] ";;
	n)	prompt="$1 [y/N] ";;
	*)	prompt="$1 [y/n] ";;
	esac
	while test -z $ans; do
		if [ -n "$override" ]; then
			ans=$override
			echo "$prompt$override" >&2
		elif $batch && [ -n "$default" ]; then
			echo "$prompt BAD" >&2
			echo "Warning: Batch mode; no override given --" \
			     "using default $default" >&2
		else
			echo -n "$prompt" >&2
			read ans
		fi
		if [ -z "$ans" ]; then
			ans=$default
		fi
		case $ans in
		y*|Y*)	ans=Y;;
		n*|N*)	ans=N;;
		*)	echo "You must answer y or n" >&2
			ans="";;
		esac
		override=
	done
	echo $ans
}

read_ugid() {
	ans=""
	prompt="$2 [default $3 $4] "
	default=$3
	override=$5
	while test -z $ans; do
		echo -n "$prompt" >&2
		if [ -n "$override" ]; then
			ans=$override
			echo "$ans" >&2
		elif $batch && [ -n "$default" ]; then
			echo "$prompt BAD" >&2
			echo "Warning: Batch mode; no override given --" \
			     "using default $default" >&2
		else
			read ans
		fi
		if [ -z "$ans" ]; then
			ans=$default
		elif expr "$ans" : "[0-9]*$" >/dev/null; then
			break;
		else
			ans=`id $1 $ans 2>/dev/null`
		fi
	done
	echo $ans
}

cat << EOF

***********************************************************
*     Universal NFS Server $VERSION Autoconfiguration    *
***********************************************************

   This package is BETA software. Until the final 2.2
   is released, please make sure you are using the latest
   version that you can get from
     
   ftp://linux.mathematik.tu-darmstadt.de/pub/linux/people/okir

   Please also make sure you replace any older versions
   of unfsd you are running.  Versions of the Universal
   NFS Server prior to 2.2 had some security holes.

   Caveat: although the Universal NFS Server 2.0 was
   originally written to support a set of different
   platfroms, including AIX, SunOS and others, versions
   above 2.0 were developed on Linux only. Thus, there
   may be some portability problems on other OSes.

   If you have a bug report, please follow the instructions
   in the file BUGS.

EOF
# -------------- blurb excerpt removed -----------------
#  This version is based on Olaf's version 2.2beta1
#  with automatic exports access control and hooks for
#  the experimental FoxbatSARS by Alex Yuriev.

if ! $batch; then
	echo -n "Please press return to continue"
	read ans
fi

version=`cat .version`
cat << EOF

****************************************************************
*  Universal NFS Server $version Site Specific Configuration  *
****************************************************************

    Please answer the following questions to make the system
    specific changes in configuration of the UNFS Server.

EOF

cat << EOF
+------------------+
| Big HD support   |
+------------------+

This release of unfsd has experimental support for a new inode number
generation scheme that should work better with large disks. If you
have experienced problems with files suddenly turning into direcotries,
or vice versa, try this feature.

EOF
DEVTAB=`read_yesno "Enable new inode number scheme?" n $devtab`

if [ "$DEVTAB" = Y ]; then
	echo 
	echo "The NFS server will need a file in which to store the device number mapping."
	echo -n "Please enter file name [/var/state/nfs/devtab]: "
	read PATH_DEVTAB
	if [ -z "$PATH_DEVTAB" ]; then
		PATH_DEVTAB=/var/state/nfs/devtab
	fi
	echo
fi

cat << EOF
+------------------+
| Multiple Servers |
+------------------+

This release of unfsd has support for running multiple server processes
in read/write mode (previous release were strictly read-only when running
more than one NFS daemon).

EOF
MULTI_NFSD=`read_yesno "Enable R/W support for multiple daemons?" y $multi`

cat << EOF
+---------------------+
| Dynamic UID mapping +
+---------------------+

This release of unfsd supports dynamic mapping of uids and gids between
hosts with different uid spaces. There are several flavors of uid mapping:

 *	Using a separate daemon named rpc.ugidd.
 *	Using the client host's NIS server.
 *	Using a static mapping file.

Static mapping is always supported; if you want one of the dynamic mapping
flavors, you have to select them now.

Note that you should not use ugidd mapping unless you absolutely must,
because it can pose a security risk: When run unprotected, the ugidd
mapping daemon can be abused to obtain a complete list of all login
names on your NFS client machine. As a counter-measure, ugidd can
be protected with the hosts_access control mechanism used by Wietse
Venema's tcp_wrapper package. Note that this does not offer a hundred
percent protection, though, as it can still be spoofed by hosts on the
same network as your client machine.

EOF

USE_UGIDD=`read_yesno "Are you going to use ugidd? (not recommended)" n $ugidd`
if [ "$USE_UGIDD" = "Y" ]; then
  echo " What can I say, its your system. I will use ugidd to map uid/gids."
else
  echo " Good, I never liked ugidd."
fi

USE_NIS=`read_yesno "Are you going to use NIS uid mapping?" n $nis`

cat << EOF

+------------------------------+
| Access control configuration |
+------------------------------+

Unfsd makes sure the exports file is always owned by the same user, and
is not writable by anyone but that user. I will now ask you for the uid
and gid of that user. Please enter appropriate user and group ids or names.

EOF

EXPSOWNUID=`read_ugid --user "Which uid should own /etc/exports?" 0 "(root)" $exports_uid`
EXPSOWNGID=`read_ugid --group "Which gid should own /etc/exports?" 0 "(root)" $exports_gid`

cat << EOF

Mountd and ugidd (if you enabled it) can be protected from illegal access
with the hosts_access control mechanism used by Wietse Venema's
tcp_wrapper package. Note that this does not offer a hundred percent
protection, though, as it can still be spoofed by hosts on the same
network as your client machine.

Especially if you run ugidd, enabling this is highly recommended.

EOF


test "$USE_UGIDD" = "Y" && _and_ugidd=" and ugidd"
USE_HSTACS=`read_yesno "Do you want to protect mountd$_and_ugidd with HOST ACCESS?" y \
		$hosts_access`

if [ "$USE_HSTACS" = "Y" ]; then
	LIBDIR=$libwrap_directory
	if [ -z "$LIBDIR" ]; then
		echo
		echo "Looking for libwrap.a... "
		for libdir in /usr/lib /usr/local/lib $LIBWRAP_DIR; do
			if [ -f $libdir/libwrap.a ]; then
				echo " Okay, libwrap is in $libdir"
				LIBDIR=$libdir;
				break;
			fi
		done
	fi
	if [ -z "$LIBDIR" ]; then
		cat << EOF

To protect ugidd with host_access, you must have libwrap.a installed
somewhere.  This library is part of the tcp_wrappers package. If you
don't have it, please obtain the source from 

	ftp:/win.tue.nl:/pub/security/tcp_wrapper_X.Y.tar.gz

and compile it.

EOF
		haveit=`read_yesno "Do you have libwrap.a installed?"`
		if [ "$haveit" != "Y" ]; then
			echo " Too bad. Aborting configuration."
			exit 1;
		fi

		while [ -z "$LIBDIR" ]; do
			echo -n "Which directory is it installed in? "
			read libdir
			if [ -f $libdir/libwrap.a ]; then
				LIBDIR=$libdir
			else
				echo " Can't find $libdir/libwrap.a"
			fi
		done
	fi
	HSTACS_LIBDIR=$LIBDIR
fi

cat << EOF

UNFS Server 2.2beta5 and later can log mount requests and their
success/failure to syslogd. This can be very useful for systems
that are not protected from internet by firewalls. (Actually, it should
by very useful in all cases).

EOF

LOG_MOUNTS=`read_yesno "Do you want to log all mount reqests into syslog? (recommended) " y $log_mounts`
LOG_MOUNTS="Y"
if [ "$LOG_MOUNTS" = "Y" ]; then
  echo "  Good, I'd log all mount requests and their status into syslog"
else
  echo "  Well, don't say I did not offer..."
fi 

echo
echo "Creating custom configuration ..."
echo "The following is your system specific configuration: "
echo

echo -n " *** New inode numbering scheme is"
test $DEVTAB = "N" && echo -n " not"
echo " enabled"
if [ "$DEVTAB" = Y ]; then
	echo " *** Device mapping stored in $PATH_DEVTAB"
fi

echo -n " *** Multi-Process nfsd read/write is"
test $MULTI_NFSD = "N" && echo -n " not"
echo " supported"

echo -n " *** User/Group ID Map Daemon is" 
test $USE_UGIDD = "N" && echo -n " not"
echo -n " used"
if [ "$USE_UGIDD" = "Y" ] ; then
  test $USE_HSTACS = "Y" && echo -n " but" || echo -n " but NOT"
  echo " protected with host access control"
else
  echo
fi

echo -n " *** NIS User/Group Mapping is"
test $USE_NIS = "N" && echo -n " not"
echo " used"

echo " *** Exports Control files should be owned by UID=$EXPSOWNUID GID=$EXPSOWNGID"
echo -n " *** Mount requests will "
test $LOG_MOUNTS = "N" && echo -n "not "
echo "be logged to syslogd(8)"
# echo -n " *** Support for export of DOS filesystems "
# test $USE_DOSFS && echo "enabled." || echo "disabled."

echo -n " *** Mount Daemon is "
test $USE_HSTACS = "Y" || echo -n "NOT "
echo "protected with host access control"

echo 
echo "Updating site.h..."

(
echo "/*"
echo " * Site-specific configuration options generated by BUILD."
echo " * Please do not edit."
echo " */"
echo
echo "/*"
echo " * If ENABLE_DEVTAB is defined, nfsd will use the new inode"
echo " * number generation scheme for avoiding inode number clashes"
echo " * on big hard disks."
echo " */"
if [ "$DEVTAB" = "Y" ]; then
  echo "#define ENABLE_DEVTAB"
  echo "#define PATH_DEVTAB	\"$PATH_DEVTAB\""
else
  echo "/* #undef ENABLE_DEVTAB */"
fi
echo
echo "/*"
echo " * If MULTIPLE_SERVER_READWRITE is defined, you will be able "
echo " * to run several nfsd process in parallel servicing all NFS "
echo " * requests."
echo " */"
if [ "$MULTI_NFSD" = "Y" ]; then
  echo "#define MULTIPLE_SERVERS_READWRITE"
else
  echo "/* #undef MULTIPLE_SERVERS_READWRITE */"
fi
echo
echo "/*"
echo " * If ENABLE_UGID_DAEMON is defined, the real rpc.ugidd is built, "
echo " * nfsd is built to support ugidd queries."
echo " * Otherwise, a dummy program is created"
echo " */"
if [ "$USE_UGIDD" = "Y" ]; then
  echo "#define ENABLE_UGID_DAEMON"
else
  echo "/* #undef ENABLE_UGID_DAEMON */"
fi
echo
echo "/*"
echo " * If ENABLE_UGID_NIS is defined, nfsd will support user mapping "
echo " * vie the client's NIS server."
echo " */"
if [ "$USE_NIS" = "Y" ]; then
  echo "#define ENABLE_UGID_NIS"
else
  echo "/* #undef ENABLE_UGID_NIS */"
fi
echo
echo "/*"
echo " * if HOSTS_ACCESS is defined, ugidd uses host access control"
echo " * provided by libwrap.a from tcp_wrappers"
echo " */"

if [  "$USE_HSTACS" = "Y" ]; then
  echo "#define HOSTS_ACCESS"
else
  echo "/* #undef HOSTS_ACCESS */"
fi  
echo 
echo "/*"
echo " * Define correct ownership of export control file"
echo " */"
echo "#define EXPORTSOWNERUID  ((uid_t) $EXPSOWNUID)"
echo "#define EXPORTSOWNERGID  ((gid_t) $EXPSOWNGID)"
echo
echo "/*"
echo " * If WANT_LOG_MOUNTS is defined, every mount request will be logged"
echo " * to syslogd with the name of source site and a path that was"
echo " * it requested"
echo " */"
if [ "$LOG_MOUNTS" = "Y" ]; then
  echo "#define WANT_LOG_MOUNTS"
else
  echo "#undef WANT_LOG_MOUNTS"
fi

) > site.h 

echo "Updating site.mk ..."
(
echo "#"
echo "# Site-specific make options generated by BUILD. Please do not edit."
echo "#"
echo
echo "# ugidd support"
if [ $USE_UGIDD = "Y" ]; then
  echo "UGIDD_PROG=\${rpcprefix}ugidd"
  echo "UGIDD_MAN=ugidd"
else
  echo "UGIDD_PROG="
  echo "UGIDD_MAN="
fi
echo "# Location of tcp_wrapper library"
if [  "$USE_HSTACS" = "Y" ]; then
  echo "LIBWRAP_DIR=-L$HSTACS_LIBDIR"
  echo "LIBWRAP_LIB=-lwrap"
else
  echo "LIBWRAP_DIR="
  echo "LIBWRAP_LIB="
fi
if [ "$DEVTAB" = "Y" ]; then
  echo "DEVTAB_FILE=$PATH_DEVTAB"
else
  echo "DEVTAB_FILE="
fi
) > site.mk

cat << EOF

I'm now running GNU configure to determine some system-specific things.
This make take a while on your first attempt.

EOF

if ! $batch; then
	echo -n "Please press return to continue "; read foo
fi

sh configure
if [ $? -ne 0 ]; then
  echo
  echo
  echo " *** Warning: GNU configure exited with error code $?"
  echo " *** Aborting installation. Please check the output of"
  echo " *** configure."
  echo
  exit 2
fi

cat << "EOF"

Uphh... Done. Now you can run `make install' to build and install the
binaries and manpages.

EOF
exit 0
