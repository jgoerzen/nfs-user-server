.COVER
.TL
The LINUX User-Space NFS Server(\*F)
'FS
This is a rewrite of the original README file (which you can now find in
README.HISTORIC).
.FE
.AU "Version 2.2
.AF "
.COVEND
.\"
.\"
.\"
.\"
.\"
.H 1 "Overview
.\"
This package contains all necessary programs to make your Linux machine
act as an NFS server, being an NFS daemon (\fIrpc.nfsd\fR), a mount daemon
(\fIrpc.mountd\fR), optionally, the uid mapping daemon (\fIrpc.ugidd\fR), and the
showmount utility.  It was originally developed by Mark Shand, and
further enhanced by Donald Becker, Rick Sladkey, Orest Zborowski, Fred
van Kempen, and Olaf Kirch.
.P
Unlike other NFS daemons, the Linux \fInfsd\fR runs entirely in user space.
This makes it a tad slower than other NFS implementations, and also
introduces some awkwardnesses in the semantics (for instance, moving
a file to a different directory will render its file handle invalid).
.\"
.\"
.\"
.H 1 "Building and installing unfsd
.\"
To compile and install the programs in this package, you first have to
run the BUILD script. It will ask you a couple of questions about your
preferred configuration. It tries to be helpful by informing you about
why it asking you which question, but a brief overview may be useful
nevertheless:
.DL
.LI "\fBmultiple servers:\fR
For a long time, unfsd was not able to run multiple servers in parallel
without sacrificing read/write access. This was implemented only recently,
and it has not been very widely tested.
.LI "\fBinode numbering scheme:\fR
One of the main features of nfsd is that when you export a directory,
it represent the entire hierarchy beneath that directory to the client
as if it were a single file system. To make this work, however, it has
to cram the device and inode number of each file system object into
32 bits, which serve as the inode number seen by the client. These must
be unique. If you export a fairly large disk, the likelihood of two
different files producing the same pseudo inode number increases, and
may lead to strange effects (files turning into directories, etc).
.P
If you've had problems with this in the past, try out the new inode
numbering scheme.
.LI "\fBuid/gid mapping:\fR
Occasionally, you will want to serve NFS clients whose assignment
of uids and gids to user names differs from that on the client. The
unfsd package offers you several mechanisms to dynamically map the client's uid
space to that of the server, and vice versa:
.DL
.LI "static mapping:
In the \fIexports\fR file, you can provide the NFS daemon with a file
that describes how individual or entire ranges of uids and gids on
a client machine correspond to those of the server.
.LI "NIS mapping:
The NFS daemon is also able to query the NIS server of the NFS client
for the appropriate uids and gids, using the user or group names and
looking them up in the appropriate NIS maps. You can do this by specifying
the client's NIS domain in the \fIexports\fR file. In addition, you
may have to edit the \fI/etc/yp.conf\fR file to point your NIS library
to the server for that NIS domain (if you're using NYS).
.LI "\fIugidd\fR mapping:
This is the original mechanism by which unfsd supported dynamic uid/gid
mapping. For this, you need to run the \fIrpc.ugidd\fR daemon on the
client machine, and instruct the server in the \fIexports\fR file to
use it.
.P
While this is convenient, it also presents a security problem because
\fIrpc.ugidd\fR can be abused by attackers to obtain a list of valid user
names for the client machine. This can be helped somewhat by making
ugidd check the requester's IP address against the \fIhosts.allow\fR
and \fIhosts.deny\fR files also used by the \fItcpd\fR wrapper
program (see below).
.LE
.P
The BUILD script will ask you whether you want dynamic \fIugidd\fR\-
or NIS\-based uid mapping. If you disable \fIugidd\fR-mapping,
the daemon will not be compiled, and the manpage will not be installed.
.P
.LI "\fBfile access control:\fR
For security reasons, \fImountd\fR and \fInfsd\fR make sure that vital
files such as \fI/etc/exports\fR are owned by the correct user and have
an appropriate access mode. BUILD will ask you which user and group
should own \fIexports\fR.  By default, this will be root/root.
.P
.LI "\fBdaemon access control:\fR
Both \fIrpc.mountd\fR and \fIrpc.ugidd\fR can be configured to use
the access control features of the TCP wrappers package. This will let
you specify in the \fI/etc/hosts.allow\fR and \fIhosts.deny\fR files
which hosts are allowed to talk to the daemons at all.
Note that you still have to configure access control as described below.
.P
If you do enable host access checking for \fIrpc.ugidd\fR, the BUILD script
will try to locate \fIlibwrap.a\fR which is needed for this. This library
is part of Wietse Venema's TCP wrapper package. BUILD looks in several
standard locations such as \fI/usr/lib\fR. If it does not find the library
(e.g. because you keep it in weird places like \fI/usr/i486-linux/lib\fR),
it will ask you for its full path name.
.P
.LI "\fBmount request logging:\fR
If you enable this option, \fIrpc.mountd\fR will log all attempts to mount a
directory via NFS from your server machine. This is very helpful in
monitoring NFS server usage, and for catching attempts at attcking your
machine via NFS.
.P
When enabled, \fImountd\fR will log all successful mount attempts to
\fIsyslog\fR's \fBdaemon\fR facility at level \fBnotice\fR. Failed mount
attempts are logged at level \fBwarning\fR.
.LE
.P
After completing these questions, BUILD will run a configure script to
detect certain system capabilities. This will take a while on your first
attempt. Repeated invocations of configure will run a lot faster because
the results of the tests are cached. If you want to start out with a fresh
build on a different release of Linux, you should make sure to get rid of
these cached values by running `\fCmake distclean\fR' first.
.P
You can then compile and install \fInfsd\fR by typing `\fCmake\fR' and/or
(as root) `\fCmake install\fR.' This will also install the manual pages.
.\"
.\"
.\"
.H 1 "Configuring \fInfsd\fR
.\"
To turn your Linux box into an NFS server, you have to start the
following programs from \fI/etc/rc.d/rc.inet2\fR (or wherever your favorite
Linux distribution starts network daemons from):
.DL
.LI *
\fIrpc.portmap\fR
.LI *
\fIrpc.mountd\fR
.LI *
\fIrpc.nfsd\fR
.LI *
\fIrpc.ugidd\fR (optional)
.LI *
\fIrpc.pcnfsd\fR (optional, not contained in this package)
.LE
.P
To make directories available to NFS clients, you have to enter
them in your \fIexports\fR file along with the hosts allowed to mount them.
The list of options and a sample file are given in the \fIexports(5)\fR
manual page (and the whole topic is covered quite extensively in the
Linux Network Administrator's Guide anyway), so I will not discuss this
here. If somebody feels like filling in the missing parts here, please
send me the diffs.
.P
.\"
.\"
.\"
.H 1 "Configuring network access control
To protect \fIrpc.ugidd\fR or \fIrpc.mountd\fR from unauthorized access,
you just have to add lines
to \fI/etc/hosts.allow\fR and/or \fI/etc/hosts.deny\fR detailing which
hosts are allowed to talk to it. If your NFS server has the IP
address 193.175.30.33, you would add the following to \fIhosts.allow\fR
and \fIhosts.deny\fR, respectively:
.VERBON 22
# hosts.allow:
rpc.ugidd: 193.175.30.33
# hosts.deny:
rpc.ugidd: ALL
.VERBOFF
.P
If you have compiled the TCP wrappers package with OPTIONS support (which
I highly recommend), you can also put the following into \fIhosts.allow\fR,
which will have the same effect:
.VERBON 22
rpc.ugidd: ALL EXCEPT 193.175.30.33 : deny
.VERBOFF
.P
Similarly, you can limit access to \fIrpc.mountd\fR on the NFS server
host. The daemon identifier to be used in this case is \fCrpc.mountd\fR.
.\"
.\"
.\"
.H 1 "Running several Daemons Concurrently
For a long time, unfsd has not supported multiple NFS processes at all.
This is paramount to good NFS performance, however, as it allows other
you to service NFS requests in parallel. Then, for a while, it supported
multiple server processes in read-only mode (which was quite easy as there
is no need to synchronize the file handle caches between daemon processes
in that case).
.P
Starting with release 2.2beta32, unfsd also supports multiple server
processes in read/write mode. Note that this code is still experimental,
and may disappear again if the concept doesn't work, or is too slow.
.\"
.\"
.\"
.H 1 "Common Problems (a.k.a. Dependencies)
.DL
.LI *
Root squashing is enabled by default, which means that requests from the
root user are treated as if they originated from the nobody user. If you
want root on the NFS client to be able to access files with full privilege,
you have to add \fBno_root_squash\fR to the option list in \fI/etc/exports\fR.
.LI *
The most specific entry applies. This means if you export both \fI/usr\fR
and \fI/usr/local\fR to a client, and the client mounts \fI/usr\fR from the
server, the options for \fI/usr/local\fR will still apply when the client
accesses 
.LI *
Wildcards in client names only do not match dots. This means that the entry
\fB*.foo.com\fR only matches hosts named \fBjoe.foo.com\fR etc, but not
\fBjoe.sales.foo.com\fR. You may call this a bug (and I may replace the
current pattern matching code with wildmat if there is enough demand).
.LI *
Changes to the \fIexports\fR file do not take effect until both
\fInfsd\fR and \fImountd\fR have re-read the file. You either have to
kill both daemons and restart them, or send them a HUP signal:
.VERBON 22
# killall -HUP \fIrpc.mountd\fR \fIrpc.nfsd\fR
.VERBOFF
.LI *
NFS operation between two Linux boxes can be quite slow. There are a number
of reasons for this, only one of which is that unfsd runs in user space.
Another (and much worse) problem is that the Linux NFS \fIclient\fR code
currently does no proper caching, read-ahead and write-behind of NFS data.
This problem can be helped by increasing the RPC transfer size on the client
by adding the `\fBrsize=8192,wsize=8192\fR' mount options. This will at least
improve throughput when reading or writing large files. You are still in a
lose-lose situation when applications write data line by line or with
no output buffering at all.
.LE
.H 1 Copyright
Much of the code in this package was originally written by Mark Shand,
and is placed under the following copyright:
.P
.B
.in +3n
.ll -6n
This software may be used for any purpose provided the above
copyright notice is retained. It is supplied as is, with no
warranties expressed or implied.
.ll +6n
.in -3n
.R
.P
Other code, especially that written by Rick Sladkey and some replacement
routines included from the GNU libc, are covered by the GNU General
Public License, version 2, or (at your option) any later version.
.\"
.\"
.\"
.H 1 "Bug Reports
.\"
If you think you have encountered a bug in \fInfsd\fR or any of the other
programs in this package, please follow the instructions in the file
BUGS.
