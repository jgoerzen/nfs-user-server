
Hi all,

Please find enclosed an experimental patch to the Linux nfsd that
supports something I've named CDFs for lack of a more appropriate name.
They're not real CDFs, and in particular, they won't let you manage
stuff like shared /etc directories for diskless clients (it breaks
/etc/mtab handling, for instance). I'm not particularly proud of it
since I consider CDFs a kludge by all means, but as it was feasible
with less than 10 minutes of hacking, I thought I'd put this suggestion
forward.

It works basically by recognizing and replacing `magic' path components
at lookup time. To provide per-user /tmp directories transparently,
you would have to do something like this:

	# Create per-user temp directories
	mkdir -pm 755 /.tmp/users /.tmp/switch
	for uid in 0 1 2 3 4 5 6 .. 500 501 ...; do
		mkdir -m 755 /.tmp/users/$uid
		chown $uid.users /.tmp/users/$uid
		ln -s /.tmp/users/$uid /.tmp/switch/$uid
	done
	mkdir -pm 1777 /.tmp/users/default;
	ln -s /.tmp/users/default /.tmp/switch/default

	# Prepare NFS-mounted /.tmp/switch directory
	mkdir -pm 755 /.tmp/nfs
	mount localhost:/.tmp/switch /.tmp/nfs -o noac

	# Replace old /tmp directory
	mv /tmp /tmp.old
	ln -s /.tmp/nfs/cdf:uid /tmp

That looks somewhat convoluted, so let me explain how it works: When
a process tries to look up /tmp, it will read the symlink pointing
to /.tmp/nfs/cdf:uid. Looking up the symlink, it will encounter the NFS
mount point (/.tmp/nfs), and ask the NFS server to look up "cdf:uid".
Nfsd will recognize the special name and replace it with the requesting
process' numeric uid (let's say 500) before looking it up. It will
now encounter yet another symlink, this time pointing to /.tmp/users/500
which is the user's private temporary directory. Once the kernel has
obtained this path, subsequent lookups will not have to go through the
server any more.

The /.tmp/switch/default symlink is somewhat special; this is the
fallback name used when nfsd is not able to look up the uid-specific
directory. In the above setting, it provides the usual /tmp semantics
for uids for which you haven't created a specific /.tmp/users directory.
If you choose to omit the default entry, a lookup of cdf:uid for such a
uid would fail.

Note the noac option when mounting /.tmp/switch over NFS. This is
absolutely crucial, because otherwise the kernel would cache the result
of looking up cdf:uid, leading to random behavior. Also take care of
the export options for /.tmp/switch: using ro is not a problem but doesn't
add anything in terms of security. It's up to you whether you enable root
squashing or not; enabling it may have unexpected side effects...

The above setup should also work nicely with setuid applications that
`forget' to yield their privileges before creating or manipulating a file
in /tmp.  Since the kernel uses the fsuid of the process (which is in
effect its euid most of the time) when constructing the RPC credentials
for the NFS call, it will automatically be redirected to its uid-specific
/.tmp/users directory that cannot be booby-trapped by an attacker.

Oh, I almost forgot to mention this: to enable CDF support in nfsd, you
must edit the Makefile and add -DSUPPORT_CDF to the NFSD_DEFS variable.

Criticism and suggestions welcome, but please allow for some days before
I find the time to reply.

Happy hacking
Olaf
