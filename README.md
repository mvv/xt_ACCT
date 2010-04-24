xt_ACCT 
=======

xt_ACCT is an accounting module for ip[6]tables.

Installation
------------

You will need iptables, pkgconfig (optional), and Linux kernel development
files. To compile and install xt_ACCT, run

	$ ./configure [VARIABLES] [OPTIONS]
	$ make
	# make install

In addition to the standard `configure` parameters you can specify
the following:

* --with-kernel=PATH -
    Path to kernel developement files (defaults to
    ``/lib/modules/`uname -r`/build``).
* IPTABLES - Path to iptables binary.
* IPTABLES_VERSION - Version of iptables.
* IPTABLES_CFLAGS - C compiler flags for iptables.
* IPTABLES_LIBDIR - Path to iptables plugins. 

