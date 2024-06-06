Tool Command Language (TCL) Transport Layer Security (TLS) Extension

Intro
=====

This package provides an extension which implements Secure Socket Layer (SSL)
and Transport Layer Security (TLS) over Transmission Control Protocol (TCP)
network communication channels. It utilizes either the OpenSSL or LibreSSL
software library.

Version 1.9 also provides a cryptography library providing TCL scripts access
to the crypto capabilities of the OpenSSL library.


Description
===========

This extension works by creating a layered TCL Channel on top of an existing
bi-directional channel created by the TLS socket command. All existing socket
functionality is supported, in addition to several new options. Both client
and server modes are supported.


Documentation
=============

See the doc directory for the full usage documentation.


Compatibility
=============

This package requires TCL 8.5 or later.

This package is compatible with:
- OpenSSL v1.1.1 or later. See (http://www.openssl.org/
- LibreSSL (TBD version)


Installation
============

This package uses the Tcl Extension Architecture (TEA) to build and install on
any supported Unix, Mac, or MS Windows system. Either the OpenSSL or LibreSSL
software libraries must be built and available prior to building TCL TLS.

UNIX and Linux
--------------

The standard TEA config, make and install process is supported.

	$ cd tcltls
	$ ./configure --enable-64bit
	$ make
	$ make test
	$ make install

The supported configure options include all of the standard TEA configure script
options, plus:

  --disable-tls1          disable TLS1 protocol
  --disable-tls1_1        disable TLS1.1 protocol
  --disable-tls1_2        disable TLS1.2 protocol
  --disable-tls1_3        disable TLS1.3 protocol
  --enable-debug          enable debugging mode and output more status
  --enable-ssl-fastpath   enable using the underlying file descriptor for talking directly to the SSL library
  --enable-hardening      enable hardening attempts
  --enable-static-ssl     enable static linking to the SSL library

If either TCL or OpenSSL are installed in non-standard locations, the following
configure options are available. For all options, see ./configure --help.

  --with-tcl=<dir>			path to where tclCondig.sh file resides
  --with-tclinclude=<dir>		directory containing the public Tcl header files
  --with-openssl-dir=<dir>		path to root directory of OpenSSL or LibreSSL installation
  --with-openssl-includedir=<dir>	path to include directory of OpenSSL or LibreSSL installation
  --with-openssl-libdir=<dir>		path to lib directory of OpenSSL or LibreSSL installation
  --with-openssl-pkgconfig=<dir>	path to root directory of OpenSSL or LibreSSL pkgconfigdir


MacOS
-----

The standard TEA installation process is supported. Use the --with-tcl option
to set the TCL path if the ActiveState or other non-Apple version of TCL is to
be used.

	$ cd tcltls
	$ ./configure --with-tcl=/Library/Frameworks/Tcl.framework/
	$ make
	$ make test
	$ make install


Windows
-------

If installing with MinGW, use the TEA build process. If using MS Visual C
(MSVC), see the win/README.txt file for the installation instructions.


Copyrights
==========

Original TLS Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
TLS 1.4.1    Copyright (C) 2000 Ajuba Solutions
TLS 1.6      Copyright (C) 2008 ActiveState Software Inc.
TLS 1.7      Copyright (C) 2016 Matt Newman, Ajuba Solutions, ActiveState
                                Software Inc, Roy Keene <tcltls@rkeene.org>
TLS 1.8      Copyright (C) 2023 Brian O'Hagan

Acknowledgments
===============

Non-exclusive credits for TLS are:
   Original work: Matt Newman @ Novadigm
   Updates: Jeff Hobbs @ ActiveState
   Tcl Channel mechanism: Andreas Kupries
   Impetus/Related work: tclSSL (Colin McCormack, Shared Technology)
                         SSLtcl (Peter Antman)

License
=======

This code is licensed under the same terms as the Tcl Core.
