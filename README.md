socket_hook
========

Simple tool for Linux/glibc hooking into socket API functions. 
This is currently only an incomplete stub.

### USAGE:

    $ LD_PRELOAD=path/to/socket_hook.so [enivronment options] target_binary


Environment variables controlling the behavior:
* `SH_SOCKET=$mode`: limit the socket domains which may be created, were `$mode` may be one of
   * `none`: no sockets can be created (will break all X11 applications usually)
   * `local`: only local sockets (`AF_UNIX` and `AF_LOCAL`) may be created
   * `all`: all sockets may be created (the default)
* `SH_VERBOSE=$level`: control level of verbosity (0 to 5)
* `SH_VERBOSE_FILE=$file`: redirect verbose output to `$file` (default is to use
			   standard error stream), see section [File Names](#file-names)
			   for details about how the file name is parsed


### FILE NAMES

Whenever an output file name is specified, special run-time information
can be inserted in the file name to avoid overwriting previous files in
complex situations (i.e. the application is using several processes).
A sequence of `%` followed by another character is treated depending
on the second character as follows:

* `p`: the PID of the process
* `t`: the current timestamp as `<seconds_since_epoch>.<nanoseconds>`
* `%`: the `%` sign itself

### INSTALLATION:

This requires glibc, as we call some internal glibc functions not intended to
be called. Tested with glibc-2.13 (from debian wheezy) and glibc-2.24
(from debian stretch). To build, just type

    $ make

(assuming you have a C compiler and the standard libs installed).
Finally copy the `socket_hook.so` to where you like it. For a debug build, do

    $ make DEBUG=1

Have fun,
     derhass <derhass@arcor.de>

