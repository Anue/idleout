#!/bin/bash

#  Uninstall the idleout daemon.
#  Marcos Moyano - marcos@gnu.org.ar

LOCAL="`pwd`"
BINDIR="/sbin"
CONFDIR="/etc"
CONFFILE="$CONFDIR/idleout"
INITDIR="$CONFDIR/init.d"
FILES="$LOCAL/src"
MAN="/usr/share/man/man1/"
#MAN="`echo $MANPATH | cut -d: -f 1`/man1/"

echo "Start removing ... "
sleep 5

echo "Removing idleout to startup services ..."

$BINDIR/chkconfig --del idleout || echo -e "Error removing idleout from startup services.\n \
Please run: $BINDIR/chkconfig --del idleout "
sleep 5

if [ -f $INITDIR/idleout ]; then
	echo "Removing idleout --> $INITDIR/idleout"
	rm -f  $INITDIR/idleout
fi

if [ -f $BINDIR/idleoutd.py then
	echo "Removing idleoutd.py> $BINDIR/idleoutd.py"
	rm -f $BINDIR/idleoutd.py
fi

[ -d $CONFFILE ] || rm -rf $CONFFILE


if [ -f $MAN/idleoutd.1.gz ]; then
	echo "Removing (1) --> $MAN/idleoutd.1.gz"
	rm -f $MAN/idleoutd.1.gz
fi

echo "Finishing removing ... "
