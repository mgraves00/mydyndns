# $Id$

SRCS=		base64.c db.c mydyndns.c
PROG=		mydyndns
CFLAGS+=	-I/usr/local/include -O0
LDFLAGS+=	-v -L/usr/local/lib -static
LDADD+=		-lkcgi -lkcgihtml -lz -lksql -lsqlite3 -lpthread -lm
MAN=		mydyndns.1
WARNINGS=YES
BINDIR=		/var/www/cgi-bin
BINGRP=		www
BINOWN=		www

afterinstall:
	sqlite3 /tmp/${PROG}.db < ${.CURDIR}/${PROG}.sql
	${INSTALL} -o ${BINOWN} -g ${BINGRP} -m 660 /tmp/${PROG}.db ${BINDIR}/../run
	echo "Please read AFTER_INSTALL"

.include <bsd.prog.mk>
