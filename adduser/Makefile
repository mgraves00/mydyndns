# $Id$

MAN=	mydyndns_adduser.1

afterinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/mydyndns_adduser.sh ${DESTDIR}/usr/bin/mydyndns_adduser

.include <bsd.prog.mk>
