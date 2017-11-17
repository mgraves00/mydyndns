# $Id$

MAN=	mydyndns_cleanup.1

afterinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/mydyndns_cleanup.sh ${DESTDIR}/usr/bin/mydyndns_cleanup

.include <bsd.prog.mk>
