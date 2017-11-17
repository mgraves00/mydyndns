# $Id$

MAN=	mydyndns_gendns.1

afterinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/mydyndns_gendns.sh ${DESTDIR}/usr/bin/mydyndns_gendns

.include <bsd.prog.mk>
