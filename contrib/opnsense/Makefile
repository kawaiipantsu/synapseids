# FreeBSD port Makefile for the SynapseIDS OPNsense plugin.
#
# This is the "upstream" path: drop this directory into an OPNsense
# plugins/ tree as net/synapseids-sensor (or security/synapseids-sensor) and
# `make package` on a FreeBSD builder. It is the conventional shape an
# OPNsense plugin PR takes.
#
# The repository does not depend on it. `make opnsense-pkg` at the top level
# builds the same package directly from a Linux host with
# scripts/package-opnsense.sh, because CI has no FreeBSD builder. The two must
# install the same file list — pkg-plist is shared, and package-opnsense.sh
# fails the build if the staged tree and pkg-plist disagree.
#
# SynapseIDS is a pure-Go, CGO_ENABLED=0 project, so the binary is
# cross-compiled rather than built here; point BINARY_DIR at a tree produced by
# `make build-freebsd`.

PORTNAME=	synapseids-sensor
PORTVERSION=	0.0.0
CATEGORIES=	security
PKGNAMEPREFIX=	os-

MAINTAINER=	12233528+kawaiipantsu@users.noreply.github.com
COMMENT=	SynapseIDS WAN sensor plugin for OPNsense
WWW=		https://github.com/kawaiipantsu/synapseids

LICENSE=	MIT
LICENSE_FILE=	${.CURDIR}/../../../LICENSE

# The payload is a static binary plus PHP/XML/Volt assets: nothing to link,
# nothing to compile on the target.
NO_ARCH=	no
NO_BUILD=	yes
USES=		php

# Where `make -C ../../.. build-freebsd` left the cross-compiled sensor.
BINARY_DIR?=	${.CURDIR}/../../dist/synapseids_${PORTVERSION}_freebsd_${ARCH}

do-install:
	@${MKDIR} ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${BINARY_DIR}/synapse-sensor ${STAGEDIR}${PREFIX}/bin/synapse-sensor
	@cd ${.CURDIR}/src && ${FIND} . -type d -exec ${MKDIR} ${STAGEDIR}${PREFIX}/{} \;
	@cd ${.CURDIR}/src && ${FIND} . -type f ! -path './etc/rc.d/*' \
		-exec ${INSTALL_DATA} {} ${STAGEDIR}${PREFIX}/{} \;
	@cd ${.CURDIR}/src && ${FIND} ./etc/rc.d -type f \
		-exec ${INSTALL_SCRIPT} {} ${STAGEDIR}${PREFIX}/{} \;

.include <bsd.port.mk>
