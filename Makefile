SHLIB=		infect
SHLIB_MAJOR=	0
SRCS=		infect.c
INCS=		infect.h
MAN=

CFLAGS+=	-I/usr/local/include \
		-I/usr/src/libexec/rtld-elf \
		-I/usr/src/libexec/rtld-elf/${MACHINE_ARCH}
LDFLAGS+=	-L/usr/local/lib

LDADD+=	-lhijack

.include <bsd.lib.mk>
