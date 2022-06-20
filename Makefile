VERSION=0.1alpha

CC = gcc
LDFLAGS = -lpcap
CFLAGS = -g -ggdb 

SRC = smurf.c network_defs.c peer.c util.c
OBJ = ${SRC:.c=.o}
INCS = network_defs.h peer.h
EXENAME = smurf

PREFIX=~/.local

all: options ${EXENAME}

.c.o:
	${CC} -c ${CFLAGS} $< -o $@


options:
	@echo "CPPFLAGS = ${CPPFLAGS}"
	@echo "CFLAGS = ${CFLAGS}"
	@echo "LDFLAGS = ${LDFLAGS}"

${EXENAME}: ${OBJ}
	${CC} ${OBJ} -o $@ $(LDFLAGS)

clean:
	rm -f ${EXENAME} ${OBJ} ${EXENAME}-${VERSION}.tar.gz

install: all
	mkdir -p ${PREFIX}/bin
	cp ${EXENAME} ${PREFIX}/bin

uninstall:
	rm -f ${EXENAME} ${PREFIX}/bin/${EXENAME}

dist: clean
	mkdir -p ${EXENAME}-${VERSION}
	cp -R Makefile ${SRC} ${INCS} ${EXENAME}-${VERSION}
	tar -czf ${EXENAME}-${VERSION}.tar.gz ${EXENAME}-${VERSION}
	rm -rf ${EXENAME}-${VERSION}

.PHONY: all options clean install uninstall dist

