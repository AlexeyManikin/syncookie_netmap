# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen 

CLEANFILES = $(PROGS) *.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
.ifdef WITH_PCAP
LDFLAGS += -lpcap
.else
CFLAGS += -DNO_PCAP
.endif

LDFLAGS += -lpthread
LDFLAGS += -lrt	# needed on linux, does not harm on BSD
#SRCS = pkt-gen.c

all: $(PROGS)

kern_test: testmod/kern_test.c

pkt-gen: pkt-gen.o
	$(CC) $(CFLAGS) -o pkt-gen pkt-gen.o $(LDFLAGS)

pkt-gen-b: pkt-gen-b.o
	$(CC) $(CFLAGS) -o pkt-gen-b pkt-gen-b.o $(LDFLAGS)

pkt-gen-b.o: pkt-gen.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c pkt-gen.c -o pkt-gen-b.o

clean:
	-@rm -rf $(CLEANFILES)
