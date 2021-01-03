# See for reference: https://stackoverflow.com/questions/170467/makefiles-compile-all-c-files-at-once

CFLAGS = -static -Wall -I.
#LIBS = -L. -lfdt
LIBS = libfdt.a

SRC=$(wildcard *.c)
DTS=$(wildcard *.dts)
DTB_OBJS=$(DTS:.dts=.dtb)

all: fdtextract $(DTB_OBJS)

fdtextract: $(SRC)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

%.dtb : %.dts
	dtc -I dts -O dtb -o $@ $<

clean:
	rm -f *.o temp.dtb fdtextract
