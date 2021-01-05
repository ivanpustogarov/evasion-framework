CC=gcc
#LDFLAGS += $(shell pkg-config --libs glib-2.0) -pthread -lm -L/usr/lib64/ -lunicorn -lcapstone $(shell xml2-config --cflags) $(shell xml2-config --libs) 
LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lc -L/usr/lib64/ -lunicorn -lcapstone $(shell xml2-config --libs) 
CFLAGS += -pthread $(shell xml2-config --cflags)
CONFIGFLAGS= -DDEBUG=1  -DDYNAMICRECOVERY=1 

CFILES     =   emulate-arm.c emulate-arm64.c
COBJS   =   $(CFILES:.c=.o)
OBJS    =   $(SOBJS) $(COBJS)
DEPS := $(COBJS:.o=.d)

all: emulate-arm emulate-arm64

-include $(DEPS)

emulate-arm: emulate-arm.o
	$(CC) $^ $(LDFLAGS) -o $@

emulate-arm64: emulate-arm64.o
	$(CC) $^ $(LDFLAGS) -o $@

# For -MM and -MF see  https://stackoverflow.com/questions/297514/how-can-i-have-a-makefile-automatically-rebuild-source-files-that-include-a-modi
%.o: %.c
	$(CC) -c $(CONFIGFLAGS)  $(CFLAGS) -MMD -MF $(patsubst %.o,%.d,$@) -o $@ $<

clean:
	rm -f emulate-arm emulate-arm64 emulate unicorn-test-arm *.o *.d

distclean: clean
	rm Makefile
