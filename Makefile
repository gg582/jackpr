CFLAGS ?= -O2
all:
	$(CC) $(CFLAGS) -o jackpr jackpr.c
