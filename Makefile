CFLAGS = -O2

all: hagrid hagridd

hagrid: hagrid.o sha256.o
	$(CC) -o $@ hagrid.o sha256.o $(LDFLAGS)

hagridd: hagridd.o sha256.o
	$(CC) -o $@ hagridd.o sha256.o $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f hagrid hagridd hagrid.o hagridd.o sha256.o
