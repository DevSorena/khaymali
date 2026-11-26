obj-m += k_tcpmux.o
obj-m += ktun_cc.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(CC) -O2 -Wall -Wextra ktun_handshake.c -o ktun_handshake

userspace:
	$(CC) -O2 -Wall -Wextra ktun_handshake.c -o ktun_handshake

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f ktun_handshake
