obj-m += ksocket.o

EXTRA_LDFLAGS := -DKSOCKET_ADDR_SAFE

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
