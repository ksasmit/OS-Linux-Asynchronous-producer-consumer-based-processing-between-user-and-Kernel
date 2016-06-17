KDIR := /lib/modules/$(shell uname -r)/build
obj-m += netlinkKernel.o

all: netlinkUser netlinkKernel


netlinkUser: netlinkUser.c
	gcc -Wall -Werror netlinkUser.c -o netlinkUser -lcrypto -lssl

netlinkKernel:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.* *.cmd .module* modules* Module* .*.cmd .tmp*
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f netlinkUser