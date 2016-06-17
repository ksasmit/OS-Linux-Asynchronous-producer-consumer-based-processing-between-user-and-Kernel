obj-m += consumer.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: producer producer_thread producer_nowait submitjob

producer: producer.c
	gcc -Wall -Werror producer.c -o producer -lcrypto -lssl

producer_nowait: producer_nowait.c
	gcc -Wall -Werror producer_nowait.c -o producer_nowait -lcrypto -lssl

producer_thread: producer_thread.c
	gcc -Wall -Werror -pthread producer_thread.c -o producer_thread -lcrypto -lssl

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f producer producer_nowait producer_thread 
