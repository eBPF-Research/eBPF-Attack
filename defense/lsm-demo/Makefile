#obj-$(CONFIG_SECURITY_DEMO) := lsm_module.o
#demo-y := lsm_module.o
obj-m:=lsm_module.o

CURRENT_PATH:=$(shell pwd)
#VERSION_NUM:=$(shell uname -r)
CONFIG_MODULE_SIG=n
LINUX_PATH:=/root/linux

all:
	make -C $(LINUX_PATH) M=$(CURRENT_PATH) modules
clean:
	make -C $(LINUX_PATH) M=$(CURRENT_PATH) clean
