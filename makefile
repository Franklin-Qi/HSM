INC= ./
OBJ=  kmctestgmapi1.c  hsmapi.a libTassApi_LINUX_64.so
CC = gcc

ALL:
	$(CC) -c -g unionsck.c sockpub.c net.c frmMutex.c hsmapi_tcpcom.c hsmapi_tools.c hsmapi_asym.c hsmapi_base.c hsmapi_der.c hsmapi_extend.c hsmapi_ic.c hsmapi_rsa.c hsmapi_magnet.c hsmapi_init.c hsmapi_log.c hsmcmd.c APIEBank.c smapi.c utilpack.c unionlog.c  DerCode.c  -D_LINUX_ 
	ar -rv hsmapi.a unionsck.o sockpub.o net.o frmMutex.o hsmapi_tcpcom.o hsmapi_tools.o hsmapi_asym.o hsmapi_base.o hsmapi_der.o hsmapi_extend.o hsmapi_ic.o hsmapi_rsa.o hsmapi_magnet.o hsmapi_init.o hsmapi_log.o hsmcmd.o APIEBank.o smapi.o utilpack.o unionlog.o DerCode.o 
	$(CC) -o test -g $(OBJ) -I $(INC) -lpthread -L ./hsmapi.a -DAPI56 
	@rm -f *.o
clean:
	-rm test
#
# End.

