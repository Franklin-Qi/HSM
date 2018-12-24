ALL:
	#cc -c -qcpluscmt UnionSck.c UnionHsmCmd.c jlnx.c HSM_pack.c HsmLog.c DerCode.c
	cc -c unionsck.c hsmcmd.c smapi.c utilpack.c unionlog.c DerCode.c -D_DEBUG -D_LINUX_ 
	
	ar -rv hsmapi.a unionsck.o hsmcmd.o smapi.o utilpack.o unionlog.o DerCode.o 
	rm *.o

