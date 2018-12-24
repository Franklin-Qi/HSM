#
# Create By WWM 2002/09/06
#
INC= ./
OBJ= kmctestsmapi.c hsmapi.a 
CC = cc

all:		$(OBJ)
		$(CC) -o testsmapi $(OBJ) -I $(INC) -L ./hsmapi.a -DAPI56
		@rm -f *.o
#.c.o:
#		$(CC) $(OSSPEC) -c -I $(INC) $<
#
# End.
