CC	= c++
FLAGS 	=
CFLAGS	= -g -O2

OBJ_FILE = RBF.o sha256.o

all: ${OBJ_FILE} RBFGen IPCheck

RBFGen: RBFGen.o
	${CC} ${FLAGS} -o RBFGen RBFGen.o ${OBJ_FILE}

IPCheck: IPCheck.o
	${CC} ${FLAGS} -o IPCheck IPCheck.o ${OBJ_FILE}

RBFGen.o: RBFGen.cpp
	${CC} ${FLAGS} -c RBFGen.cpp

RBF.o: RBF.cpp
	${CC} ${FLAGS} -c RBF.cpp

IPCheck.o: IPCheck.cpp
	${CC} ${FLAGS} -c IPCheck.cpp

sha256.o: sha256.cpp
	${CC} ${FLAGS} -c sha256.cpp

clean:
	rm -f RBFGen IPCheck RBFGen.o IPCheck.o RBF.o sha256.o
