CXX = c++
CC  = gcc

LINKOPT = -L/lib64 -lcrypto

.SUFFIXES: .c .cpp .o

.cpp.o:
	$(CXX) -c $<

all : crypto

crypto : testMD5.o
	$(CXX) testMD5.o $(LINKOPT) -o tmd5

clean :
	rm -f tmd5 *.o
