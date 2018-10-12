CXX = c++
CC  = gcc

LINKOPT = -L/lib64 -lcrypto

.SUFFIXES: .c .cpp .o

.cpp.o:
	$(CXX) -c $<

all : crypto

crypto : testRSA.o
	$(CXX) testRSA.o $(LINKOPT) -o trsa 

clean :
	rm -f trsa *.o
