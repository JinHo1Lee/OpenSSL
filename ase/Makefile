CXX = c++
CC  = gcc

LINKOPT = -L/lib64 -lcrypto

.SUFFIXES: .c .cpp .o

.cpp.o:
	$(CXX) -c $<

all : crypto

crypto : testAES.o 
	$(CXX) testAEX.o  $(LINKOPT) -o taes

clean :
	rm -f taes *.o
