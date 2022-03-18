CC=gcc
CXX=g++
OBJ=basic_capstone_linear

.PHONY: all clean

all: $(OBJ)

loader.o: ../binloader/loader.cc
	$(CXX) -std=c++11 -c ../binloader/loader.cc

basic_capstone_linear: loader.o basic_capstone_linear.cc
	$(CXX) -std=c++11 -o build/basic_capstone_linear basic_capstone_linear.cc loader.o -lbfd -lcapstone

clean:
	rm -f $(OBJ)
	rm -f *.o

