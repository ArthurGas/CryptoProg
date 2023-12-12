CC=g++
CCLAGS=-c -Wall 
LIBFLAGS=-lcryptopp
SOURCES=$(wildcard *.cpp)
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=hash

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) $(LIBFLAGS) -o $@

.cpp.o:
	$(CC) $(CCLAGS) $< -o $@
	
clean:
	rm -rf *.o $(Target)
	rm -rf *.app $(Target)
