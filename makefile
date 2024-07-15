CXX=g++
CXXFLAGS=-std=c++20

TARGET=server
SCRIPT_TARGET=client
SRCS=server.cpp
SCRIPT_SRCS=client.cpp
LIBS=-lcryptopp -lfmt

all: $(TARGET) $(SCRIPT_TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

$(SCRIPT_TARGET): $(SCRIPT_SRCS)
	$(CXX) -o $(SCRIPT_TARGET) $(SCRIPT_SRCS) $(LIBS)

clean:
	rm -f $(TARGET) $(SCRIPT_TARGET)

