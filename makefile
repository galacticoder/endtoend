CXX=g++
CXXFLAGS=-std=c++20

TARGET=server
SCRIPT_TARGET=client
SRCS=server.cpp
F_LINK=headers/linux_conio.cpp
SCRIPT_SRCS=client.cpp
LIBS=-lcryptopp -lfmt
PACKAGES=libboost-all-dev libcrypto++-dev libfmt-dev g++

packages:
	sudo apt update
	sudo apt install $(PACKAGES) -y

all: $(TARGET) $(SCRIPT_TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

$(SCRIPT_TARGET): $(SCRIPT_SRCS)
	$(CXX) -o $(SCRIPT_TARGET) $(SCRIPT_SRCS) $(F_LINK) $(LIBS)

clean:
	rm -f $(TARGET) $(SCRIPT_TARGET)

