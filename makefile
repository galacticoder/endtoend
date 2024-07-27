CXX=g++
CXXFLAGS=-std=c++20

TARGET=server
SCRIPT_TARGET=client
SRCS=server.cpp
F_LINK=headers/linux_conio.cpp headers/bcrypt.cpp headers/blowfish.cpp headers/getch_getline.cpp headers/leave.cpp
SCRIPT_SRCS=client.cpp
LIBS=-lcryptopp -lfmt -lncurses
PACKAGES=libboost-all-dev libcrypto++-dev libfmt-dev g++ libncurses5-dev libncursesw5-dev

packages:
	sudo apt update
	sudo apt install $(PACKAGES) -y

all: $(TARGET) $(SCRIPT_TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(F_LINK) $(LIBS)

$(SCRIPT_TARGET): $(SCRIPT_SRCS)
	$(CXX) -o $(SCRIPT_TARGET) $(SCRIPT_SRCS) $(F_LINK) $(LIBS)

clean:
	rm -f $(TARGET) $(SCRIPT_TARGET)

