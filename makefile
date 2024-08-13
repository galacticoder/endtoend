CXX=g++
CXXFLAGS=-std=c++20

SERVER=server
CLIENT=client
SERVER_SRCS=server.cpp
F_LINK=headers/cpp-files/linux_conio.cpp headers/cpp-files/bcrypt.cpp headers/cpp-files/blowfish.cpp headers/cpp-files/getch_getline_sv.cpp headers/cpp-files/leave.cpp headers/cpp-files/hostHttp.cpp 
F_LINK_CLIENT=headers/cpp-files/linux_conio.cpp headers/cpp-files/getch_getline_cl.cpp headers/cpp-files/leave.cpp headers/cpp-files/fetchHttp.cpp
CLIENT_SRCS=client.cpp
LIBS=-lcryptopp -lfmt -lncurses -lssl -lcrypto -lboost_system -lboost_thread -lpthread -lcurl
LIBS_CLIENT=-lcryptopp -lfmt -lssl -lcrypto -lboost_system -lboost_thread -lpthread -lcurl
PACKAGES=libboost-all-dev libcrypto++-dev libfmt-dev g++ libncurses5-dev libncursesw5-dev libboost-all-dev libcurl4-openssl-dev libssl-dev

packages:
	sudo apt update
	sudo apt install $(PACKAGES) -y

all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_SRCS)
	$(CXX) $(CXXFLAGS) -Wall -o $(SERVER) $(SERVER_SRCS) $(F_LINK) $(LIBS)

$(CLIENT): $(CLIENT_SRCS)
	$(CXX) -Wall -o $(CLIENT) $(CLIENT_SRCS) $(F_LINK_CLIENT) $(LIBS_CLIENT) 

clean:
	rm -f $(CLIENT) $(SERVER)

