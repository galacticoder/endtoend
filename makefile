CXX=g++
CXXFLAGS=-std=c++20

SERVER=server
CLIENT=client

SERVER_SRC=server.cpp
CLIENT_SRC=client.cpp

FILE_LINKING_SERVER=headers/cpp-files/Server/bcrypt.cpp headers/cpp-files/Server/blowfish.cpp headers/cpp-files/Server/hostHttp.cpp 
FILE_LINKING_CLIENT=headers/cpp-files/Client/httpCl.cpp

LIBS=-lcryptopp -lfmt -lncurses -lssl -lcrypto -lboost_system -lboost_thread -lpthread -lcurl
LIBS_CLIENT=-lcryptopp -lfmt -lssl -lcrypto -lboost_system -lboost_thread -lpthread -lcurl -lncurses

PACKAGES=libboost-all-dev libcrypto++-dev libfmt-dev g++ libncurses5-dev libncursesw5-dev libboost-all-dev libcurl4-openssl-dev libssl-dev

packages:
	sudo apt update
	sudo apt install $(PACKAGES) -y

all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -Wall -Wextra -DNCURSES_NOMACROS -o $(SERVER) $(SERVER_SRC) $(FILE_LINKING_SERVER) $(LIBS)

$(CLIENT): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -Wall -o $(CLIENT) $(CLIENT_SRC) $(FILE_LINKING_CLIENT) $(LIBS_CLIENT)

clean:
	rm -f $(CLIENT) $(SERVER)

