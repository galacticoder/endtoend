FROM ubuntu:24.04

RUN apt update && apt install -y \
	libboost-all-dev \
	libcrypto++-dev \
	libfmt-dev \
	g++ \
	libncurses5-dev \
	libncursesw5-dev \
	libcurl4-openssl-dev \
	libssl-dev \
	make

WORKDIR /app
COPY . /app
RUN make server
RUN make client
CMD ["./server"]

