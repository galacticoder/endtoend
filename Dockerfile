FROM ubuntu:latest
LABEL org.opencontainers.image.authors="galacticoderr@gmail.com"
COPY . /app
WORKDIR /app/src/
RUN apt update && apt install build-essential -y
RUN make packages
RUN make server
RUN make client
CMD ["/bin/bash"]