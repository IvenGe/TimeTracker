FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY timetracking_server.cpp .

RUN g++ -std=c++11 -pthread timetracking_server.cpp -o timetracking_server -lsqlite3

RUN mkdir -p /app/data

EXPOSE 9999 8080

CMD ["./timetracking_server"]