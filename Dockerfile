# Partiamo da una base ufficiale di Ubuntu 22.04
FROM ubuntu:22.04

# Evita che l'installazione dei pacchetti si blocchi chiedendo la tastiera o la timezone
ENV DEBIAN_FRONTEND=noninteractive

# Installiamo i compilatori, OpenSSL e soprattutto gli strumenti di rete (tc, ping)
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Creiamo una cartella di lavoro dentro il container
WORKDIR /app

# Comando di default all'avvio: una shell interattiva bash
CMD ["/bin/bash"]