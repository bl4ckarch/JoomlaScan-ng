FROM debian:buster-slim
LABEL maintainer="@Bl4ckarch"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    net-tools \
    iputils-ping \
    curl \
    git \
    vim \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x joomlascan-ng.py
EXPOSE 8080 
CMD ["python3", "joomlascan-ng.py"]
