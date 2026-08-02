FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    net-tools \
    iproute2 \
    dnsutils \
    curl \
    wget \
    tcpdump \
    x11vnc \
    xvfb \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/darkie-suite

COPY tool.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENV DISPLAY=:99

CMD ["python3", "tool.py", "--web", "--host", "0.0.0.0"]
