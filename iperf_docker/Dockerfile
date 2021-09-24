FROM debian:latest
RUN apt-get update --fix-missing && \
    DEBIAN_FRONTEND=noninteractive apt-get install -qqy --no-install-recommends \
      iperf \
      iperf3 \
      iproute2 \
      tcpdump

CMD ip addr & nice -n 19 iperf3 -i 5 -s
