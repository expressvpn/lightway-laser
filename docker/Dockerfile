FROM debian/buildd:bookworm as builder
ARG DEBIAN_FRONTEND=noninteractive

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

RUN apt-get update && apt-get install -qqy --no-install-recommends \
  autoconf \
  automake \
  bsdmainutils \
  dnsutils \
  git \
  iperf3 \
  iproute2 \
  iptables \
  iputils-ping \
  liblua5.3-dev \
  libtool \
  libsqlite3-dev \
  lua5.3 \
  procps \
  psmisc \
  rubygems \
  tcpdump \
  unzip \
  valgrind \
  wget \
  strace \
  vim \
  cmake

# Set up ceedling
RUN gem install ceedling

WORKDIR /lw_reference

FROM builder
COPY ./ .
RUN ceedling clobber
RUN ceedling dependencies:fetch
RUN ceedling dependencies:make
RUN ceedling release
