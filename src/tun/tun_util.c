/* *
 * Lightway Laser
 * Copyright (C) 2021 Express VPN International Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "tun_util.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <string.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <lw.h>

#include "util.h"

int tun_alloc(char *dev, int flags) {
  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";
  if((fd = open(clonedev, O_RDWR)) < 0) {
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if(*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
  }

  if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

static void internal_tun_set_ip_ioctl(int s, unsigned long req, const char *name, const char *field,
                                      const struct sockaddr_in *addr) {
  struct ifreq in_addreq;
  memset(&in_addreq, 0, sizeof(in_addreq));
  strncpy(in_addreq.ifr_name, name, sizeof(in_addreq.ifr_name) - 1);
  memcpy(&in_addreq.ifr_addr, addr, sizeof(*addr));

  int res = ioctl(s, req, &in_addreq);
  LW_CHECK_WITH_MSG(res >= 0, "Unable to set ip with ioctl");
}

static void internal_tun_set_mtu_ioctl(int s, const char *name, const int mtu) {
  struct ifreq req = {0};
  strncpy(req.ifr_name, name, sizeof(req.ifr_name) - 1);
  req.ifr_ifru.ifru_mtu = mtu;

  int res = ioctl(s, SIOCSIFMTU, &req);
  LW_CHECK_WITH_MSG(res >= 0, "Unable to set MTU with ioctl");
}

static void internal_tun_set_flags_up(int s, const char *name) {
  struct ifreq req = {0};
  strncpy(req.ifr_name, name, sizeof(req.ifr_name) - 1);

  int res = ioctl(s, SIOCGIFFLAGS, &req);
  LW_CHECK_WITH_MSG(res >= 0, "Unable to get flags from tunnel");

  req.ifr_flags |= IFF_UP;
  res = ioctl(s, SIOCSIFFLAGS, &req);
  LW_CHECK_WITH_MSG(res >= 0, "Unable to set flags on tunnel");
}

void tun_set_ip_internal(const char *tun_name, const char *local_ip, const char *peer_ip,
                         const int mtu) {
  // Only support IPv4 for now
  const sa_family_t address_family = AF_INET;
  int s = socket(address_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  LW_CHECK_WITH_MSG(s >= 0, "Unable to create socket for configuring tunnel");

  struct sockaddr_in addr = {0};
  struct sockaddr_in netmask = {0};
  struct sockaddr_in dstaddr = {0};

  int res = 0;

  // Parse local_ip
  addr.sin_family = address_family;
  res = inet_aton(local_ip, &addr.sin_addr);
  LW_CHECK_WITH_MSG(res == 1, "Invalid local IP");

  dstaddr.sin_family = address_family;
  res = inet_aton(peer_ip, &dstaddr.sin_addr);
  LW_CHECK_WITH_MSG(res == 1, "Invalid peer ip");

  memset(&netmask, 0, sizeof(netmask));
  netmask.sin_family = address_family;
  netmask.sin_addr.s_addr = 0xffffffff;

  internal_tun_set_ip_ioctl(s, SIOCSIFADDR, tun_name, "IP", &addr);
  internal_tun_set_ip_ioctl(s, SIOCSIFDSTADDR, tun_name, "PEER", &dstaddr);
  internal_tun_set_ip_ioctl(s, SIOCSIFNETMASK, tun_name, "NETMASK", &netmask);
  internal_tun_set_mtu_ioctl(s, tun_name, mtu);

  internal_tun_set_flags_up(s, tun_name);

  close(s);
}

void write_to_tun(int tun_fd, uint8_t *buffer, int length) {
  // Can't write to tun before it's ready...
  if(tun_fd == 0) return;

  // Drop the packet if it exceeds our max MTU
  if(length > LW_MAX_INSIDE_MTU) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Packet was dropped since it exceeds max tunnel MTU");
    zlog_flush_buffer();
    return;
  }

  if(write(tun_fd, buffer, length) == -1) {
    // TODO: Report Err?
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error writing to TUN device");
    zlog_flush_buffer();
  }
}

ssize_t read_from_tun(int tun_fd, void *buf, size_t count) {
  return read(tun_fd, buf, count);
}
