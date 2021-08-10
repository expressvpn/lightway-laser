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

#include <util.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

/* Convert IP string to 32 bit unsigned int */
uint32_t ip2int(const char *ip) {
  struct in_addr a;
  if(!inet_aton(ip, &a)) {
    // IP was invalid - return 0
    return ((uint32_t)0);
  }
  return a.s_addr;
}

size_t slurp_file(char *path, char **buf) {
  int fd = open(path, O_RDONLY);
  LW_CHECK_WITH_MSG(fd > 0, "Unable to open file");

  int len = lseek(fd, 0, SEEK_END);
  LW_CHECK_WITH_MSG(len > 0, "Unable to calculate file length");

  void *data = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
  LW_CHECK_WITH_MSG(data, "Unable to mmap file");

  *buf = data;

  return len;
}

void unslurp_file(char *buf, size_t length) {
  munmap(buf, length);
}
