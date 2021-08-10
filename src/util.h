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

#include <zlog.h>
#include <stdint.h>

/* Convert IP string to 32 bit unsigned int */
uint32_t ip2int(const char *ip);

/* Slurp a file into a buffer */
size_t slurp_file(char *path, char **buf);
void unslurp_file(char *buf, size_t length);

/**
 * Size of 1MB in bytes for clearer code
 */
#define MEGABYTE (1024 * 1024)

/**
 * Macro to exit the program with error performing any necessary tear down
 */
#define LW_EXIT_WITH_FAILURE() exit(EXIT_FAILURE)

/**
 * Exit the program if this expression isn't true (should be used where condition violation is a
 * serious / impossible error) Similar to assert but runs outside of debug mode
 */
#ifdef TEST
#define LW_CHECK_WITH_MSG(expression, msg)                                     \
  if(!(expression)) {                                                          \
    TEST_FAIL_MESSAGE("Fatal assertion " #expression " caused check failure"); \
  }
#else
#define LW_CHECK_WITH_MSG(expression, msg)                                                        \
  if(!(expression)) {                                                                             \
    zlogf_time(ZLOG_INFO_LOG_MSG,                                                                 \
               "Fatal assertion " #expression " violated (%s) in %s at %s:%i\n", (msg), __FILE__, \
               __func__, __LINE__);                                                               \
    zlog_finish();                                                                                \
    LW_EXIT_WITH_FAILURE();                                                                       \
  }
#endif
