/*  Author: Michal Karm Babacek

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef ORACULUM_H
#define ORACULUM_H

#include <stdbool.h>
#include <stdlib.h>

#define die(X, ...) fprintf(stderr, "ERROR %s:%d: " X "\n", __FILE__, __LINE__, ##__VA_ARGS__);exit(EXIT_FAILURE);
#define ERR_MSG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define DEBUG_MSG(fmt, ...) kr_log_debug("DEBUG %s: %d " fmt, __FILE__, __LINE__, ##__VA_ARGS__);

void init_connection();

void free_connection();

bool address_malevolent(const char *client_address, const char *address, const char *hostname);

bool hostname_malevolent(const char *client_address, const char *hostname);

#endif // ORACULUM_H
