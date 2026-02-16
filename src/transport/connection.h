#ifndef SENDTOY_CONNECTION_H
#define SENDTOY_CONNECTION_H

#include "platform/platform.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct Connection Connection;

int transport_init(void);
void transport_cleanup(void);

Connection* connection_create(void);
void connection_destroy(Connection *conn);

bool connection_connect(Connection *conn, const char *ip, uint16_t port);
bool connection_send_all(Connection *conn, const void *data, size_t len);
int connection_receive(Connection *conn, void *buf, size_t len);

bool connection_send_file(Connection *conn, const char *filepath, uint64_t offset, uint64_t length);

#endif // SENDTOY_CONNECTION_H