#ifndef _H_SENSOR_CLIENT_
#define _H_SENSOR_CLIENT_

void sensor_client_init(const char *sensor_ip, int sensor_port);

int sensor_client_run();

int sensor_client_stop();

void sensor_client_free();

void sensor_client_add(const char *username, int num);


#endif
