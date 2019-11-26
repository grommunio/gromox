#ifndef _H_SENSOR_CLIENT_
#define _H_SENSOR_CLIENT_

void sensor_client_init(const char *sensor_ip, int sensor_port);
extern int sensor_client_run(void);
extern int sensor_client_stop(void);
extern void sensor_client_free(void);
void sensor_client_add(const char *username, int num);


#endif
