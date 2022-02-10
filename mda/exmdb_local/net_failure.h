#pragma once
void net_failure_init(int times, int interval, int alarm_interval);
extern int net_failure_run();
extern void net_failure_free();
void net_failure_statistic(int OK_num, int temp_fail, int permanent_fail,
	int nouser_num);
