#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "midb_client.h"

int main(int argc, char **argv)
{


	FILE *fp;
	char *mailID;
	char *ptr1, *ptr2;
	char temp_line[1024];
	char temp_buff[4096];

	
	
        if (2 == argc && 0 == strcmp(argv[1], "--version")) {
                printf("version: %s\n", PROJECT_VERSION);
                exit(0);
        }

	if (argc != 2) {
		printf("usage: %s log_file\n");
		return 1;
	}

	fp = fopen(argv[1], "r");

	if (NULL == fp) {
		printf("fail to open %s\n", argv[1]);
		return 2;
	}


	midb_client_init("../data/midb_list.txt");
	if (0 != midb_client_run()) {
		fclose(fp);
		printf("fail to run midb client\n");
		return 2;
	}



	while (NULL != fgets(temp_buff, 4096, fp)) {
		ptr1 = strstr(temp_buff,  " is delivered OK");

		if (NULL == ptr1) {
			continue;
		}
		
		*ptr1 = '\0';

		ptr2 = strstr(temp_buff, "/u-data/");
		
		if (NULL == ptr2 || ptr1 < ptr2) {
			continue;
		}
		

		strncpy(temp_line, ptr2, 1024);
		
		ptr1 = strrchr(ptr2, '/');
		if (NULL == ptr1) {
			continue;
		}
		*ptr1 = '\0';
		mailID = ptr1 + 1;

		ptr1 = strrchr(ptr2, '/');
		if (NULL == ptr1) {
			continue;
		}
		*ptr1 = '\0';
		
		remove(temp_line);
		midb_client_delete(ptr2, "inbox", mailID);
		printf("%s is deleted\n", temp_line);
	}
	
	fclose(fp);

	midb_client_stop();
	midb_client_free();

	exit(0);

	return 0;

}
