/*
 *  define the constant for plugin's return value load, unload, reload, 
 *  console talk actions.
 */
#pragma once
#include <gromox/common_types.hpp>

/* enumeration for indicate the ation of plugin_main function */
enum{
    PLUGIN_INIT,
    PLUGIN_FREE,
    PLUGIN_THREAD_CREATE,
	PLUGIN_THREAD_DESTROY,
	PLUGIN_RELOAD,
};

/* enumeration for the return value of xxx_load_library */
enum{
	PLUGIN_FAIL_EXECUTEMAIN = -5,
    PLUGIN_FAIL_ALLOCNODE,
    PLUGIN_NO_MAIN,
    PLUGIN_FAIL_OPEN,
    PLUGIN_ALREADY_LOADED,
    PLUGIN_LOAD_OK = 0,
};

/* enumeration for the return value of xxx_unload_library */
enum{
    PLUGIN_UNABLE_UNLOAD = -3,
    PLUGIN_SYSTEM_ERROR,
    PLUGIN_NOT_FOUND,
    PLUGIN_UNLOAD_OK = 0,
};

/* enumeration for result of console talk */
enum{
    PLUGIN_NO_TALK = -2,
    PLUGIN_NO_FILE,
    PLUGIN_TALK_OK = 0,
};

typedef BOOL (*PLUGIN_MAIN)(int, void**);
typedef void (*TALK_MAIN)(int, char**, char*, int);
