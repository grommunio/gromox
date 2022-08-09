/*
 *  define the constant for plugin's return value load, unload, reload actions.
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
	PLUGIN_EARLY_INIT,
	PLUGIN_USR1,
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

using PLUGIN_MAIN = BOOL (*)(int, void **);
