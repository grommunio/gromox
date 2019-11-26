#include <unistd.h>
#include <gromox/flusher_common.h>
#include <stdio.h>
#include <pthread.h>


static void console_talk(int argc, char **argv, char *result, int length);

static void* thread_work_func(void* arg);

static void cancel_flushing(FLUSH_ENTITY *pentity);
        
static pthread_t        g_flushing_thread;
static BOOL             g_notify_stop;

DECLARE_API;

BOOL FLH_LibMain(int reason, void** ppdata, char* path)
{
    pthread_attr_t  attr;

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

        if (FALSE == register_cancel(cancel_flushing)) {
            printf("[sample flusher]: fail to register cancel flushing\n");
            return FALSE;
        }
        if (FALSE == register_talk(console_talk)) {
            printf("[sample flusher]: fail to register console talk\n");
            return FALSE;
        }

		set_flush_ID(0); /* must set the last flush ID */
        /* create a thread to get context from queues */
        pthread_attr_init(&attr);
        if (0 != pthread_create(&g_flushing_thread, &attr, thread_work_func, 
            NULL)){
            printf("[sample flusher]: fail to create thread\n");
            return FALSE;
        }
		pthread_setname_np(g_flushing_thread, "flusher");
        return TRUE;
    case PLUGIN_FREE:
        g_notify_stop = TRUE;
        pthread_join(g_flushing_thread, NULL);
        unregister_cancel(cancel_flushing);
        unregister_talk(console_talk);
        return TRUE;
    }
    return TRUE;
}

/* 
 *  cancel flushed mail
 *  @param
 *      pentity [in]       mail object for cancelling
 */
static void cancel_flushing(FLUSH_ENTITY *pentity)
{
    /* 
    pentity->pflusher->flush_ID is set by flusher plugin and plugin can get this
    data and use it to indentify the part of mail that has been flushed
    */
    return;
}

/*
*    thread's work function
*    @param
*        arg [in]    argument passed by thread creator
*/
static void* thread_work_func(void* arg)
{
    FLUSH_ENTITY *pentity = NULL;

    
    while (TRUE != g_notify_stop) {
        /* get one entity from local queue */
        pentity = get_from_queue();
        /* handle the entity */
        /* ...               */

        if (NULL == pentity) {
            usleep(50);
            continue;
        }

        /*
        check if the context has already been flushed. if not, create an unique
        ID, and save it in entity's pflusher->flush_ID
        */
    }
    return 0;
}

/*
 * console talk function
 * @param
 *      argc            arguments number
 *      argv            arguments
 *      result [out]    buffer for echo result
 *      length          buffer length
 */
static void console_talk(int argc, char **argv, char *result, int length)
{
    /* TO BE IMPLEMENTED */
}

