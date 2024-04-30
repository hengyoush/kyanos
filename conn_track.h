#ifndef __CT_H__
#define __CT_H__

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <sys/socket.h>

#include <glib.h>
#include "pktlatency.skel.h"
#include "pktlatency.h"
#include "ring_buffer.h"

#define RINGBUFFER_CAP 2097152

/**
 * key = ct->tsid + ct->fd + ct->upid.pid + ct->upid.start_time_ticks
 * value = 
*/
static GHashTable* conn_tracks;

extern struct pktlatency_bpf *skel; 

struct conn_track {
    struct conn_id_t conn_id;
    struct conn_info_t *conn_info;
    struct my_ring_buffer *recv;
    struct my_ring_buffer *send;
};

guint conn_id_hash_func(gconstpointer  v);

gboolean conn_id_equals(gconstpointer  v1,gconstpointer  v2);

void init_conn_tracks();

void destroy_conn_tracks();


int add_data_evt_to_ct(struct data_evt* evt) {
    return 0;
}
struct conn_info_t *retrieve_conn_info_by_conn_id(struct conn_id_t *conn_id);
static struct conn_track *get_or_create_ct_for_conn_id(struct conn_id_t *cid);
void destroy_conn_track(gpointer key, gpointer value, gpointer data);

#endif