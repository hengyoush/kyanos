//go:build ignore
#include <stdlib.h>
#include "conn_track.h"

// int add_data_evt_to_ct(struct data_evt* evt) {
//     // int err;
//     // struct conn_id_t cid = evt->attr.conn_id; 
//     // struct conn_track *ct = get_or_create_ct_for_conn_id(&cid);
//     // if (ct == NULL) {
//     //     return -1; 
//     // }
//     // struct my_ring_buffer *buf;
//     // if (evt->attr.direct == kEgress) {
//     //     buf = ct->send;
//     // } else {
//     //     buf = ct->recv;
//     // }
//     // err = add_new_data_to_buffer(evt->msg, evt->attr.seq, evt->attr.data_len, evt->attr.origin_len, buf);

//     // return err;
//     return 0;
// }

struct conn_info_t *retrieve_conn_info_by_conn_id(struct conn_id_t *conn_id) {
    int err;
	uint64_t conn_key = (uint64_t)conn_id->upid.pid << 32 | (uint32_t)conn_id->fd;
	struct conn_info_t *conn_info = malloc(sizeof(struct conn_info_t));
	if (!conn_info) {
		return -1;
	}
	err = bpf_map__lookup_elem(skel->maps.conn_info_map, &conn_key, sizeof(uint64_t), conn_info, sizeof(struct conn_info_t), 0);
    if (err) {
        free(conn_info);
        fprintf(stderr, "lookup conn_info failed: %d\n", err);
        return NULL;
    } else {
        return conn_info;
    }
}

struct conn_track *get_or_create_ct_for_conn_id(struct conn_id_t *cid) {
    struct conn_track *ct;
    struct my_ring_buffer *buf;

    ct = g_hash_table_lookup(conn_tracks, cid);

    if (ct == NULL) {
       ct = malloc(sizeof(struct conn_track));
       if (!ct) {
        goto ret;
       }
       ct->conn_info = retrieve_conn_info_by_conn_id(cid);
       if (ct->conn_info == NULL) {
        // 没有找到？
        goto ret;
       }

       buf = new_ring_buffer(RINGBUFFER_CAP);
       if (buf == NULL) {
        goto clean;
       }
       ct->recv = buf;

       buf = new_ring_buffer(RINGBUFFER_CAP);
       if (buf == NULL) {
        goto clean_recv_buf;
       }

       ct->send = buf;
       
       // put into map
       g_hash_table_insert(conn_tracks, cid, ct);
       goto ret;
    } else {
        goto ret;
    }


    clean_recv_buf:
    free(ct->recv);
    clean:
    free(ct);
    ret:
    return ct;
}

void destroy_conn_tracks() {
    if (conn_tracks == NULL) {
        return;
    }
    // g_hash_table_foreach(conn_tracks, )
    // g_hash_table_destroy(conn_tracks);
}

void destroy_conn_track(gpointer key, gpointer value, gpointer data) {
    
    // free(ct->conn_info);
    // destroy_ring_buffer(ct->recv);
    // destroy_ring_buffer(ct->send);
}

void init_conn_tracks() {
    // 使用自定义的hash/equals函数
    conn_tracks = g_hash_table_new(conn_id_hash_func, conn_id_equals);
}

gboolean conn_id_equals(gconstpointer  v1,gconstpointer  v2) {
    struct conn_id_t* ct1 = v1, *ct2 = v2;
    return ct1->fd == ct2->fd && ct1->tsid == ct2->tsid && 
        ct1->upid.pid == ct2->upid.pid && ct1->upid.start_time_ticks == ct1->upid.start_time_ticks;
}

guint conn_id_hash_func(gconstpointer  v) {
    struct conn_id_t* ct = v;
    return g_int64_hash(ct->tsid + ct->fd + ct->upid.pid + ct->upid.start_time_ticks);
}