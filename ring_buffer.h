#ifndef __RB_H__
#define __RB_H__

#include <stdint.h>
#include <sys/types.h>
#include <glib.h>
#include "common_types.h"

struct chunk_t {
    size_t seq;
    size_t len;
    size_t real_len;
};

struct my_ring_buffer {
    const size_t cap;
    void* buf;
    size_t write_pos;

    /* (pos in buffer) => (<seq on stream> , <len in buffer>, <real len in stream>)*/
    GList *chunks;
};



struct my_ring_buffer* new_ring_buffer(uint32_t cap);

static size_t avail_space(struct my_ring_buffer* buf) {
    return buf->cap - buf->write_pos;
}

int add_new_data_to_buffer(const void* new_data, size_t seq, size_t len, 
                        size_t real_len, struct my_ring_buffer *buf);

static void destroy_ring_buffer(struct my_ring_buffer *buf) {
    
}
#endif