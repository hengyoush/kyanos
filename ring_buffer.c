//go:build ignore
#include <stdlib.h>
#include <stdio.h>
#include "ring_buffer.h"


struct my_ring_buffer* new_ring_buffer(uint32_t cap) {
    struct my_ring_buffer* buf;
    buf = malloc(sizeof(struct my_ring_buffer));
    if (buf == NULL) {
        return NULL;
    }
    buf->buf = malloc(cap);
    if (buf->buf == NULL) {
        goto fail;
    }

    return buf;

    fail:
    if (buf && buf->buf) {
        free(buf->buf);
    }
    if (buf) {
        free(buf);
    }
}

static struct chunk_t *new_chunk(size_t seq, size_t len, size_t real_len) {
    struct chunk_t *c = malloc(sizeof(struct chunk_t));
    if (c) {
        c->seq = seq;
        c->real_len = real_len;
        c->len = len;
    }
    return c;
}

int add_new_data_to_buffer(const void* new_data, size_t seq, size_t len, 
                        size_t real_len, struct my_ring_buffer *buf) {
    
    fprintf(stderr, "new data add to ringbuffer!\n");
    size_t avail = avail_space(buf);
    if (avail <= 0) {
        // TODO
        return;
    }

    if (buf->cap < len) {
        // 必须截断, 我们已经占了所有空间！ TODO
        size_t offset = 0;
        offset += (len - buf->cap);
        seq += offset;
        
        return;
    }

    if (avail < len) {
        size_t offset = 0;
        // 缩减长度
        len = avail;
    }

    // 看是否能merge到前一个chunk
    if(g_list_length(buf->chunks) > 0) {
        struct chunk_t * last_chunk = g_slist_last(buf->chunks)->data;
        if (last_chunk->real_len == last_chunk->len && last_chunk->seq + last_chunk->len == seq) {
            // 可以合并！
            last_chunk->len += len;
            last_chunk->real_len += real_len;
        } else {
            // 不能合并
            struct chunk_t *chunk = new_chunk(seq, real_len, len);
            g_slist_append(buf->chunks, chunk);
        }
    } else {
        // 我们是第一个chunk
        struct chunk_t *_chunk = new_chunk(seq, real_len, len);
        g_slist_append(buf->chunks, _chunk);
    }

    memcpy(buf->buf + buf->write_pos, new_data, len);
    buf->write_pos += len;
}
