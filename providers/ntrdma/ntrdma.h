/*
 * Copyright (c) 2014-2019 Dell EMC, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef NTRDMA_H
#define NTRDMA_H

#include <infiniband/driver.h>
#include <ccan/container_of.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <pthread.h>

struct ntrdma_dev {
	struct verbs_device	ibdev;
};

static inline struct ntrdma_dev *to_ntrdma_dev(struct verbs_device *ibdev)
{
	return container_of(ibdev, struct ntrdma_dev, ibdev);
}

struct ntrdma_context {
        struct verbs_context ibv_ctx;
};

static inline struct ntrdma_context *to_ntrdma_ctx(struct ibv_context *ibctx)
{
        return container_of(ibctx, struct ntrdma_context, ibv_ctx.context);
}

struct ntrdma_qp {
	struct ibv_qp ibv_qp;
	pthread_mutex_t mutex;
	void *buffer;
	int buffer_size;
	int fd;
};

static inline struct ntrdma_qp *to_ntrdma_qp(struct ibv_qp *ibv_qp)
{
        return container_of(ibv_qp, struct ntrdma_qp, ibv_qp);
}

struct ntrdma_cq {
	struct ibv_cq ibv_cq;
	pthread_mutex_t mutex;
	void *buffer;
	int buffer_size;
	int fd;
};

static inline struct ntrdma_cq *to_ntrdma_cq(struct ibv_cq *ibv_cq)
{
        return container_of(ibv_cq, struct ntrdma_cq, ibv_cq);
}

int ntrdma_query_device(struct ibv_context *context,
			struct ibv_device_attr *device_attr);
int ntrdma_query_port(struct ibv_context *context, uint8_t port_num,
		      struct ibv_port_attr *port_attr);
struct ibv_pd *ntrdma_alloc_pd(struct ibv_context *context);
int ntrdma_dealloc_pd(struct ibv_pd *pd);
struct ibv_mr *ntrdma_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     uint64_t hca_va, int access);

int ntrdma_dereg_mr(struct verbs_mr *vmr);
struct ibv_cq *ntrdma_create_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector);
int ntrdma_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc);
int ntrdma_destroy_cq(struct ibv_cq *cq);
struct ibv_qp *ntrdma_create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr);
int ntrdma_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask);
int ntrdma_destroy_qp(struct ibv_qp *qp);
int ntrdma_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    int attr_mask, struct ibv_qp_init_attr *init_attr);
int ntrdma_post_send(struct ibv_qp *qp, struct ibv_send_wr *swr,
		     struct ibv_send_wr **bad);
int ntrdma_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *rwr,
		     struct ibv_recv_wr **bad);
struct ibv_ah *ntrdma_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);
int ntrdma_destroy_ah(struct ibv_ah *ah);
int ntrdma_req_notify_cq(struct ibv_cq *cq, int solicited_only);

typedef unsigned long long cycles_t;
typedef unsigned long long u64;
typedef unsigned int u32;

struct ntc_perf_tracker {
	cycles_t total;
	cycles_t total_out;
	cycles_t last;
	u64 num_calls;
};

struct ntc_perf_tracker_current {
	struct ntc_perf_tracker *tracker;
	cycles_t start;
	const char *prefix;
	u64 window;
};

static inline u64 ntc_get_cycles(void)
{
	u32 low, high;

	__asm __volatile("rdtsc" : "=a" (low), "=d" (high)::"memory");
	return (low | ((u64)high << 32));
}

extern bool ntrdma_measure_perf;
extern bool ntrdma_print_debug;
extern FILE *ntrdma_kmsg_file;

#define PRINT_KMSG(format, ...)					\
	do {							\
		FILE *kmsg_file = ntrdma_kmsg_file;		\
		if (!kmsg_file)					\
			break;					\
		fprintf(kmsg_file, format, ## __VA_ARGS__);	\
		fflush(kmsg_file);				\
	} while (0)

#define PRINT_DEBUG_KMSG(format, ...)			\
	do {						\
		if (!ntrdma_print_debug)		\
			break;				\
		PRINT_KMSG(format, ## __VA_ARGS__);	\
	} while (0)



static inline void ntc_perf_finish_measure(struct ntc_perf_tracker_current *c)
{
	struct ntc_perf_tracker *t = c->tracker;

	if (!ntrdma_measure_perf)
		return;

	if (likely(t->last || t->num_calls))
		t->total_out += c->start - t->last;

	t->last = ntc_get_cycles();
	t->total += t->last - c->start;
	t->num_calls++;

	if (t->num_calls != c->window)
		return;

	PRINT_KMSG("USPERF: %s [%d]: "
		"%lld calls. %lld%% of time. %lld cyc average.\n",
		c->prefix, (int)syscall(SYS_gettid), t->num_calls,
		t->total * 100 / (t->total + t->total_out),
		t->total / t->num_calls);

	t->num_calls = 0;
	t->total_out = 0;
	t->total = 0;
}

#define NTC_PERF_TRACK

#ifdef NTC_PERF_TRACK

#define DEFINE_NTC_PERF_TRACKER(name, p, w)				\
	static __thread struct ntc_perf_tracker name##_per_cpu;		\
	struct ntc_perf_tracker_current name =				\
	{ .start = ntc_get_cycles(), .prefix = p, .window = w }

#define NTC_PERF_MEASURE(name) do {					\
		name.tracker = &name##_per_cpu;				\
		ntc_perf_finish_measure(&name);				\
	} while (0)

#else
#define DEFINE_NTC_PERF_TRACKER(name, p, w) int name  __attribute__ ((unused))
#define NTC_PERF_MEASURE(name) do {} while (0)
#endif


#define DEFINE_NTC_FUNC_PERF_TRACKER(name, w)		\
	DEFINE_NTC_PERF_TRACKER(name, __func__, w)

#endif
