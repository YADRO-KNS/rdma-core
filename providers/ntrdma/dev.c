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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include "ntrdma.h"

int ntrdma_query_device(struct ibv_context *context,
			struct ibv_device_attr *device_attr)
{
	uint64_t raw_fw_ver;
	struct ibv_query_device cmd;

	return ibv_cmd_query_device(context, device_attr,
				    &raw_fw_ver, &cmd, sizeof cmd);
}

int ntrdma_query_port(struct ibv_context *context, uint8_t port_num,
		      struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port_num, port_attr,
				  &cmd, sizeof cmd);
}

struct ibv_pd *ntrdma_alloc_pd(struct ibv_context *context)
{
	struct ibv_pd *pd;
	struct ibv_alloc_pd cmd;
	struct ib_uverbs_alloc_pd_resp resp;

	pd = malloc(sizeof(*pd));
	if (!pd)
		return NULL;

	memset(pd, 0, sizeof(*pd));

	errno = ibv_cmd_alloc_pd(context, pd,
				 &cmd, sizeof cmd,
				 &resp, sizeof resp);
	if (errno)
		goto err_free;

	return pd;

err_free:
	free(pd);
	return NULL;
}

int ntrdma_dealloc_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(pd);
	return 0;
}

struct ibv_mr *ntrdma_reg_mr(struct ibv_pd *pd, void *addr,
			     size_t length, int access)
{
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	memset(vmr, 0, sizeof(*vmr));

	errno = ibv_cmd_reg_mr(pd, addr,
			       length, (unsigned long)addr,
			       access, vmr,
			       &cmd, sizeof cmd,
			       &resp, sizeof resp);
	if (errno) {
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

int ntrdma_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);
	return 0;
}

struct ibv_cq *ntrdma_create_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector)
{
	struct ibv_cq *cq;
	struct ibv_create_cq cmd;
	struct ib_uverbs_create_cq_resp resp;

	cq = malloc(sizeof(*cq));
	if (!cq)
		return NULL;

	memset(cq, 0, sizeof(*cq));

	errno = ibv_cmd_create_cq(context, cqe, channel,
				  comp_vector, cq,
				  &cmd, sizeof cmd,
				  &resp, sizeof resp);
	if (errno)
		goto err_free;

	return cq;

err_free:
	free(cq);
	return NULL;
}

int ntrdma_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{
	return ibv_cmd_poll_cq(cq, num_entries, wc);
}

int ntrdma_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	free(cq);
	return 0;
}

struct ibv_qp *ntrdma_create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr)
{
	struct ntrdma_qp *qp;
	struct ibv_create_qp cmd;
	struct {
		 /* resp must be first member of this struct. */
		struct ib_uverbs_create_qp_resp resp;
		int qpfd;
	} ext_resp = {
		.qpfd = -1,
	};

	/* resp must be first member of ext_resp. */
	assert((void *)&ext_resp == (void *)&ext_resp.resp);

	qp = malloc(sizeof(*qp));
	if (!qp)
		return NULL;

	memset(qp, 0, sizeof(*qp));

	pthread_mutex_init(&qp->mutex, NULL);

	qp->buffer_size = sysconf(_SC_PAGESIZE);
	qp->buffer = memalign(qp->buffer_size, qp->buffer_size);
	if (!qp->buffer)
		goto err;

	errno = ibv_cmd_create_qp(pd, &qp->ibv_qp, attr,
				&cmd, sizeof cmd,
				&ext_resp.resp, sizeof ext_resp);
	if (errno)
		goto err;

	qp->fd = ext_resp.qpfd;

	PRINT_DEBUG_KMSG("NTRDMADEB %s: qp->fd = %d\n", __func__, qp->fd);

	if (qp->fd < 0) {
		free(qp->buffer);
		qp->buffer = NULL;
	}

	return &qp->ibv_qp;

 err:
	if (qp->buffer)
		free(qp->buffer);

	pthread_mutex_destroy(&qp->mutex);

	free(qp);
	return NULL;
}

int ntrdma_modify_qp(struct ibv_qp *qp,
		     struct ibv_qp_attr *attr, int attr_mask)
{
	struct ibv_modify_qp cmd;

	return ibv_cmd_modify_qp(qp, attr, attr_mask,
				&cmd, sizeof cmd);
}

int ntrdma_destroy_qp(struct ibv_qp *_qp)
{
	struct ntrdma_qp *qp = to_ntrdma_qp(_qp);
	int ret;

	if (qp->fd >= 0) {
		close(qp->fd);
		qp->fd = -1;
	}

	ret = ibv_cmd_destroy_qp(&qp->ibv_qp);
	if (ret)
		return ret;

	free(qp->buffer);

	pthread_mutex_destroy(&qp->mutex);

	free(qp);
	return 0;
}

int ntrdma_query_qp(struct ibv_qp *qp,
		    struct ibv_qp_attr *qp_attr, int attr_mask,
		    struct ibv_qp_init_attr *qp_init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, qp_attr, attr_mask, qp_init_attr,
				&cmd, sizeof cmd);
}

int ntrdma_post_send(struct ibv_qp *_qp, struct ibv_send_wr *swr,
		     struct ibv_send_wr **bad)
{
	struct ntrdma_qp *qp = to_ntrdma_qp(_qp);
	int rc;

	DEFINE_NTC_FUNC_PERF_TRACKER(perf, 1 << 20);

	pthread_mutex_lock(&qp->mutex);

	/* Now use qp->buffer */

	rc = ibv_cmd_post_send(_qp, swr, bad);
	pthread_mutex_unlock(&qp->mutex);

	NTC_PERF_MEASURE(perf);

	return rc;
}

int ntrdma_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *rwr,
		     struct ibv_recv_wr **bad)
{
	return ibv_cmd_post_recv(qp, rwr, bad);
}

struct ibv_ah *ntrdma_create_ah(struct ibv_pd *pd,
				struct ibv_ah_attr *attr)
{
	errno = ENOSYS;
	return NULL;
}

int ntrdma_destroy_ah(struct ibv_ah *ah)
{
	errno = ENOSYS;
	return -1;
}

int ntrdma_req_notify_cq(struct ibv_cq *cq, int solicited_only)
{
	return ibv_cmd_req_notify_cq(cq, solicited_only);
}
