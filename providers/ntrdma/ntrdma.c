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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "ntrdma.h"

static const struct verbs_match_ent hca_table[] = {
	/* FIXME: ntrdma needs a more reliable way to detect the device */
	VERBS_NAME_MATCH("ntrdma", NULL),
	{},
};

static const struct verbs_context_ops ntrdma_ctx_ops = {
	.query_device = ntrdma_query_device,
	.query_port = ntrdma_query_port,
	.alloc_pd = ntrdma_alloc_pd,
	.dealloc_pd = ntrdma_dealloc_pd,
	.reg_mr = ntrdma_reg_mr,
	.dereg_mr = ntrdma_dereg_mr,
	.create_cq = ntrdma_create_cq,
	.poll_cq = ntrdma_poll_cq,
	.destroy_cq = ntrdma_destroy_cq,
	.create_qp = ntrdma_create_qp,
	.modify_qp = ntrdma_modify_qp,
	.destroy_qp = ntrdma_destroy_qp,
	.query_qp = ntrdma_query_qp,
	.post_send = ntrdma_post_send,
	.post_recv = ntrdma_post_recv,
	.create_ah = ntrdma_create_ah,
	.destroy_ah = ntrdma_destroy_ah,
	.req_notify_cq = ntrdma_req_notify_cq,
};

static struct verbs_context *ntrdma_alloc_context(struct ibv_device *ibdev,
						  int cmd_fd,
						  void *private_data)
{
	struct ntrdma_context *context;
	struct ibv_get_context cmd;
	struct ib_uverbs_get_context_resp resp;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context,
					       ibv_ctx, RDMA_DRIVER_NTRDMA);
	if (!context)
		return NULL;

	if (ibv_cmd_get_context(&context->ibv_ctx,
				&cmd, sizeof cmd,
				&resp, sizeof resp))
		goto out;

	verbs_set_ops(&context->ibv_ctx, &ntrdma_ctx_ops);

	return &context->ibv_ctx;

out:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void ntrdma_free_context(struct ibv_context *ibctx)
{
	struct ntrdma_context *context = to_ntrdma_ctx(ibctx);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static struct verbs_device *
ntrdma_driver_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct ntrdma_dev *dev;

	dev = malloc(sizeof *dev);
	if (!dev)
		return NULL;

	memset(dev, 0, sizeof(*dev));

	return &dev->ibdev;
}

static void ntrdma_driver_uninit(struct verbs_device *verbs_device)
{
	struct ntrdma_dev *dev = to_ntrdma_dev(&verbs_device->device);

	free(dev);
}

static const struct verbs_device_ops ntrdma_dev_ops = {
	.name = "ntrdma",
	.match_min_abi_version = 0,
	.match_max_abi_version = INT_MAX,
	.match_table = hca_table,
	.alloc_device = ntrdma_driver_alloc,
	.uninit_device = ntrdma_driver_uninit,
	.alloc_context = ntrdma_alloc_context,
	.free_context  = ntrdma_free_context
};
PROVIDER_DRIVER(ntrdma, ntrdma_dev_ops);
