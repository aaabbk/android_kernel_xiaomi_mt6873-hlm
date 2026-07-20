/*
 * Copyright (c) 2015-2019, MICROTRUST Incorporated
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include "teei_keymaster.h"
#include "teei_client_transfer_data.h"
#define IMSG_TAG "[tz_driver]"
#include <imsg_log.h>
#include <linux/vmalloc.h>

extern unsigned long teei_config_flag;

#define KM_COMMAND_MAGIC 'X'

int send_keymaster_command(void *buffer, unsigned long size)
{
	int ret = 0;
	struct TEEC_Context context;
	struct TEEC_UUID uuid_ta = { 0xc09c9c5d, 0xaa50, 0x4b78,
	{ 0xb0, 0xe4, 0x6e, 0xda, 0x61, 0x55, 0x6c, 0x3a } };
	int wait_count = 0;

	if (buffer == NULL || size < 1)
		return -1;

	/* Wait for TEE to be ready before sending keymaster command.
	 * keystore2 may call earlyBootEnded before TEE init completes. */
	while (!teei_config_flag) {
		if (wait_count++ > 50) /* 5 seconds max */
			return -1;
		msleep(100);
	}

	memset(&context, 0, sizeof(context));
	ret = ut_pf_gp_initialize_context(&context);
	if (ret) {
		IMSG_ERROR("Failed to initialize keymaster context ,err: %x",
		ret);
		goto release_1;
	}

	ret = ut_pf_gp_transfer_user_data(&context, &uuid_ta, KM_COMMAND_MAGIC,
	buffer, size);
	if (ret) {
		IMSG_ERROR("Failed to transfer data,err: %x", ret);
		goto release_2;
	}
release_2:
	ut_pf_gp_finalize_context(&context);
release_1:
	return ret;
}
