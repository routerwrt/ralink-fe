/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RA_PPE_H
#define _RA_PPE_H

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct net_device;
struct ralink_fe_priv;
struct ra_ppe;

struct ra_ppe_offload_ops;

struct ra_ppe_ops {
	int (*init)(struct ra_ppe *ppe);
	void (*deinit)(struct ra_ppe *ppe);

	int (*start)(struct ra_ppe *ppe);
	void (*stop)(struct ra_ppe *ppe);

	const struct ra_ppe_offload_ops *offload;

	size_t foe_entry_size;

	u8 cpu_reason_unbind_rate;
	u8 cpu_reason_keepalive;
};

struct ra_ppe {
	struct device *dev;
	struct ralink_fe_priv *fe;
	void __iomem *base;

	const struct ra_ppe_ops *ops;

	void *foe_table;
	dma_addr_t foe_phys;
	u32 foe_entries;
	size_t foe_entry_size;

	/*
	 * Serializes direct manipulation of hardware-visible FOE entries.
	 */
	spinlock_t lock;

	/*
	 * Linux-authorized offload flows.
	 *
	 * flow_table:
	 *	flow cookie -> ra_flow_entry
	 *
	 * flow_tuple_table:
	 *	exact learned IPv4 5-tuple -> ra_flow_entry
	 */
	struct rhashtable flow_table;
	struct rhashtable flow_tuple_table;

	struct list_head flow_block_cb_list;
	struct mutex flow_lock;
};

static inline u32 ra_ppe_r32(struct ra_ppe *ppe, u32 reg)
{
	return readl(ppe->base + reg);
}

static inline void ra_ppe_w32(struct ra_ppe *ppe, u32 reg, u32 val)
{
	writel(val, ppe->base + reg);
}

static inline void ra_ppe_m32(struct ra_ppe *ppe, u32 reg,
			      u32 mask, u32 val)
{
	u32 data;

	data = ra_ppe_r32(ppe, reg);
	data &= ~mask;
	data |= val & mask;

	ra_ppe_w32(ppe, reg, data);
}

int ra_ppe_init(struct ralink_fe_priv *priv);
int ra_ppe_start(struct ra_ppe *ppe);
void ra_ppe_stop(struct ra_ppe *ppe);
void ra_ppe_deinit(struct ra_ppe *ppe);

int ra_ppe_setup_tc(struct ra_ppe *ppe, struct net_device *dev,
		    void *type_data);

bool ra_ppe_offload_check(struct ra_ppe *ppe, u16 foe, bool keepalive);

#ifdef CONFIG_RALINK_FE_PPE
extern const struct ra_ppe_ops ra_ppe_v1_ops;
extern const struct ra_ppe_ops ra_ppe_v2_ops;

#define RA_PPE_V1_OPS	(&ra_ppe_v1_ops)
#define RA_PPE_V2_OPS	(&ra_ppe_v2_ops)
#else
#define RA_PPE_V1_OPS	NULL
#define RA_PPE_V2_OPS	NULL
#endif

#endif
