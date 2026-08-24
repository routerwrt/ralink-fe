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

struct ralink_fe_priv;
struct ra_foe_entry;

struct ra_ppe {
	struct device *dev;
	struct ralink_fe_priv *fe;
	void __iomem *base;

	struct ra_foe_entry *foe_table;
	dma_addr_t foe_phys;
	u32 foe_entries;

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

void ra_ppe_foe_clear(struct ra_ppe *ppe, u32 index);
void ra_ppe_foe_clear_locked(struct ra_ppe *ppe, u32 index);

void ra_ppe_foe_commit(struct ra_ppe *ppe, u32 index,
		       const struct ra_foe_entry *entry);

void ra_ppe_foe_commit_locked(struct ra_ppe *ppe, u32 index,
			      const struct ra_foe_entry *entry);

#endif
