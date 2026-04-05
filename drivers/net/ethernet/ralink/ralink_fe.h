/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RALINK_FE_H
#define __RALINK_FE_H

#include <linux/spinlock.h>

struct ralink_fe_soc_data {
	u8				txqs;
	u8				rxqs;
	bool				needs_sdm;
};

struct ralink_fe_priv {
	void __iomem			*base;
	struct device			*dev;
	struct net_device		*ndev;

	const struct ralink_fe_soc_data	*soc;

	struct clk			*clk;
	struct reset_control		*rst_fe;

	spinlock_t			irq_lock;

	u8				txqs;
	u8				rxqs;
};

#endif /* __RALINK_FE_H */
