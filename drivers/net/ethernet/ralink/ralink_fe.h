/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RALINK_FE_H
#define __RALINK_FE_H

#include <linux/spinlock.h>

/* SDM – Switch DMA glue block */

/* SDM registers */
#define SDM_CON             0x0000
#define SDM_MAC_ADRL        0x000c
#define SDM_MAC_ADRH        0x0010
#define SDM_MAC_ADRH_MASK   GENMASK(15, 0)

#define SDM_PDMA_FC     BIT(23)
#define SDM_PORT_MAP    BIT(22)
#define SDM_TCI_81XX    BIT(20)
#define SDM_UDPCS       BIT(18)
#define SDM_TCPCS       BIT(17)
#define SDM_IPCS        BIT(16)
#define SDM_EXT_VLAN    GENMASK(15, 0)

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
	struct regmap			*sdm;
	int				irq;
	spinlock_t			irq_lock;

	u8				txqs;
	u8				rxqs;
};

#endif /* __RALINK_FE_H */
