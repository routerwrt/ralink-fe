/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RALINK_FE_H
#define __RALINK_FE_H

#include <linux/spinlock.h>

/* --- configurable --- */
#define RALINK_FE_TX_RING_SIZE     128
#define RALINK_FE_RX_RING_SIZE     256

#define RALINK_FE_NAPI_RX          32
#define RALINK_FE_NAPI_TX          32

#define RALINK_FE_TX_STOP_RESERVE 16
#define RALINK_FE_TX_WAKE_THRESH 16

/* Power-of-2 masks */
#define RALINK_FE_TX_RING_MASK     (RALINK_FE_TX_RING_SIZE - 1)
#define RALINK_FE_RX_RING_MASK     (RALINK_FE_RX_RING_SIZE - 1)

/* explicit headroom, independent from RALINK_FE_MAX_DMA_LEN */
#define RALINK_FE_RX_HEADROOM_BYTES     64 + NET_IP_ALIGN
#define RALINK_FE_MAX_DMA_LEN		1536
#define RALINK_FE_RX_DMA_SIZE		RALINK_FE_RX_HEADROOM_BYTES + \

#define RALINK_FE_MAX_TXQ          4
#define RALINK_FE_MAX_RXQ          2

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

/* ---- descriptors ---- */
struct ralink_fe_tx_desc {
	u32 info1; /* addr0 */
	u32 info2; /* len0/len1/flags/done */
	u32 info3; /* addr1 */
	u32 info4; /* reserved (kept 0 for cross-SoC compatibility) */
};

struct ralink_fe_rx_desc {
	u32 info1; /* addr */
	u32 info2; /* len/flags/done */
	u32 info3;
	u32 info4; /* checksum flags etc. */
};

struct ralink_fe_soc_data {
	u8				txqs;
	u8				rxqs;
	bool				needs_sdm;
};

/* Per-queue NAPI wrapper so poll callbacks can recover the queue index. */
struct ralink_fe_qnapi {
	struct napi_struct		napi;
	struct ralink_fe_priv		*priv;
	u8				q;
};

struct ralink_fe_tx_ring {
	struct ralink_fe_tx_desc	*desc;
	dma_addr_t			desc_dma;

	u16				cpu_idx;
	u16				clean_idx;

	struct sk_buff			*skb[RALINK_FE_TX_RING_SIZE];
	u8				map[RALINK_FE_TX_RING_SIZE];

	struct ralink_fe_qnapi		napi;
};

/* RX buffer (full page) */
struct ralink_fe_rx_buf {
	struct page	*page;
	dma_addr_t	dma;
};

struct ralink_fe_rx_ring {
	struct ralink_fe_rx_desc	*desc;
	dma_addr_t			desc_dma;

	u16				cpu_idx;

	struct page_pool		*pp;
	struct ralink_fe_rx_buf		buf[RALINK_FE_RX_RING_SIZE];
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
	u32				irq_mask;
	u32				rx_irq_mask;
	u32				irq_mask_all;

	u8				txqs;
	u8				rxqs;

	struct ralink_fe_tx_ring	tx_ring[RALINK_FE_MAX_TXQ];
	struct ralink_fe_rx_ring	rx_ring[RALINK_FE_MAX_RXQ];
	struct napi_struct		rx_napi_all;
};

#endif /* __RALINK_FE_H */
