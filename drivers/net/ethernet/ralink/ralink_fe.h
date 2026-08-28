/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RALINK_FE_H
#define __RALINK_FE_H

#include <linux/dim.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/phylink.h>
#include <linux/u64_stats_sync.h>

/* --- configurable --- */
#define RALINK_FE_TX_RING_SIZE		128
#define RALINK_FE_RX_RING_SIZE		256

#define RALINK_FE_NAPI_RX		64
#define RALINK_FE_NAPI_TX		64
#define RALINK_FE_TX_POLL_QUANTUM	8

#define RALINK_FE_TX_STOP_RESERVE	16
#define RALINK_FE_TX_WAKE_THRESH	16

#define RALINK_MAX_DSA_PORTS		8

/* Power-of-2 masks */
#define RALINK_FE_TX_RING_MASK		(RALINK_FE_TX_RING_SIZE - 1)
#define RALINK_FE_RX_RING_MASK		(RALINK_FE_RX_RING_SIZE - 1)

/* explicit headroom, independent from RALINK_FE_MAX_DMA_LEN */
#define RALINK_FE_RX_HEADROOM_BYTES     (64 + NET_IP_ALIGN)
#define RALINK_FE_MAX_DMA_LEN		(1536)
#define RALINK_FE_RX_DMA_SIZE		\
	(RALINK_FE_RX_HEADROOM_BYTES + RALINK_FE_MAX_DMA_LEN)
#define RALINK_FE_MAX_TXQ		4
#define RALINK_FE_MAX_RXQ		2

#define PDMA_RST_DTX_IDX0		BIT(0)
#define PDMA_RST_DTX_IDX1		BIT(1)
#define PDMA_RST_DTX_IDX2		BIT(2)
#define PDMA_RST_DTX_IDX3		BIT(3)
#define PDMA_RST_DRX_IDX0		BIT(16)
#define PDMA_RST_DRX_IDX1		BIT(17)

#define FE_DLY_INT_TX_EN	BIT(31)
#define FE_DLY_INT_TX_PINT	GENMASK(30, 24)
#define FE_DLY_INT_TX_PTIME	GENMASK(23, 16)

#define FE_DLY_INT_RX_EN	BIT(15)
#define FE_DLY_INT_RX_PINT	GENMASK(14, 8)
#define FE_DLY_INT_RX_PTIME	GENMASK(7, 0)

static const u32 tx_rst[] = {
	PDMA_RST_DTX_IDX0,
	PDMA_RST_DTX_IDX1,
	PDMA_RST_DTX_IDX2,
	PDMA_RST_DTX_IDX3,
};

static const u32 rx_rst[] = {
	PDMA_RST_DRX_IDX0,
	PDMA_RST_DRX_IDX1,
};

/* ---- PDMA GLO bits ---- */
#define RX_2B_OFFSET			BIT(31)
#define CSR_CLKGATE			BIT(30)
#define TX_WB_DDONE			BIT(6)
#define RX_DMA_BUSY			BIT(3)
#define RX_DMA_EN			BIT(2)
#define TX_DMA_BUSY			BIT(1)
#define TX_DMA_EN			BIT(0)

#define PDMA_BT_SIZE_8WORDS		(1 << 4)
#define PDMA_BT_SIZE_16WORDS		(2 << 4)

#define RT305x_PDMA_FC_CFG	0x01f0

/* RALINK TX scheduling */
#define RA_SCH_MODE_MASK	GENMASK(25, 24)
#define  RA_SCH_MODE_WRR	0x0
#define RA_SCH_MODE(v)		FIELD_PREP(RA_SCH_MODE_MASK, (v))
#define RA_WRR_WT_Q0_MASK	GENMASK(2, 0)
#define RA_WRR_WT_Q1_MASK	GENMASK(6, 4)
#define RA_WRR_WT_Q2_MASK	GENMASK(10, 8)
#define RA_WRR_WT_Q3_MASK	GENMASK(14, 12)
#define RA_WRR_WT_Q0(v)		FIELD_PREP(RA_WRR_WT_Q0_MASK, (v))
#define RA_WRR_WT_Q1(v)		FIELD_PREP(RA_WRR_WT_Q1_MASK, (v))
#define RA_WRR_WT_Q2(v)		FIELD_PREP(RA_WRR_WT_Q2_MASK, (v))
#define RA_WRR_WT_Q3(v)		FIELD_PREP(RA_WRR_WT_Q3_MASK, (v))

#define RA_FE_WT_1		0

#define RA_FE_SCH_EQUAL_WRR	(RA_WRR_WT_Q0(RA_FE_WT_1) | \
				RA_WRR_WT_Q1(RA_FE_WT_1) | \
				RA_WRR_WT_Q2(RA_FE_WT_1) | \
				RA_WRR_WT_Q3(RA_FE_WT_1))

/* PDMA shaper: two queues per scheduler register */
#define PDMA_SHPR_MAX_BKT_HI		BIT(31)
#define PDMA_SHPR_MAX_RATE_ULMT_HI	BIT(30)
#define PDMA_SHPR_MAX_WEIGHT_HI_MASK	GENMASK(29, 28)
#define PDMA_SHPR_MIN_RATE_HI_MASK	GENMASK(27, 26)
#define PDMA_SHPR_MAX_RATE_HI_MASK	GENMASK(25, 16)

#define PDMA_SHPR_MAX_BKT_LO		BIT(15)
#define PDMA_SHPR_MAX_RATE_ULMT_LO	BIT(14)
#define PDMA_SHPR_MAX_WEIGHT_LO_MASK	GENMASK(13, 12)
#define PDMA_SHPR_MIN_RATE_LO_MASK	GENMASK(11, 10)
#define PDMA_SHPR_MAX_RATE_LO_MASK	GENMASK(9, 0)

#define PDMA_SHPR_MAX_WEIGHT_HI(v)	\
	FIELD_PREP(PDMA_SHPR_MAX_WEIGHT_HI_MASK, (v))
#define PDMA_SHPR_MIN_RATE_HI(v)	\
	FIELD_PREP(PDMA_SHPR_MIN_RATE_HI_MASK, (v))
#define PDMA_SHPR_MAX_RATE_HI(v)	\
	FIELD_PREP(PDMA_SHPR_MAX_RATE_HI_MASK, (v))

#define PDMA_SHPR_MAX_WEIGHT_LO(v)	\
	FIELD_PREP(PDMA_SHPR_MAX_WEIGHT_LO_MASK, (v))
#define PDMA_SHPR_MIN_RATE_LO(v)	\
	FIELD_PREP(PDMA_SHPR_MIN_RATE_LO_MASK, (v))
#define PDMA_SHPR_MAX_RATE_LO(v)	\
	FIELD_PREP(PDMA_SHPR_MAX_RATE_LO_MASK, (v))

#define PDMA_SHPR_WEIGHT_EQUAL		0
#define PDMA_SHPR_MIN_RATE_NONE		3

#define PDMA_SHPR_UNLIMITED_EQUAL				\
	(PDMA_SHPR_MAX_RATE_ULMT_HI |				\
	 PDMA_SHPR_MAX_WEIGHT_HI(PDMA_SHPR_WEIGHT_EQUAL) |	\
	 PDMA_SHPR_MIN_RATE_HI(PDMA_SHPR_MIN_RATE_NONE) |	\
	 PDMA_SHPR_MAX_RATE_ULMT_LO |				\
	 PDMA_SHPR_MAX_WEIGHT_LO(PDMA_SHPR_WEIGHT_EQUAL) |	\
	 PDMA_SHPR_MIN_RATE_LO(PDMA_SHPR_MIN_RATE_NONE))

#define FE_GLO_CFG		0x0008
#define FE_US_CYC_CNT_MASK	GENMASK(15, 8)
#define FE_US_CYC_CNT_SET(v)	FIELD_PREP(FE_US_CYC_CNT_MASK, (v))

#define SDM_PORT_MAP		BIT(22)
#define SDM_UDPCS		BIT(18)
#define SDM_TCPCS		BIT(17)
#define SDM_IPCS		BIT(16)

/* GDM */
#define GDM_ICS_EN		BIT(22)
#define GDM_TCS_EN		BIT(21)
#define GDM_UCS_EN		BIT(20)

#define GDM_SHPR_EN		BIT(24)

/* CDM_CSG_CFG */
#define CDM_CSG_CFG_INS_VLAN_MASK	GENMASK(31, 16)
#define CDM_CSG_CFG_SP_RING_MASK	GENMASK(15, 8)
#define CDM_CSG_CFG_SP_RING(port)	BIT(8 + (port))

#define CDM_ICS_GEN_EN			BIT(2)
#define CDM_UCS_GEN_EN			BIT(1)
#define CDM_TCS_GEN_EN			BIT(0)

/* RT2880/RT3883 FE MDIO / GE1 */
#define FE_MDIO_ACCESS			0x0000
#define FE_MDIO_CFG			0x0004

#define FE_MDIO_CMD_TRG			BIT(31)
#define FE_MDIO_WRITE			BIT(30)
#define FE_MDIO_PHY_ADDR		GENMASK(28, 24)
#define FE_MDIO_REG_ADDR		GENMASK(20, 16)
#define FE_MDIO_DATA			GENMASK(15, 0)

#define FE_MDIO_CFG_GP1_AUTO_POLL	BIT(29)
#define FE_MDIO_CFG_GP1_FRC_EN		BIT(15)
#define FE_MDIO_CFG_GP1_SPEED		GENMASK(14, 13)
#define FE_MDIO_CFG_GP1_DUPLEX		BIT(12)
#define FE_MDIO_CFG_GP1_FC_TX		BIT(11)
#define FE_MDIO_CFG_GP1_FC_RX		BIT(10)

#define FE_MDIO_CFG_GP1_SPEED_10	0
#define FE_MDIO_CFG_GP1_SPEED_100	1
#define FE_MDIO_CFG_GP1_SPEED_1000	2

#define RALINK_FE_MDIO_TIMEOUT_US	1000

/* ---- descriptors ---- */
struct ralink_fe_tx_desc {
	u32 info1; /* addr0 */
	u32 info2; /* len0/len1/flags/done */
	u32 info3; /* addr1 */
	u32 info4; /* reserved (kept 0 for cross-SoC compatibility) */
};

#define TX2_DMA_SDL1_MASK	GENMASK(13, 0)
#define TX2_DMA_LS1		BIT(14)
#define TX2_DMA_SDL0_MASK	GENMASK(29, 16)
#define TX2_DMA_LS0		BIT(30)
#define TX2_DMA_DONE		BIT(31)

#define TX2_DMA_SDL1(_x)	FIELD_PREP(TX2_DMA_SDL1_MASK, (_x))
#define TX2_DMA_SDL0(_x)	FIELD_PREP(TX2_DMA_SDL0_MASK, (_x))
#define TX2_DMA_SDL1_GET(_x)	FIELD_GET(TX2_DMA_SDL1_MASK, (_x))
#define TX2_DMA_SDL0_GET(_x)	FIELD_GET(TX2_DMA_SDL0_MASK, (_x))

#define TX4_DMA_ICO		BIT(31)
#define TX4_DMA_UCO		BIT(30)
#define TX4_DMA_TCO		BIT(29)

#define TX4_DMA_PN_MASK		GENMASK(26, 24)
#define TX4_DMA_QN_MASK		GENMASK(18, 16)

#define TX4_DMA_PN(_x)		FIELD_PREP(TX4_DMA_PN_MASK, (_x))
#define TX4_DMA_QN(_x)		FIELD_PREP(TX4_DMA_QN_MASK, (_x))

#define MT7620_FP_BMAP		GENMASK(27, 20)
#define TX4_DMA_FP(_x)		FIELD_PREP(MT7620_FP_BMAP, (_x))

struct ralink_fe_rx_desc {
	u32 info1; /* addr */
	u32 info2; /* len/flags/done */
	u32 info3;
	u32 info4; /* checksum flags etc. */
};

#define RX2_DMA_SDL1_MASK	GENMASK(13, 0)
#define RX2_DMA_SDL0_MASK	GENMASK(29, 16)
#define RX2_DMA_LS0		BIT(30)
#define RX2_DMA_DONE		BIT(31)

#define RX2_DMA_SDL1(_x)	FIELD_PREP(RX2_DMA_SDL1_MASK, (_x))
#define RX2_DMA_SDL0(_x)	FIELD_PREP(RX2_DMA_SDL0_MASK, (_x))
#define RX2_DMA_SDL1_GET(_x)	FIELD_GET(RX2_DMA_SDL1_MASK, (_x))
#define RX2_DMA_SDL0_GET(_x)	FIELD_GET(RX2_DMA_SDL0_MASK, (_x))

/*
 * RX4_DMA_L4FVLD means the L4 checksum result is valid for this packet
 * (IPv4, no fragments, TCP/UDP). RX4_DMA_L4F indicates checksum failure.
 */
#define RX4_DMA_IPFVLD		BIT(31)
#define RX4_DMA_L4FVLD		BIT(30)
#define RX4_DMA_IPF		BIT(29)
#define RX4_DMA_L4F		BIT(28)
#define RX4_DMA_AIS		BIT(27)
#define RX4_DMA_SP_MASK		GENMASK(26, 24)
#define RX4_DMA_AI_MASK		GENMASK(23, 16)
#define RX4_DMA_FVLD		BIT(14)
#define RX4_DMA_FOE_ENTRY	GENMASK(13, 0)

#define RX4_DMA_SP_GET(_x)	FIELD_GET(RX4_DMA_SP_MASK, (_x))
#define RX4_DMA_AI_GET(_x)	FIELD_GET(RX4_DMA_AI_MASK, (_x))
#define RX4_DMA_FOE_GET(_x)	FIELD_GET(RX4_DMA_FOE_ENTRY, (_x))

#define MT7620_RX4_PKT_INFO	GENMASK(27, 22)
#define MT7620_RX4_PKT_L4_ERR	BIT(22)
#define MT7620_RX4_PKT_L4_VALID	BIT(23)
#define MT7620_RX4_PKT_IP_ERR	BIT(25)
#define MT7620_RX4_SP_MASK	GENMASK(21, 19)
#define MT7620_DMA_SP_GET(_x)	FIELD_GET(MT7620_RX4_SP_MASK, (_x))


/* ---- private ---- */
#define RALINK_FE_TX_MAP0_PAGE  BIT(0)
#define RALINK_FE_TX_MAP1_PAGE  BIT(1)

enum ra_ppe_version {
	RA_PPE_NONE = 0,
	RA_PPE_V1,
	RA_PPE_V2,
};

enum ra_tx4_port {
	RA_TX4_NONE = 0,
	RA_TX4_PNQN,
	RA_TX4_FP,
};

struct ralink_fe_reg_map {
	u32 tx_base_ptr[RALINK_FE_MAX_TXQ];
	u32 tx_max_cnt[RALINK_FE_MAX_TXQ];
	u32 tx_cpu_idx[RALINK_FE_MAX_TXQ];
	u32 tx_dma_idx[RALINK_FE_MAX_TXQ];

	u32 rx_base_ptr[RALINK_FE_MAX_RXQ];
	u32 rx_max_cnt[RALINK_FE_MAX_RXQ];
	u32 rx_cpu_idx[RALINK_FE_MAX_RXQ];

	u32 tx_dly_irq;
	u32 rx_dly_irq;

	u32 glo_cfg;
	u32 rst_idx;
	u32 dly_int_cfg;
	u32 int_status;
	u32 int_enable;
};

struct ralink_pdma_sched_regs {
	u32 cfg0;
	u32 cfg1;
};

enum ralink_pdma_sched_type {
	RALINK_PDMA_SCHED_NONE,
	RALINK_PDMA_SCHED_WRR,
	RALINK_PDMA_SCHED_SHAPER,
};

struct ralink_cdm_regs {
	u32 csg_cfg;
	u32 sch_cfg;
};

struct ralink_gdma_regs {
	u32 fwd_cfg;
	u32 sch_cfg;
	u32 shpr_cfg;
};

struct ralink_sdm_regs {
	u32 con;
	u32 rring;
	u32 tring;
};

struct ralink_fe_soc_data {
	const char			*name;
	const struct ralink_fe_reg_map	*reg_map;
	u32			pdma_bt_size;

	const struct ralink_pdma_sched_regs	*pdma_sched_regs;
	enum ralink_pdma_sched_type	pdma_sched;

	const struct ralink_cdm_regs *cdm_regs;
	const struct ralink_gdma_regs *gdma1_regs;
	const struct ralink_gdma_regs *gdma2_regs;
	const struct ralink_sdm_regs *sdm_regs;

	u8			txqs;
	u8			rxqs;

	bool			dsa_use_oob;
	u32			tx4_port;

	u32			rx_csum_ctrl;
	u32			rx_csum_ctrl_set;
	u32			rx_csum_ctrl_clear;
	u32			rx_csum_valid;
	u32			rx_csum_clear;

	u32			mac_adr_l;
	u32			mac_adr_h;

	enum ra_ppe_version	ppe;
	u32			foe_entries;
};

struct ralink_fe_tx_ring {
	struct ralink_fe_tx_desc	*desc;
	dma_addr_t			desc_dma;

	u16				cpu_idx;
	u16				clean_idx;

	struct sk_buff			*skb[RALINK_FE_TX_RING_SIZE];
	u8				map[RALINK_FE_TX_RING_SIZE];

	struct u64_stats_sync		syncp;
	u64				packets;
	u64				bytes;
	u64				errors;
	u64				dropped;

	u32				ring_full;
};

/* RX buffer (full page) */
struct ralink_fe_rx_buf {
	struct page			*page;
	dma_addr_t			dma;
};

struct ralink_fe_rx_ring {
	struct ralink_fe_rx_desc	*desc;
	dma_addr_t			desc_dma;

	u16				cpu_idx;

	struct page_pool		*pp;
	struct ralink_fe_rx_buf		buf[RALINK_FE_RX_RING_SIZE];

	struct u64_stats_sync		syncp;
	u64				packets;
	u64				bytes;
	u64				dropped;

	u32				refill_fail;
};


struct ralink_fe_priv {
	void __iomem			*base;
	void __iomem			*tx_cpu_idx[RALINK_FE_MAX_TXQ];
	void __iomem			*tx_dma_idx[RALINK_FE_MAX_TXQ];
	void __iomem			*rx_cpu_idx[RALINK_FE_MAX_RXQ];
	void __iomem			*int_status;
	void __iomem			*int_enable;

	struct device			*dev;
	struct net_device		*ndev;
	struct ra_ppe			*ppe;

	const struct ralink_fe_soc_data	*soc;

	struct clk			*clk;
	struct reset_control		*rst_fe;
	int				irq;
	spinlock_t			irq_lock;
	u32				irq_mask;

	u32				rx_irq_mask;
	u32				tx_irq_mask;
	u32				irq_mask_all;
	int				tx_poll_next;
	u8				txqs;
	u8				rxqs;
	bool				dsa_use_oob;

	struct mutex			mdio_lock;

	struct phylink			*phylink;
	struct phylink_config		phylink_config;

	struct ralink_fe_tx_ring	tx_ring[RALINK_FE_MAX_TXQ];
	struct ralink_fe_rx_ring	rx_ring[RALINK_FE_MAX_RXQ];
	struct napi_struct		tx_napi_all;
	struct napi_struct		rx_napi_all;
	struct metadata_dst		*dsa_meta[RALINK_MAX_DSA_PORTS];

	struct dim rx_dim;
	struct dim tx_dim;
	u32 dly_int_cfg;

	u64 rx_dim_events;
	u64 rx_dim_packets;
	u64 rx_dim_bytes;

	u64 tx_dim_events;
	u64 tx_dim_packets;
	u64 tx_dim_bytes;

	spinlock_t dim_lock;

	u32				msg_enable;
};

#endif /* __RALINK_FE_H */
