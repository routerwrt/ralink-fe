// SPDX-License-Identifier: GPL-2.0
/*
 * Ralink Frame Engine driver
 * Copyright (c) 2026 Richard van Schagen <richard@routerwrt.org>
 */

#include <generated/utsrelease.h>
#include <linux/clk.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/phylink.h>
#include <linux/reset.h>
#include <linux/string.h>
#include <linux/u64_stats_sync.h>

#include <net/dsa.h>
#include <net/dst_metadata.h>
#include <net/page_pool/helpers.h>

#include "ralink_fe.h"
#include "ra_ppe.h"
#include "ra_ppe_offload.h"
#include "ra_ppe_regs.h"

static u32 ralink_fe_r32(struct ralink_fe_priv *priv, u32 reg)
{
	return readl(priv->base + reg);
}

static void ralink_fe_w32(struct ralink_fe_priv *priv, u32 reg, u32 val)
{
	writel(val, priv->base + reg);
}

static int ralink_fe_mdio_wait(struct ralink_fe_priv *priv, u32 *val)
{
	return readl_poll_timeout(priv->base + FE_MDIO_ACCESS, *val,
				  !(*val & FE_MDIO_CMD_TRG),
				  1, RALINK_FE_MDIO_TIMEOUT_US);
}

static int ralink_fe_mdio_read(struct mii_bus *bus, int phy, int reg)
{
	struct ralink_fe_priv *priv = bus->priv;
	u32 cmd, val;
	int ret;

	mutex_lock(&priv->mdio_lock);

	ret = ralink_fe_mdio_wait(priv, &val);
	if (ret)
		goto out;

	cmd = FIELD_PREP(FE_MDIO_PHY_ADDR, phy) |
	      FIELD_PREP(FE_MDIO_REG_ADDR, reg);

	/*
	 * Preserve the known working RT2880 sequence:
	 * program command first, then assert CMD_TRG.
	 */
	ralink_fe_w32(priv, FE_MDIO_ACCESS, cmd);
	ralink_fe_w32(priv, FE_MDIO_ACCESS, cmd | FE_MDIO_CMD_TRG);

	ret = ralink_fe_mdio_wait(priv, &val);

out:
	mutex_unlock(&priv->mdio_lock);

	if (ret)
		return ret;

	return FIELD_GET(FE_MDIO_DATA, val);
}

static int ralink_fe_mdio_write(struct mii_bus *bus, int phy,
				int reg, u16 data)
{
	struct ralink_fe_priv *priv = bus->priv;
	u32 cmd, val;
	int ret;

	mutex_lock(&priv->mdio_lock);

	ret = ralink_fe_mdio_wait(priv, &val);
	if (ret)
		goto out;

	cmd = FE_MDIO_WRITE |
	      FIELD_PREP(FE_MDIO_PHY_ADDR, phy) |
	      FIELD_PREP(FE_MDIO_REG_ADDR, reg) |
	      FIELD_PREP(FE_MDIO_DATA, data);

	ralink_fe_w32(priv, FE_MDIO_ACCESS, cmd);
	ralink_fe_w32(priv, FE_MDIO_ACCESS, cmd | FE_MDIO_CMD_TRG);

	ret = ralink_fe_mdio_wait(priv, &val);

out:
	mutex_unlock(&priv->mdio_lock);

	return ret;
}

static int ralink_fe_mdio_register(struct ralink_fe_priv *priv)
{
	struct device_node *mdio_np;
	struct mii_bus *bus;
	int ret;

	mdio_np = of_get_available_child_by_name(priv->dev->of_node, "mdio");
	if (!mdio_np)
		mdio_np = of_get_available_child_by_name(priv->dev->of_node,
							 "mdio-bus");
	if (!mdio_np)
		return 0;

	bus = devm_mdiobus_alloc(priv->dev);
	if (!bus) {
		of_node_put(mdio_np);
		return -ENOMEM;
	}

	bus->name = "ralink-fe-mdio";
	bus->read = ralink_fe_mdio_read;
	bus->write = ralink_fe_mdio_write;
	bus->parent = priv->dev;
	bus->priv = priv;

	snprintf(bus->id, MII_BUS_ID_SIZE, "%s-mdio",
		 dev_name(priv->dev));

	ret = devm_of_mdiobus_register(priv->dev, bus, mdio_np);
	of_node_put(mdio_np);
	if (ret)
		return dev_err_probe(priv->dev, ret,
				     "failed to register FE MDIO bus\n");

	priv->mii_bus = bus;

	return 0;
}

static void
ralink_fe_mac_config(struct phylink_config *config, unsigned int mode,
		     const struct phylink_link_state *state)
{
	/* Interface mux/pin setup is SoC/board setup; nothing needed here yet. */
}

static void
ralink_fe_mac_link_down(struct phylink_config *config, unsigned int mode,
			phy_interface_t interface)
{
	/*
	 * The old RT2880 driver only changed software carrier state on
	 * link-down. Phylink owns carrier now, so nothing to do here.
	 */
}

static void
ralink_fe_mac_link_up(struct phylink_config *config,
		      struct phy_device *phydev, unsigned int mode,
		      phy_interface_t interface, int speed, int duplex,
		      bool tx_pause, bool rx_pause)
{
	struct ralink_fe_priv *priv =
		container_of(config, struct ralink_fe_priv, phylink_config);
	u32 mask, val;

	mask = FE_MDIO_CFG_GP1_AUTO_POLL |
	       FE_MDIO_CFG_GP1_FRC_EN |
	       FE_MDIO_CFG_GP1_SPEED |
	       FE_MDIO_CFG_GP1_DUPLEX |
	       FE_MDIO_CFG_GP1_FC_TX |
	       FE_MDIO_CFG_GP1_FC_RX;

	val = FE_MDIO_CFG_GP1_FRC_EN;

	switch (speed) {
	case SPEED_1000:
		val |= FIELD_PREP(FE_MDIO_CFG_GP1_SPEED,
				  FE_MDIO_CFG_GP1_SPEED_1000);
		break;
	case SPEED_100:
		val |= FIELD_PREP(FE_MDIO_CFG_GP1_SPEED,
				  FE_MDIO_CFG_GP1_SPEED_100);
		break;
	case SPEED_10:
		val |= FIELD_PREP(FE_MDIO_CFG_GP1_SPEED,
				  FE_MDIO_CFG_GP1_SPEED_10);
		break;
	default:
		return;
	}

	if (duplex == DUPLEX_FULL)
		val |= FE_MDIO_CFG_GP1_DUPLEX;

	if (tx_pause)
		val |= FE_MDIO_CFG_GP1_FC_TX;

	if (rx_pause)
		val |= FE_MDIO_CFG_GP1_FC_RX;

	/*
	 * Do not touch the low clock/skew bits yet. This preserves the
	 * boot/pin setup while phylink owns speed/duplex/pause.
	 *
	 * AUTO_POLL is deliberately cleared: Linux/phylink owns PHY state.
	 */
	ralink_fe_w32(priv, FE_MDIO_CFG,
		      (ralink_fe_r32(priv, FE_MDIO_CFG) & ~mask) | val);
}

static const struct phylink_mac_ops ralink_fe_phylink_mac_ops = {
	.mac_config	= ralink_fe_mac_config,
	.mac_link_down	= ralink_fe_mac_link_down,
	.mac_link_up	= ralink_fe_mac_link_up,
};

static void ralink_fe_irq_enable(struct ralink_fe_priv *priv, u32 mask)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->irq_lock, flags);
	priv->irq_mask |= mask;
	writel(priv->irq_mask, priv->int_enable);
	spin_unlock_irqrestore(&priv->irq_lock, flags);
}

static void ralink_fe_irq_disable(struct ralink_fe_priv *priv, u32 mask)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->irq_lock, flags);
	priv->irq_mask &= ~mask;
	writel(priv->irq_mask, priv->int_enable);
	spin_unlock_irqrestore(&priv->irq_lock, flags);
}

static int ralink_fe_dma_disable(struct ralink_fe_priv *priv)
{
	u32 val;
	const struct ralink_fe_reg_map *pdma = priv->soc->reg_map;

	val = ralink_fe_r32(priv, pdma->glo_cfg);
	val &= ~(RX_DMA_EN | TX_DMA_EN);
	ralink_fe_w32(priv, pdma->glo_cfg, val);

	return readl_poll_timeout(priv->base + pdma->glo_cfg, val,
				  !(val & (RX_DMA_BUSY | TX_DMA_BUSY)),
				  1000, 200000);
}

static void ralink_fe_dma_enable(struct ralink_fe_priv *priv)
{
	u32 val;
	const struct ralink_fe_reg_map *pdma = priv->soc->reg_map;

	ralink_fe_w32(priv, pdma->dly_int_cfg, 0);

//	val = RX_DMA_EN | TX_DMA_EN | TX_WB_DDONE | priv->soc->pdma_bt_size;
	val = RX_2B_OFFSET | RX_DMA_EN | TX_DMA_EN | TX_WB_DDONE | priv->soc->pdma_bt_size;

	ralink_fe_w32(priv, pdma->glo_cfg, val);
}

static bool ralink_uses_dsa(struct net_device *dev)
{
#if IS_ENABLED(CONFIG_NET_DSA)
	return netdev_uses_dsa(dev) &&
	       dev->dsa_ptr->tag_ops->proto == DSA_TAG_PROTO_RALINK;
#else
	return false;
#endif
}

static inline void ralink_fe_txq_error(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

	u64_stats_update_begin(&ring->syncp);
	ring->errors++;
	u64_stats_update_end(&ring->syncp);
}

static inline void ralink_fe_rxq_drop(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

	u64_stats_update_begin(&ring->syncp);
	ring->dropped++;
	u64_stats_update_end(&ring->syncp);
}

static inline void ralink_fe_txq_drop(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

	u64_stats_update_begin(&ring->syncp);
	ring->dropped++;
	u64_stats_update_end(&ring->syncp);
}

static void ralink_fe_hw_set_mac(struct ralink_fe_priv *priv, const u8 *mac)
{
	u32 hi, lo;

	hi = ((u32)mac[0] << 8) | mac[1];
	lo = ((u32)mac[2] << 24) | ((u32)mac[3] << 16) |
	     ((u32)mac[4] << 8) | mac[5];

	ralink_fe_w32(priv, priv->soc->mac_adr_h, hi);
	ralink_fe_w32(priv, priv->soc->mac_adr_l, lo);
}

static void ralink_fe_rx_release_ring(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	int i;

	for (i = 0; i < RALINK_FE_RX_RING_SIZE; i++) {
		struct ralink_fe_rx_buf *b = &ring->buf[i];

		if (!b->page)
			continue;

		page_pool_put_full_page(ring->pp, b->page, true);
		b->page = NULL;
		b->dma = 0;
	}

	ring->cpu_idx = 0;
}

static inline void ralink_fe_tx_unmap_desc(struct ralink_fe_priv *priv,
					   struct ralink_fe_tx_desc *d, u8 *map)
{
	u32 info2 = READ_ONCE(d->info2);
	u8 m = *map;

	if (TX2_DMA_SDL0_GET(info2)) {
		dma_addr_t dma = (dma_addr_t)(u32)d->info1;
		u16 len = TX2_DMA_SDL0_GET(info2);

		if (m & RALINK_FE_TX_MAP0_PAGE)
			dma_unmap_page(priv->dev, dma, len, DMA_TO_DEVICE);
		else
			dma_unmap_single(priv->dev, dma, len, DMA_TO_DEVICE);
	}

	if (TX2_DMA_SDL1_GET(info2)) {
		dma_addr_t dma = (dma_addr_t)(u32)d->info3;
		u16 len = TX2_DMA_SDL1_GET(info2);

		if (m & RALINK_FE_TX_MAP1_PAGE)
			dma_unmap_page(priv->dev, dma, len, DMA_TO_DEVICE);
		else
			dma_unmap_single(priv->dev, dma, len, DMA_TO_DEVICE);
	}

	*map = 0;
}

static void ralink_fe_tx_ring_init(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
	int i;

	for (i = 0; i < RALINK_FE_TX_RING_SIZE; i++) {
		struct ralink_fe_tx_desc *d = &ring->desc[i];

		ring->skb[i] = NULL;
		ring->map[i] = 0;

		d->info1 = 0;
		d->info3 = 0;
		d->info4 = 0;

		/* CPU owns descriptor initially */
		WRITE_ONCE(d->info2, TX2_DMA_DONE);
	}

	ring->cpu_idx = 0;
	ring->clean_idx = 0;
}

static void ralink_fe_program_rings(struct ralink_fe_priv *priv)
{
	int q;
	const struct ralink_fe_reg_map *pdma = priv->soc->reg_map;

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

		ralink_fe_tx_ring_init(priv, q);
		ralink_fe_w32(priv, pdma->tx_base_ptr[q], ring->desc_dma);
		ralink_fe_w32(priv, pdma->tx_max_cnt[q], RALINK_FE_TX_RING_SIZE);
		ralink_fe_w32(priv, pdma->rst_idx, tx_rst[q]);
		writel(0, priv->tx_cpu_idx[q]);
	}

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

		ring->cpu_idx = RALINK_FE_RX_RING_SIZE - 1;
		ralink_fe_w32(priv, pdma->rx_base_ptr[q], ring->desc_dma);
		ralink_fe_w32(priv, pdma->rx_max_cnt[q],
						RALINK_FE_RX_RING_SIZE);
		ralink_fe_w32(priv, pdma->rst_idx, rx_rst[q]);
		writel(ring->cpu_idx, priv->rx_cpu_idx[q]);
	}
}

static int ralink_fe_rx_ring_refill(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	int i;

	for (i = 0; i < RALINK_FE_RX_RING_SIZE; i++) {
		struct ralink_fe_rx_desc *d = &ring->desc[i];
		struct ralink_fe_rx_buf *b = &ring->buf[i];
		struct page *page;
		dma_addr_t dma;

		page = page_pool_dev_alloc_pages(ring->pp);
		if (!page)
			return -ENOMEM;

		dma = page_pool_get_dma_addr(page);

		b->page = page;
		b->dma = dma;

		d->info1 = (u32)(dma + RALINK_FE_RX_HEADROOM_BYTES);
		d->info3 = 0;
		d->info4 = 0;
		WRITE_ONCE(d->info2, RX2_DMA_LS0);
	}
	dma_wmb();

	ring->cpu_idx = RALINK_FE_RX_RING_SIZE - 1;

	return 0;
}

static void ralink_fe_napi_enable(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->txqs; q++)
		napi_enable(&priv->tx_ring[q].napi.napi);

	napi_enable(&priv->rx_napi_all);
}

static void ralink_fe_napi_disable(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->txqs; q++)
		napi_disable(&priv->tx_ring[q].napi.napi);

	napi_disable(&priv->rx_napi_all);
}

static void ralink_fe_tx_ring_reset(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
	int i;

	for (i = 0; i < RALINK_FE_TX_RING_SIZE; i++) {
		struct ralink_fe_tx_desc *d = &ring->desc[i];

		if (ring->skb[i]) {
			dev_kfree_skb_any(ring->skb[i]);
			ring->skb[i] = NULL;
		}

		ralink_fe_tx_unmap_desc(priv, d, &ring->map[i]);

		d->info1 = 0;
		d->info3 = 0;
		d->info4 = 0;
		WRITE_ONCE(d->info2, TX2_DMA_DONE);
	}

	ring->cpu_idx = 0;
	ring->clean_idx = 0;

	writel(0, priv->tx_cpu_idx[q]);
}

static void ralink_fe_rings_release(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->txqs; q++)
		ralink_fe_tx_ring_reset(priv, q);

	for (q = 0; q < priv->rxqs; q++)
		ralink_fe_rx_release_ring(priv, q);
}

static int ralink_fe_dsa_metadata_init(struct ralink_fe_priv *priv)
{
	int i;

	if (!priv->soc->dsa_use_oob)
		return 0;

	for (i = 0; i < ARRAY_SIZE(priv->dsa_meta); i++) {
		struct metadata_dst *md_dst;

		md_dst = metadata_dst_alloc(0, METADATA_HW_PORT_MUX,
					    GFP_KERNEL);
		if (!md_dst)
			goto err_free;

		md_dst->u.port_info.port_id = i;
		priv->dsa_meta[i] = md_dst;
	}

	return 0;

err_free:
	while (--i >= 0) {
		metadata_dst_free(priv->dsa_meta[i]);
		priv->dsa_meta[i] = NULL;
	}

	return -ENOMEM;
}

static void ralink_fe_dsa_metadata_cleanup(struct ralink_fe_priv *priv)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(priv->dsa_meta); i++) {
		if (!priv->dsa_meta[i])
			continue;

		metadata_dst_free(priv->dsa_meta[i]);
		priv->dsa_meta[i] = NULL;
	}
}

static int
ralink_fe_tx_poll_q(struct ralink_fe_priv *priv, int q, int budget)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
	struct net_device *ndev = priv->ndev;
	struct netdev_queue *txq = netdev_get_tx_queue(ndev, q);
	u16 clean = ring->clean_idx & RALINK_FE_TX_RING_MASK;
	u16 dtx;
	int pkts = 0;
	u32 bytes = 0;

	dtx = (readl(priv->tx_dma_idx[q]) & 0x0fff) & RALINK_FE_TX_RING_MASK;
	dma_rmb();

	while (clean != dtx && pkts < budget) {
		struct ralink_fe_tx_desc *d = &ring->desc[clean];
		struct sk_buff *skb;
		u32 info2 = READ_ONCE(d->info2);
		bool done_last = info2 & (TX2_DMA_LS0 | TX2_DMA_LS1);

		ralink_fe_tx_unmap_desc(priv, d, &ring->map[clean]);

		skb = ring->skb[clean];
		if (done_last && skb) {
			ring->skb[clean] = NULL;
			bytes += skb->len;
			pkts++;
			consume_skb(skb);
		}

		clean = (clean + 1) & RALINK_FE_TX_RING_MASK;
	}

	ring->clean_idx = clean;

	u64_stats_update_begin(&ring->syncp);
	ring->packets += pkts;
	ring->bytes += bytes;
	u64_stats_update_end(&ring->syncp);

	netdev_tx_completed_queue(txq, pkts, bytes);

	if (netif_tx_queue_stopped(txq)) {
		u16 avail = (clean - ring->cpu_idx -
			     RALINK_FE_TX_STOP_RESERVE) & RALINK_FE_TX_RING_MASK;

		if (avail >= RALINK_FE_TX_WAKE_THRESH)
			netif_tx_wake_queue(txq);
	}

	if (pkts < budget) {
		if (napi_complete_done(&ring->napi.napi, pkts))
			ralink_fe_irq_enable(priv, priv->tx_irq[q]);
	}

	return pkts;
}

static void ralink_fe_tx_unwind_sg(struct ralink_fe_priv *priv,
				   struct ralink_fe_tx_ring *ring,
				   u16 first_desc, int needed_desc,
				   const u32 *info2)
{
	int i;

	for (i = 0; i < needed_desc; i++) {
		u16 didx = (first_desc + i) & RALINK_FE_TX_RING_MASK;
		struct ralink_fe_tx_desc *d = &ring->desc[didx];

		/*
		 * Reconstruct descriptor length fields so tx_unmap_desc()
		 * can unmap any segments successfully mapped before failure.
		 * Ownership stays with the CPU.
		 */
		WRITE_ONCE(d->info2, TX2_DMA_DONE | info2[i]);
		ralink_fe_tx_unmap_desc(priv, d, &ring->map[didx]);

		ring->skb[didx] = NULL;
		d->info1 = 0;
		d->info3 = 0;
		d->info4 = 0;
		WRITE_ONCE(d->info2, TX2_DMA_DONE);
	}
}

static netdev_tx_t
ralink_fe_tx_xmit_linear(struct ralink_fe_priv *priv,
			 struct ralink_fe_tx_ring *ring,
			 struct netdev_queue *txq,
			 struct sk_buff *skb, int q)
{
	u16 first_desc = ring->cpu_idx;
	u16 clean = ring->clean_idx;
	u16 avail;
	u16 new_cpu;
	struct ralink_fe_tx_desc *d = &ring->desc[first_desc];
	dma_addr_t dma;
	u16 len;
	u32 desc_info2;
	u32 txinfo = 0;
	int pn = (q & BIT(1)) ? 2 : 1;
	int qn = (q & BIT(0)) ? 3 : 2;
	int port = skb_get_queue_mapping(skb);

	avail = (clean - first_desc - RALINK_FE_TX_STOP_RESERVE) &
		RALINK_FE_TX_RING_MASK;
	if (unlikely(avail < 1)) {
		ring->ring_full++;
		netif_tx_stop_queue(txq);
		return NETDEV_TX_BUSY;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		txinfo = TX4_DMA_ICO | TX4_DMA_UCO | TX4_DMA_TCO;

	if (priv->soc->tx4_port == RA_TX4_PNQN)
		txinfo |= TX4_DMA_PN(pn) | TX4_DMA_QN(qn);
	if (priv->soc->tx4_port == RA_TX4_FP)
		txinfo |= TX4_DMA_FP(BIT(port));

	if (skb_put_padto(skb, ETH_ZLEN)) {
		ralink_fe_txq_drop(priv, q);
		return NETDEV_TX_OK;
	}

	len = skb_headlen(skb);

	dma = dma_map_single(priv->dev, skb->data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(priv->dev, dma)))
		goto err_drop;

	ring->map[first_desc] = 0;
	ring->skb[first_desc] = skb;

	desc_info2 = TX2_DMA_SDL0(len) | TX2_DMA_LS0;

	d->info1 = (u32)dma;
	d->info3 = 0;
	d->info4 = txinfo;

	dma_wmb();
	WRITE_ONCE(d->info2, desc_info2);

	new_cpu = (first_desc + 1) & RALINK_FE_TX_RING_MASK;
	ring->cpu_idx = new_cpu;

	netdev_tx_sent_queue(txq, skb->len);

	if (!netdev_xmit_more() || netif_xmit_stopped(txq))
		writel(new_cpu, priv->tx_cpu_idx[q]);

	return NETDEV_TX_OK;

err_drop:
	ralink_fe_txq_drop(priv, q);
	ralink_fe_txq_error(priv, q);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static netdev_tx_t
ralink_fe_tx_xmit_sg(struct ralink_fe_priv *priv,
		     struct ralink_fe_tx_ring *ring,
		     struct netdev_queue *txq,
		     struct sk_buff *skb, int q)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	u16 first_desc = ring->cpu_idx;
	u16 clean = ring->clean_idx;
	u16 avail;
	u16 new_cpu;
	u16 last_didx;
	u32 info2[DIV_ROUND_UP(MAX_SKB_FRAGS + 1, 2)];
	int nr_frags = shinfo->nr_frags;
	int segs = 1 + nr_frags;
	int needed_desc = (segs + 1) >> 1;
	int i, fidx;
	u32 txinfo = 0;
	int pn = (q & BIT(1)) ? 2 : 1;
	int qn = (q & BIT(0)) ? 3 : 2;
	int port = skb_get_queue_mapping(skb);

	/*
	 * PDMA supports scatter-gather TX. Each descriptor carries up to
	 * two DMA segments, so a packet may span multiple descriptors.
	 */
	avail = (clean - first_desc - RALINK_FE_TX_STOP_RESERVE) &
		RALINK_FE_TX_RING_MASK;
	if (unlikely(avail < needed_desc)) {
		ring->ring_full++;
		netif_tx_stop_queue(txq);
		return NETDEV_TX_BUSY;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		txinfo |= TX4_DMA_ICO | TX4_DMA_UCO | TX4_DMA_TCO;

	if (priv->soc->tx4_port == RA_TX4_PNQN)
		txinfo |= TX4_DMA_PN(pn) | TX4_DMA_QN(qn);
	if (priv->soc->tx4_port == RA_TX4_FP)
		txinfo |= TX4_DMA_FP(BIT(port));

	if (skb_put_padto(skb, ETH_ZLEN)) {
		ralink_fe_txq_drop(priv, q);
		return NETDEV_TX_OK;
	}

	for (i = 0; i < needed_desc; i++) {
		u16 didx = (first_desc + i) & RALINK_FE_TX_RING_MASK;

		ring->map[didx] = 0;
		ring->skb[didx] = NULL;
		info2[i] = 0;
	}

	/* Head goes in slot0 of the first descriptor. */
	{
		struct ralink_fe_tx_desc *d = &ring->desc[first_desc];
		dma_addr_t dma;
		u16 len = skb_headlen(skb);

		dma = dma_map_single(priv->dev, skb->data, len, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(priv->dev, dma)))
			goto err_drop;

		d->info1 = (u32)dma;
		d->info3 = 0;
		d->info4 = txinfo;
		info2[0] = TX2_DMA_SDL0(len);
	}

	last_didx = first_desc;

	for (fidx = 0; fidx < nr_frags; fidx++) {
		skb_frag_t *f = &shinfo->frags[fidx];
		int seg = fidx + 1;
		int didx_off = seg >> 1;
		bool last = (fidx == nr_frags - 1);
		u16 didx = (first_desc + didx_off) & RALINK_FE_TX_RING_MASK;
		struct ralink_fe_tx_desc *d = &ring->desc[didx];
		dma_addr_t dma;
		u16 len = skb_frag_size(f);

		dma = skb_frag_dma_map(priv->dev, f, 0, len, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(priv->dev, dma)))
			goto err_unwind_sg;

		if (seg & 1) {
			ring->map[didx] |= RALINK_FE_TX_MAP1_PAGE;
			d->info3 = (u32)dma;
			info2[didx_off] |= TX2_DMA_SDL1(len);
			if (last)
				info2[didx_off] |= TX2_DMA_LS1;
		} else {
			ring->map[didx] |= RALINK_FE_TX_MAP0_PAGE;
			d->info1 = (u32)dma;
			info2[didx_off] |= TX2_DMA_SDL0(len);
			if (last)
				info2[didx_off] |= TX2_DMA_LS0;
		}
		d->info4 = txinfo;

		if (last)
			last_didx = didx;
	}

	/* Completion frees skb from the last descriptor only. */
	ring->skb[last_didx] = skb;
	dma_wmb();

	for (i = 0; i < needed_desc; i++) {
		u16 didx = (first_desc + i) & RALINK_FE_TX_RING_MASK;

		WRITE_ONCE(ring->desc[didx].info2, info2[i]);
	}

	new_cpu = (first_desc + needed_desc) & RALINK_FE_TX_RING_MASK;
	ring->cpu_idx = new_cpu;

	netdev_tx_sent_queue(txq, skb->len);

	if (!netdev_xmit_more() || netif_xmit_stopped(txq))
		writel(new_cpu, priv->tx_cpu_idx[q]);

	return NETDEV_TX_OK;

err_unwind_sg:
	ralink_fe_tx_unwind_sg(priv, ring, first_desc, needed_desc, info2);
	ralink_fe_txq_drop(priv, q);
	ralink_fe_txq_error(priv, q);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;

err_drop:
	ralink_fe_txq_drop(priv, q);
	ralink_fe_txq_error(priv, q);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static netdev_tx_t ralink_fe_start_xmit(struct sk_buff *skb,
					struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	struct ralink_fe_tx_ring *ring;
	struct netdev_queue *txq;
	int q;

	q = (skb_get_queue_mapping(skb) & 0x3);

	if (unlikely(q >= priv->txqs))
		q = 0;

	ring = &priv->tx_ring[q];
	txq = netdev_get_tx_queue(ndev, q);

	if (likely(!skb_is_nonlinear(skb)))
		return ralink_fe_tx_xmit_linear(priv, ring, txq, skb, q);

	return ralink_fe_tx_xmit_sg(priv, ring, txq, skb, q);
}

/*
 * Preserve queue_mapping assigned by DSA for CPU-port traffic.
 * For non-DSA users, fall back to the normal core selection policy.
 */
static u16
ralink_fe_select_queue(struct net_device *ndev, struct sk_buff *skb,
				  struct net_device *sb_dev)
{
	if (likely(netdev_uses_dsa(ndev)))
		return skb_get_queue_mapping(skb);
	/* fallback to default behavior */
	return netdev_pick_tx(ndev, skb, sb_dev);
}

static int ralink_fe_open(struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	int q, err;

	/*
	 * Populate RX ownership before programming the hardware rings.
	 * Descriptor memory and page-pool objects themselves persist for
	 * the lifetime of the device.
	 */
	for (q = 0; q < priv->rxqs; q++) {
		err = ralink_fe_rx_ring_refill(priv, q);
		if (err)
			goto err_release_rings;
	}

	ralink_fe_program_rings(priv);

	priv->dsa_use_oob = priv->soc->dsa_use_oob &&
			    ralink_uses_dsa(ndev);

	/*
	 * Start with all FE interrupts masked. NAPI must be ready before
	 * DMA can begin producing completions.
	 */
	priv->irq_mask = 0;
	ralink_fe_napi_enable(priv);

	writel(0xffffffff, priv->int_status);

	/*
	 * Bring up the CPU datapath before enabling PPE. PPE misses and
	 * exception packets may be redirected to the CPU immediately once
	 * the engine is started.
	 */
	ralink_fe_dma_enable(priv);

	if (priv->ppe) {
		err = ra_ppe_start(priv->ppe);
		if (err)
			goto err_dma;
	}

	ralink_fe_irq_enable(priv, priv->irq_mask_all);

	if (priv->phylink)
		phylink_start(priv->phylink);
	else
		netif_carrier_on(ndev);

	netif_tx_start_all_queues(ndev);

	return 0;

err_dma:
	/*
	 * Interrupts are still masked here, but DMA may already own RX
	 * descriptors. Stop it before disabling NAPI or releasing buffers.
	 */
	if (ralink_fe_dma_disable(priv))
		netdev_warn(ndev, "DMA did not stop cleanly after open failure\n");

	ralink_fe_napi_disable(priv);

err_release_rings:
	/*
	 * No TX packet can have been queued yet because the netdev TX
	 * queues are started only after successful initialization.
	 */
	ralink_fe_rings_release(priv);

	return err;
}

static int ralink_fe_stop(struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);

	/*
	 * Stop link state changes and prevent new packets from entering the
	 * TX path before quiescing the hardware.
	 */
	if (priv->phylink)
		phylink_stop(priv->phylink);
	else
		netif_carrier_off(ndev);

	/*
	 * Unlike netif_tx_stop_all_queues(), netif_tx_disable() also
	 * synchronizes against transmit paths currently executing on other
	 * CPUs.
	 */
	netif_tx_disable(ndev);

	/*
	 * Prevent new interrupt-driven work, then wait for any interrupt
	 * handler already in progress.
	 */
	ralink_fe_irq_disable(priv, priv->irq_mask_all);
	synchronize_irq(priv->irq);

	/*
	 * IRQ and NAPI control CPU processing only; they do not stop PDMA
	 * from accessing descriptors. Stop DMA before releasing ownership
	 * of any descriptor-backed resources.
	 */
	if (ralink_fe_dma_disable(priv))
		netdev_warn(ndev, "DMA did not stop cleanly\n");

	/*
	 * DMA is now quiesced. Wait for any NAPI poll which was already
	 * running to leave the RX/TX paths.
	 */
	ralink_fe_napi_disable(priv);

	/*
	 * RX can no longer enter ra_ppe_offload_check(), so PPE software
	 * state may now be reset safely.
	 */
	if (priv->ppe)
		ra_ppe_stop(priv->ppe);

	/*
	 * Hardware and software users are both quiesced. Return all packet
	 * ownership while retaining descriptor allocations and page pools
	 * for the next open.
	 */
	ralink_fe_rings_release(priv);

	priv->dsa_use_oob = false;

	return 0;
}

static int ralink_fe_set_mac_addr(struct net_device *ndev, void *p)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	int ret;

	ret = eth_mac_addr(ndev, p);
	if (ret)
		return ret;

	ralink_fe_hw_set_mac(priv, ndev->dev_addr);

	return 0;
}

static void ralink_fe_get_stats64(struct net_device *ndev,
				  struct rtnl_link_stats64 *stats)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	unsigned int start;
	int q;

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
		u64 packets, bytes, dropped;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			packets = ring->packets;
			bytes   = ring->bytes;
			dropped = ring->dropped;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		stats->rx_packets += packets;
		stats->rx_bytes   += bytes;
		stats->rx_dropped += dropped;
	}

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
		u64 packets, bytes, dropped, errors;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			packets = ring->packets;
			bytes   = ring->bytes;
			dropped = ring->dropped;
			errors  = ring->errors;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		stats->tx_packets += packets;
		stats->tx_bytes   += bytes;
		stats->tx_dropped += dropped;
		stats->tx_errors  += errors;
	}
}

static int ralink_fe_setup_tc(struct net_device *dev,
			      enum tc_setup_type type, void *type_data)
{
	struct ralink_fe_priv *priv = netdev_priv(dev);

	if (!priv->ppe)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_BLOCK:
	case TC_SETUP_FT:
		return ra_ppe_setup_tc_block(priv->ppe, dev, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static const struct net_device_ops ralink_fe_netdev_ops = {
	.ndo_open		= ralink_fe_open,
	.ndo_stop		= ralink_fe_stop,
	.ndo_start_xmit		= ralink_fe_start_xmit,
	.ndo_select_queue	= ralink_fe_select_queue,
	.ndo_set_mac_address	= ralink_fe_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_get_stats64	= ralink_fe_get_stats64,
	.ndo_setup_tc		= ralink_fe_setup_tc,
};

static inline int
ralink_fe_rx_consume_one(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	const struct ralink_fe_soc_data *soc = priv->soc;
	u16 cpu = (ring->cpu_idx + 1) & RALINK_FE_RX_RING_MASK;
	struct ralink_fe_rx_desc *d = &ring->desc[cpu];
	struct ralink_fe_rx_buf *b = &ring->buf[cpu];
	struct sk_buff *skb;
	struct page *page;
	dma_addr_t dma;
	u32 rxinfo2, rxinfo4, len;
	int ret = 0;

	rxinfo2 = READ_ONCE(d->info2);
	if (!(rxinfo2 & RX2_DMA_DONE))
		return -1;

	dma_rmb();
	rxinfo4 = READ_ONCE(d->info4);
	len = RX2_DMA_SDL0_GET(rxinfo2);

	page = page_pool_dev_alloc_pages(ring->pp);
	if (unlikely(!page)) {
		ring->refill_fail++;
		ralink_fe_rxq_drop(priv, q);

		page = b->page;
		dma = b->dma;
		goto rx_rearm;
	}

	dma = page_pool_get_dma_addr(page);

	dma_sync_single_for_cpu(priv->dev,
				b->dma + RALINK_FE_RX_HEADROOM_BYTES,
				len, DMA_FROM_DEVICE);

	skb = napi_build_skb(page_address(b->page), PAGE_SIZE);
	if (unlikely(!skb)) {
		ralink_fe_rxq_drop(priv, q);
		page_pool_put_full_page(ring->pp, b->page, true);
		goto rx_rearm;
	}

	skb_mark_for_recycle(skb);
	skb_reserve(skb, RALINK_FE_RX_HEADROOM_BYTES);
	skb_put(skb, len);

	if ((rxinfo4 & soc->rx_csum_valid) == soc->rx_csum_valid &&
	    !(rxinfo4 & soc->rx_csum_clear))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	else
		skb_checksum_none_assert(skb);

	skb->protocol = eth_type_trans(skb, priv->ndev);

	if (priv->dsa_use_oob) {
		unsigned int port = MT7620_DMA_SP_GET(rxinfo4);

		if (port < ARRAY_SIZE(priv->dsa_meta) && priv->dsa_meta[port])
			skb_dst_set_noref(skb, &priv->dsa_meta[port]->dst);
	}

	if ((soc->ppe == RA_PPE_V1) && (rxinfo4 & RX4_DMA_AIS)) {
		u8 reason = RX4_DMA_AI_GET(rxinfo4);
		u16 foe = RX4_DMA_FOE_GET(rxinfo4);

		if (reason == RA_PPE_REASON_HIT_UNBIND_RATE_REACH) {
			if (ra_ppe_offload_check(priv->ppe, foe, false)) {
				dev_kfree_skb_any(skb);
				goto rx_rearm;
			}
		} else if (reason == RA_PPE_REASON_HIT_BIND_KEEPALIVE) {
			ra_ppe_offload_check(priv->ppe, foe, true);
			dev_kfree_skb_any(skb);
			goto rx_rearm;
		}
	}

	skb_record_rx_queue(skb, q);
	napi_gro_receive(&priv->rx_napi_all, skb);

	ret = len;

rx_rearm:
	b->page = page;
	b->dma = dma;

	d->info1 = (u32)(dma + RALINK_FE_RX_HEADROOM_BYTES);
	d->info3 = 0;
	d->info4 = 0;
	WRITE_ONCE(d->info2, RX2_DMA_LS0);

	ring->cpu_idx = cpu;

	return ret;
}

static int ralink_fe_rx_poll_1q(struct napi_struct *napi, int budget)
{
	struct ralink_fe_priv *priv =
		container_of(napi, struct ralink_fe_priv, rx_napi_all);
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[0];
	u32 rx_pkts = 0;
	u32 rx_bytes = 0;
	int work_done = 0;

	while (work_done < budget) {
		int bytes;

		bytes = ralink_fe_rx_consume_one(priv, 0);
		if (bytes < 0)
			break;
		work_done++;
		if (bytes) {
			rx_pkts++;
			rx_bytes += bytes;
		}
	}

	if (work_done) {
		if (rx_pkts) {
			u64_stats_update_begin(&ring->syncp);
			ring->packets += rx_pkts;
			ring->bytes += rx_bytes;
			u64_stats_update_end(&ring->syncp);
		}

		dma_wmb();
		writel(ring->cpu_idx, priv->rx_cpu_idx[0]);
	}

	if (work_done < budget) {
		if (napi_complete_done(napi, work_done))
			ralink_fe_irq_enable(priv, priv->rx_irq_mask);
	}

	return work_done;
}

static int ralink_fe_rx_poll_2q(struct napi_struct *napi, int budget)
{
	struct ralink_fe_priv *priv =
		container_of(napi, struct ralink_fe_priv, rx_napi_all);
	struct ralink_fe_rx_ring *ring0 = &priv->rx_ring[0];
	struct ralink_fe_rx_ring *ring1 = &priv->rx_ring[1];
	u32 rx_pkts0 = 0, rx_bytes0 = 0;
	u32 rx_pkts1 = 0, rx_bytes1 = 0;
	bool touched0 = false;
	bool touched1 = false;
	int work_done = 0;

	while (work_done < budget) {
		bool did_work = false;
		int bytes;

		bytes = ralink_fe_rx_consume_one(priv, 0);
		if (bytes >= 0) {
			work_done++;
			did_work = true;
			touched0 = true;

			if (bytes) {
				rx_pkts0++;
				rx_bytes0 += bytes;
			}
		}

		if (work_done >= budget)
			break;

		bytes = ralink_fe_rx_consume_one(priv, 1);
		if (bytes >= 0) {
			work_done++;
			did_work = true;
			touched1 = true;

			if (bytes) {
				rx_pkts1++;
				rx_bytes1 += bytes;
			}
		}

		if (!did_work)
			break;
	}

	if (rx_pkts0) {
		u64_stats_update_begin(&ring0->syncp);
		ring0->packets += rx_pkts0;
		ring0->bytes += rx_bytes0;
		u64_stats_update_end(&ring0->syncp);
	}

	if (rx_pkts1) {
		u64_stats_update_begin(&ring1->syncp);
		ring1->packets += rx_pkts1;
		ring1->bytes += rx_bytes1;
		u64_stats_update_end(&ring1->syncp);
	}

	if (touched0 || touched1) {
		dma_wmb();

		if (touched0)
			writel(ring0->cpu_idx, priv->rx_cpu_idx[0]);

		if (touched1)
			writel(ring1->cpu_idx, priv->rx_cpu_idx[1]);
	}

	if (work_done < budget) {
		if (napi_complete_done(napi, work_done))
			ralink_fe_irq_enable(priv, priv->rx_irq_mask);
	}

	return work_done;
}

static int ralink_fe_tx_poll(struct napi_struct *napi, int budget)
{
	struct ralink_fe_qnapi *qn =
		container_of(napi, struct ralink_fe_qnapi, napi);

	return ralink_fe_tx_poll_q(qn->priv, qn->q, budget);
}

static irqreturn_t ralink_fe_irq(int irq, void *data)
{
	struct ralink_fe_priv *priv = data;
	u32 st = readl(priv->int_status) & READ_ONCE(priv->irq_mask);
	irqreturn_t ret = IRQ_NONE;
	int nq = max_t(int, priv->txqs, priv->rxqs);
	bool rx = false;
	int q;

	if (!st)
		return IRQ_NONE;

	ralink_fe_irq_disable(priv, st);
	writel(st, priv->int_status);

	for (q = 0; q < nq; q++) {
		if (q < priv->rxqs && (st & priv->rx_irq[q])) {
			rx = true;
			ret = IRQ_HANDLED;
		}

		if (q < priv->txqs && (st & priv->tx_irq[q])) {
			if (napi_schedule_prep(&priv->tx_ring[q].napi.napi))
				__napi_schedule(&priv->tx_ring[q].napi.napi);
			ret = IRQ_HANDLED;
		}
	}

	if (rx && napi_schedule_prep(&priv->rx_napi_all))
		__napi_schedule(&priv->rx_napi_all);

	return ret;
}

static void ralink_fe_get_drvinfo(struct net_device *ndev,
				  struct ethtool_drvinfo *info)
{
	strscpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strscpy(info->version, UTS_RELEASE, sizeof(info->version));
	strscpy(info->bus_info, dev_name(ndev->dev.parent),
		sizeof(info->bus_info));
}

static u32 ralink_fe_get_msglevel(struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);

	return priv->msg_enable;
}

static void ralink_fe_set_msglevel(struct net_device *ndev, u32 value)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);

	priv->msg_enable = value;
}

static void ralink_fe_get_ringparam(struct net_device *ndev,
				    struct ethtool_ringparam *ring,
				    struct kernel_ethtool_ringparam *kernel_ring,
				    struct netlink_ext_ack *extack)
{
	ring->rx_max_pending = RALINK_FE_RX_RING_SIZE;
	ring->tx_max_pending = RALINK_FE_TX_RING_SIZE;
	ring->rx_pending = RALINK_FE_RX_RING_SIZE;
	ring->tx_pending = RALINK_FE_TX_RING_SIZE;
}

static int ralink_fe_get_sset_count(struct net_device *ndev, int sset)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);

	if (sset != ETH_SS_STATS)
		return -EOPNOTSUPP;

	return priv->txqs * 5 + priv->rxqs * 4;
}

static void
ralink_fe_get_strings(struct net_device *ndev, u32 sset, u8 *data)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	unsigned int q;

	if (sset != ETH_SS_STATS)
		return;

	for (q = 0; q < priv->txqs; q++) {
		ethtool_sprintf(&data, "tx_queue_%u_packets", q);
		ethtool_sprintf(&data, "tx_queue_%u_bytes", q);
		ethtool_sprintf(&data, "tx_queue_%u_errors", q);
		ethtool_sprintf(&data, "tx_queue_%u_dropped", q);
		ethtool_sprintf(&data, "tx_queue_%u_ring_full", q);
	}

	for (q = 0; q < priv->rxqs; q++) {
		ethtool_sprintf(&data, "rx_queue_%u_packets", q);
		ethtool_sprintf(&data, "rx_queue_%u_bytes", q);
		ethtool_sprintf(&data, "rx_queue_%u_dropped", q);
		ethtool_sprintf(&data, "rx_queue_%u_refill_fail", q);
	}
}

static void ralink_fe_get_ethtool_stats(struct net_device *ndev,
					struct ethtool_stats *stats, u64 *data)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	unsigned int q, i = 0;

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
		unsigned int start;
		u64 pkts, bytes, errors, dropped;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			pkts = ring->packets;
			bytes = ring->bytes;
			errors = ring->errors;
			dropped = ring->dropped;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = errors;
		data[i++] = dropped;
		data[i++] = READ_ONCE(ring->ring_full);
	}

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
		unsigned int start;
		u64 pkts, bytes, dropped;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			pkts = ring->packets;
			bytes = ring->bytes;
			dropped = ring->dropped;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = dropped;
		data[i++] = READ_ONCE(ring->refill_fail);
	}
}

const struct ethtool_ops ralink_fe_ethtool_ops = {
	.get_drvinfo		= ralink_fe_get_drvinfo,
	.get_msglevel		= ralink_fe_get_msglevel,
	.set_msglevel		= ralink_fe_set_msglevel,
	.get_link		= ethtool_op_get_link,
	.get_ringparam		= ralink_fe_get_ringparam,
	.get_sset_count		= ralink_fe_get_sset_count,
	.get_strings		= ralink_fe_get_strings,
	.get_ethtool_stats	= ralink_fe_get_ethtool_stats,
};

static void ralink_fe_setup_netdev(struct net_device *ndev,
				   struct ralink_fe_priv *priv)
{
	struct device *dev = priv->dev;
	int err;

	err = of_get_ethdev_address(dev->of_node, ndev);
	if (err)
		eth_hw_addr_random(ndev);

	ralink_fe_hw_set_mac(priv, ndev->dev_addr);

	ndev->hw_features = NETIF_F_RXCSUM | NETIF_F_SG;

	if (priv->soc->has_tx_csum)
		ndev->hw_features |= NETIF_F_IP_CSUM;
	if (priv->soc->ppe != RA_PPE_NONE)
		ndev->hw_features |= NETIF_F_HW_TC;
	ndev->features = ndev->hw_features;
	ndev->vlan_features = ndev->hw_features;

	ndev->max_mtu = RALINK_FE_MAX_DMA_LEN - VLAN_ETH_HLEN;
	ndev->netdev_ops = &ralink_fe_netdev_ops;
	ndev->ethtool_ops = &ralink_fe_ethtool_ops;

	priv->msg_enable = NETIF_MSG_DRV |
			   NETIF_MSG_PROBE |
			   NETIF_MSG_IFUP;
}

static int ralink_fe_pp_create(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	struct page_pool_params pp = {
		.flags     = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.order     = 0,
		.pool_size = RALINK_FE_RX_RING_SIZE + (RALINK_FE_RX_RING_SIZE / 2),
		.nid       = NUMA_NO_NODE,
		.dev       = priv->dev,
		.dma_dir   = DMA_FROM_DEVICE,
		.max_len   = RALINK_FE_MAX_DMA_LEN,
		.offset    = RALINK_FE_RX_HEADROOM_BYTES,
	};

	ring->pp = page_pool_create(&pp);
	if (IS_ERR(ring->pp)) {
		int err = PTR_ERR(ring->pp);

		ring->pp = NULL;
		return err;
	}

	return 0;
}

static void ralink_fe_pp_destroy(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

	if (ring->pp) {
		page_pool_destroy(ring->pp);
		ring->pp = NULL;
	}
}

static int ralink_fe_init_page_pools(struct ralink_fe_priv *priv)
{
	int q, err;

	for (q = 0; q < priv->rxqs; q++) {
		err = ralink_fe_pp_create(priv, q);
		if (err)
			goto err;
	}

	return 0;

err:
	while (--q >= 0)
		ralink_fe_pp_destroy(priv, q);

	return err;
}

static void ralink_fe_cleanup_page_pools(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->rxqs; q++)
		ralink_fe_pp_destroy(priv, q);
}

static void ralink_fe_setup_sdm(struct ralink_fe_priv *priv)
{
//	u32 val;

//	val = SDM_TCI_81XX | FIELD_PREP(SDM_EXT_VLAN, ETH_P_8021Q);
//	val &= ~(SDM_UDPCS | SDM_TCPCS | SDM_IPCS);
//	ralink_fe_w32(priv, SDM_CON, val);

	/* priority tag 2 -> RX ring 1 */
	ralink_fe_w32(priv, SDM_RRING, BIT(2));
	/* no TX ring pause/FC */
	ralink_fe_w32(priv, SDM_TRING, 0);
}

static void ralink_fe_setup_tx_csum_ctrl(struct ralink_fe_priv *priv)
{
	u32 val;

	if (!priv->soc->cdm_csg_cfg)
		return;

	val = ralink_fe_r32(priv, priv->soc->cdm_csg_cfg);
	if (priv->soc->has_tx_csum)
		val |= CDM_ICS_GEN_EN | CDM_UCS_GEN_EN | CDM_TCS_GEN_EN;
	else
		val &= ~(CDM_ICS_GEN_EN | CDM_UCS_GEN_EN | CDM_TCS_GEN_EN);
	/* move "wan" to RX1 on MT7620 */
	if (priv->soc->rxqs > 1)
		val |= BIT(8);

	ralink_fe_w32(priv, priv->soc->cdm_csg_cfg, val);
}

static void ralink_fe_setup_rx_csum_ctrl(struct ralink_fe_priv *priv)
{
	u32 val;

	if (!priv->soc->rx_csum_ctrl)
		return;

	val = ralink_fe_r32(priv, priv->soc->rx_csum_ctrl);
	val |= priv->soc->rx_csum_ctrl_set;
	val &= ~priv->soc->rx_csum_ctrl_clear;
	ralink_fe_w32(priv, priv->soc->rx_csum_ctrl, val);
}

static int ralink_fe_alloc_desc(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

		ring->desc = dmam_alloc_coherent(priv->dev,
			sizeof(struct ralink_fe_tx_desc) *
			RALINK_FE_TX_RING_SIZE,
			&ring->desc_dma, GFP_KERNEL);
		if (!ring->desc)
			return -ENOMEM;
	}

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

		ring->desc = dmam_alloc_coherent(priv->dev,
			sizeof(struct ralink_fe_rx_desc) *
			RALINK_FE_RX_RING_SIZE,
			&ring->desc_dma, GFP_KERNEL);
		if (!ring->desc)
			return -ENOMEM;
	}

	return 0;
}

static int ralink_fe_init_queues(struct net_device *ndev,
				 struct ralink_fe_priv *priv)
{
	u32 tx_irq_mask = 0;
	int q;

	priv->rx_irq_mask = 0;

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

		priv->rx_irq_mask |= priv->rx_irq[q];
		u64_stats_init(&ring->syncp);
	}

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

		tx_irq_mask |= priv->tx_irq[q];
		u64_stats_init(&ring->syncp);
	}

	priv->irq_mask_all = priv->rx_irq_mask | tx_irq_mask;

	for (q = 0; q < priv->txqs; q++) {
		priv->tx_ring[q].napi.priv = priv;
		priv->tx_ring[q].napi.q = q;

		netif_napi_add_tx_weight(ndev,
			&priv->tx_ring[q].napi.napi,
			ralink_fe_tx_poll,
			RALINK_FE_NAPI_TX);
	}

	switch (priv->rxqs) {
	case 1:
		netif_napi_add_weight(ndev, &priv->rx_napi_all,
			     ralink_fe_rx_poll_1q,
			     RALINK_FE_NAPI_RX);
		break;
	case 2:
		netif_napi_add_weight(ndev, &priv->rx_napi_all,
			     ralink_fe_rx_poll_2q,
			     RALINK_FE_NAPI_RX);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void ralink_fe_napi_cleanup(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->txqs; q++)
		netif_napi_del(&priv->tx_ring[q].napi.napi);

	netif_napi_del(&priv->rx_napi_all);
}

static void ralink_fe_pdma_sched_init(struct ralink_fe_priv *priv)
{
	u32 val;
	const struct ralink_fe_reg_map *pdma = priv->soc->reg_map;

	return;

	switch (priv->soc->pdma_sched) {
	case RALINK_PDMA_SCHED_RT305X:
		/* one register: mode + encoded WRR weights */
		ralink_fe_w32(priv, pdma->sch_cfg,
				RA_SCH_MODE(RA_SCH_MODE_WRR) |
				RA_FE_SCH_EQUAL_WRR);
		ralink_fe_w32(priv, RT305X_GDMA1_SCH_CFG, RA_FE_SCH_EQUAL_WRR);
		ralink_fe_w32(priv, RT305X_GDMA2_SCH_CFG, RA_FE_SCH_EQUAL_WRR);
		ralink_fe_w32(priv, RT305X_CDMA_SCH_CFG,  RA_FE_SCH_EQUAL_WRR);

		val = ralink_fe_r32(priv, FE_GLO_CFG);
		val &= ~FE_US_CYC_CNT_MASK;
		val |= FE_US_CYC_CNT_SET(133);
		ralink_fe_w32(priv, FE_GLO_CFG, val);

		ralink_fe_w32(priv, RT305x_PDMA_FC_CFG, 0);
		break;
	case RALINK_PDMA_SCHED_RT5350:
		/* v2 layout: separate scheduler/WRR registers */
		ralink_fe_w32(priv, pdma->sch_cfg,
				RA_SCH_MODE(RA_SCH_MODE_WRR));

		ralink_fe_w32(priv, pdma->wrr_cfg,
				RA_FE_SCH_EQUAL_WRR);
			break;
	case RALINK_PDMA_SCHED_MT7620:

		break;
	}
}

static int ralink_fe_phylink_init(struct ralink_fe_priv *priv)
{
	struct device_node *port;
	phy_interface_t interface;
	u32 id;
	int ret;

	/*
	 * We support GMAC0 only for now. of_node_name_eq() ignores the
	 * unit address, so this finds port@0 without a generic port loop.
	 */
	port = of_get_available_child_by_name(priv->dev->of_node, "port");
	if (!port)
		return 0;

	ret = of_property_read_u32(port, "reg", &id);
	if (ret || id != 0) {
		of_node_put(port);
		return dev_err_probe(priv->dev, -EINVAL,
				     "only GMAC0 is supported\n");
	}

	ret = of_get_phy_mode(port, &interface);
	if (ret) {
		of_node_put(port);
		return dev_err_probe(priv->dev, ret,
				     "missing/invalid GMAC phy-mode\n");
	}

	priv->phylink_config.dev = &priv->ndev->dev;
	priv->phylink_config.type = PHYLINK_NETDEV;
	priv->phylink_config.mac_capabilities =
		MAC_SYM_PAUSE | MAC_ASYM_PAUSE |
		MAC_10 | MAC_100 | MAC_1000FD;

	__set_bit(PHY_INTERFACE_MODE_MII,
		  priv->phylink_config.supported_interfaces);
	__set_bit(PHY_INTERFACE_MODE_RMII,
		  priv->phylink_config.supported_interfaces);
	phy_interface_set_rgmii(priv->phylink_config.supported_interfaces);

	priv->phylink =
		phylink_create(&priv->phylink_config,
			       of_fwnode_handle(port),
			       interface,
			       &ralink_fe_phylink_mac_ops);
	if (IS_ERR(priv->phylink)) {
		ret = PTR_ERR(priv->phylink);
		priv->phylink = NULL;
		of_node_put(port);
		return dev_err_probe(priv->dev, ret,
				     "failed to create phylink\n");
	}

	ret = phylink_of_phy_connect(priv->phylink, port, 0);
	of_node_put(port);

	if (ret) {
		phylink_destroy(priv->phylink);
		priv->phylink = NULL;

		return dev_err_probe(priv->dev, ret,
				     "failed to connect phylink\n");
	}

	return 0;
}

static void ralink_fe_phylink_cleanup(struct ralink_fe_priv *priv)
{
	if (!priv->phylink)
		return;

	phylink_disconnect_phy(priv->phylink);
	phylink_destroy(priv->phylink);
	priv->phylink = NULL;
}

static int ralink_fe_hw_init(struct platform_device *pdev,
			     struct ralink_fe_priv *priv)
{
	struct device *dev = &pdev->dev;
	int err;

	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return dev_err_probe(dev, PTR_ERR(priv->base),
				     "failed to map registers");

	priv->irq = platform_get_irq(pdev, 0);
	if (priv->irq < 0)
		return dev_err_probe(dev, priv->irq, "missing IRQ");

	priv->clk = devm_clk_get_optional(dev, "fe");
	if (IS_ERR(priv->clk))
		return dev_err_probe(dev, PTR_ERR(priv->clk),
				     "failed to get fe clock");

	err = clk_prepare_enable(priv->clk);
	if (err)
		return dev_err_probe(dev, err,
				     "failed to enable fe clock");

	priv->rst_fe = devm_reset_control_get_optional_exclusive(dev, "fe");
	if (IS_ERR(priv->rst_fe)) {
		err = dev_err_probe(dev, PTR_ERR(priv->rst_fe),
				    "failed to get fe reset");
		goto err_clk;
	}

	if (priv->rst_fe) {
		err = reset_control_deassert(priv->rst_fe);
		if (err) {
			err = dev_err_probe(dev, err,
					    "failed to deassert fe reset");
			goto err_clk;
		}
	}

	ralink_fe_pdma_sched_init(priv);
	ralink_fe_setup_rx_csum_ctrl(priv);
	if (priv->soc->has_tx_csum)
		ralink_fe_setup_tx_csum_ctrl(priv);

	if (priv->soc->has_sdm)
		ralink_fe_setup_sdm(priv);

	return 0;

err_clk:
	clk_disable_unprepare(priv->clk);
	return err;
}

static void ralink_fe_hw_cleanup(struct ralink_fe_priv *priv)
{
	if (priv->rst_fe)
		reset_control_assert(priv->rst_fe);

	if (priv->clk)
		clk_disable_unprepare(priv->clk);
}

static int ralink_fe_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct ralink_fe_soc_data *soc;
	const struct ralink_fe_reg_map *pdma;
	struct net_device *ndev;
	struct ralink_fe_priv *priv;
	int err, q;

	soc = of_device_get_match_data(dev);
	if (!soc)
		return dev_err_probe(dev, -EINVAL, "missing match data\n");

	ndev = devm_alloc_etherdev_mqs(dev, sizeof(*priv),
				      soc->txqs, soc->rxqs);
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, dev);

	priv = netdev_priv(ndev);
	priv->dev = dev;
	priv->ndev = ndev;
	priv->soc = soc;
	priv->txqs = soc->txqs;
	priv->rxqs = soc->rxqs;

	spin_lock_init(&priv->irq_lock);
	mutex_init(&priv->mdio_lock);

	pdma = soc->reg_map;

	err = ralink_fe_hw_init(pdev, priv);
	if (err)
		return err;

	for (q = 0; q < priv->txqs; q++) {
		priv->tx_cpu_idx[q] = priv->base + pdma->tx_cpu_idx[q];
		priv->tx_dma_idx[q] = priv->base + pdma->tx_dma_idx[q];
		priv->tx_irq[q] = pdma->tx_irq[q];
	}

	for (q = 0; q < priv->rxqs; q++) {
		priv->rx_cpu_idx[q] = priv->base + pdma->rx_cpu_idx[q];
		priv->rx_irq[q] = pdma->rx_irq[q];
	}

	priv->int_status = priv->base + pdma->int_status;
	priv->int_enable = priv->base + pdma->int_enable;

	err = ralink_fe_alloc_desc(priv);
	if (err)
		goto err_hw;

	err = ralink_fe_init_queues(ndev, priv);
	if (err)
		goto err_hw;

	err = ralink_fe_init_page_pools(priv);
	if (err)
		goto err_napi;

	ralink_fe_setup_netdev(ndev, priv);

	err = ralink_fe_dsa_metadata_init(priv);
	if (err)
		goto err_pp;

	err = ralink_fe_mdio_register(priv);
	if (err)
		goto err_dsa_meta;

	err = ralink_fe_phylink_init(priv);
	if (err)
		goto err_dsa_meta;

	platform_set_drvdata(pdev, priv);

	/*
	 * Leave the datapath fully quiesced until ndo_open().
	 */
	ralink_fe_dma_disable(priv);
	writel(0xffffffff, priv->int_status);
	writel(0, priv->int_enable);
	priv->irq_mask = 0;

	err = devm_request_irq(dev, priv->irq, ralink_fe_irq, 0,
			       dev_name(dev), priv);
	if (err) {
		err = dev_err_probe(dev, err, "failed to request IRQ");
		goto err_phylink;
	}

	if (soc->ppe != RA_PPE_NONE) {
		priv->ppe = devm_kzalloc(dev, sizeof(*priv->ppe), GFP_KERNEL);
		if (!priv->ppe) {
			err = -ENOMEM;
			goto err_phylink;
		}

		err = ra_ppe_init(priv);
		if (err)
			goto err_phylink;
	}

	err = register_netdev(ndev);
	if (err)
		goto err_ppe;

	dev_info(dev, "Ralink FE: %u TXQ / %u RXQ\n",
		 priv->txqs, priv->rxqs);

	return 0;

err_ppe:
	if (priv->ppe)
		ra_ppe_deinit(priv->ppe);

err_phylink:
	ralink_fe_phylink_cleanup(priv);

err_dsa_meta:
	ralink_fe_dsa_metadata_cleanup(priv);

err_pp:
	ralink_fe_cleanup_page_pools(priv);

err_napi:
	ralink_fe_napi_cleanup(priv);

err_hw:
	ralink_fe_hw_cleanup(priv);

	return err;
}

static void ralink_fe_remove(struct platform_device *pdev)
{
	struct ralink_fe_priv *priv = platform_get_drvdata(pdev);

	/*
	 * If the interface is up, unregister_netdev() runs ndo_stop()
	 * first, which quiesces TX/RX, DMA, NAPI and the PPE hardware.
	 */
	unregister_netdev(priv->ndev);

	if (priv->ppe)
		ra_ppe_deinit(priv->ppe);

	ralink_fe_phylink_cleanup(priv);
	ralink_fe_dsa_metadata_cleanup(priv);
	ralink_fe_cleanup_page_pools(priv);
	ralink_fe_napi_cleanup(priv);
	ralink_fe_hw_cleanup(priv);
}

static const struct ralink_fe_reg_map pdma_v1_regs = {
	.tx_base_ptr = { 0x0110, 0x0120, 0x0140, 0x0150 },
	.tx_max_cnt  = { 0x0114, 0x0124, 0x0144, 0x0154 },
	.tx_cpu_idx  = { 0x0118, 0x0128, 0x0148, 0x0158 },
	.tx_dma_idx  = { 0x011c, 0x012c, 0x014c, 0x015c },

	.rx_base_ptr = { 0x0130 },
	.rx_max_cnt  = { 0x0134 },
	.rx_cpu_idx = { 0x0138 },
	.rx_dma_idx  = { 0x013c },

	.tx_irq = { BIT(8), BIT(9), BIT(10), BIT(11) },
	.rx_irq = { BIT(2) },

	.glo_cfg = 0x0100,
	.rst_idx = 0x0104,
	.dly_int_cfg = 0x010c,
	.int_status = 0x0010,
	.int_enable = 0x0014,
	.sch_cfg = 0x0108,
};

static const struct ralink_fe_reg_map pdma_v2_regs = {
	.tx_base_ptr = { 0x0800, 0x0810, 0x0820, 0x0830 },
	.tx_max_cnt  = { 0x0804, 0x0814, 0x0824, 0x0834 },
	.tx_cpu_idx  = { 0x0808, 0x0818, 0x0828, 0x0838 },
	.tx_dma_idx  = { 0x080c, 0x081c, 0x082c, 0x083c },

	.rx_base_ptr = { 0x0900, 0x0910 },
	.rx_max_cnt  = { 0x0904, 0x0914 },
	.rx_cpu_idx = { 0x0908, 0x0918 },
	.rx_dma_idx  = { 0x090c, 0x091c },

	.tx_irq = { BIT(0), BIT(1), BIT(2), BIT(3) },
	.rx_irq = { BIT(16), BIT(17) },

	.glo_cfg = 0x0a04,
	.rst_idx = 0x0a08,
	.dly_int_cfg = 0x0a0c,
	.int_status = 0x0a20,
	.int_enable = 0x0a28,
	.sch_cfg = 0x0a80,
	.wrr_cfg = 0x0a84,
};

static const struct ralink_fe_soc_data rt2880_data = {
	.name = "rt2880",
	.reg_map = &pdma_v1_regs,
	.pdma_sched = RALINK_PDMA_SCHED_RT305X,
	.txqs = 2,
	.rxqs = 1,

	.tx4_port = RA_TX4_PNQN,
	.dsa_use_oob = false,
	.has_tx_csum = true,
	.cdm_csg_cfg = 0x0080,
	/* RT305x GDM: enable checksum verification */
	.rx_csum_ctrl = 0x0020,
	.rx_csum_ctrl_set = GDM_ICS_EN | GDM_TCS_EN | GDM_UCS_EN,
	/* BC / MC /UC to CPU */
	.rx_csum_ctrl_clear = 0xffff,
	.rx_csum_valid = RX4_DMA_L4FVLD,
	.rx_csum_clear = RX4_DMA_L4F | RX4_DMA_IPF,

	.mac_adr_l = 0x002c,
	.mac_adr_h = 0x0030,

	.has_sdm = false,
	.pdma_bt_size = PDMA_BT_SIZE_8WORDS,
	.ppe = RA_PPE_V1,
	.foe_entries = 1024,
};

static const struct ralink_fe_soc_data rt305x_data = {
	.name = "rt305x",
	.reg_map = &pdma_v1_regs,
	.pdma_sched = RALINK_PDMA_SCHED_RT305X,
	.txqs = 4,
	.rxqs = 1,

	.tx4_port = RA_TX4_PNQN,
	.dsa_use_oob = false,
	.has_tx_csum = true,
	.cdm_csg_cfg = 0x0080,
	/* RT305x GDM: enable checksum verification */
	.rx_csum_ctrl = 0x0020,
	.rx_csum_ctrl_set = GDM_ICS_EN | GDM_TCS_EN | GDM_UCS_EN,
	/* BC / MC /UC to CPU */
	.rx_csum_ctrl_clear = 0xffff,
	.rx_csum_valid = RX4_DMA_L4FVLD,
	.rx_csum_clear = RX4_DMA_L4F | RX4_DMA_IPF,

	.mac_adr_l = 0x002c,
	.mac_adr_h = 0x0030,

	.has_sdm = false,
	.pdma_bt_size = PDMA_BT_SIZE_8WORDS,
	.ppe = RA_PPE_V1,
	.foe_entries = 4096,
};

static const struct ralink_fe_soc_data rt3883_data = {
	.name = "rt3883",
	.reg_map = &pdma_v1_regs,
	.pdma_sched = RALINK_PDMA_SCHED_RT305X,
	.txqs = 4,
	.rxqs = 1,

	.tx4_port = RA_TX4_PNQN,
	.dsa_use_oob = false,
	.has_tx_csum = true,
	.cdm_csg_cfg = 0x0080,
	/* RT305x GDM: enable checksum verification */
	.rx_csum_ctrl = 0x0020,
	.rx_csum_ctrl_set = GDM_ICS_EN | GDM_TCS_EN | GDM_UCS_EN,
	/* BC / MC /UC to CPU */
	.rx_csum_ctrl_clear = 0xffff,
	.rx_csum_valid = RX4_DMA_L4FVLD,
	.rx_csum_clear = RX4_DMA_L4F | RX4_DMA_IPF,

	.mac_adr_l = 0x002c,
	.mac_adr_h = 0x0030,

	.has_sdm = false,
	.pdma_bt_size = PDMA_BT_SIZE_8WORDS,
	.ppe = RA_PPE_V1,
	.foe_entries = 4096,
};

static const struct ralink_fe_soc_data rt5350_data = {
	.name = "rt5350",
	.reg_map = &pdma_v2_regs,
	.pdma_sched = RALINK_PDMA_SCHED_RT5350,
	.txqs = 4,
	.rxqs = 2,

	.tx4_port = RA_TX4_NONE,
	.dsa_use_oob = false,
	.has_tx_csum = false,

	/* RT5350 SDM:
	 * clear drop-on-checksum-error bits so errors are reported in RXD.
	 */
	.rx_csum_ctrl = 0x0c00,
	.rx_csum_ctrl_set = 0,
	.rx_csum_ctrl_clear = SDM_IPCS | SDM_TCPCS | SDM_UDPCS,
	.rx_csum_valid = RX4_DMA_L4FVLD,
	.rx_csum_clear = RX4_DMA_L4F | RX4_DMA_IPF,

	.mac_adr_l = 0x0c0c,
	.mac_adr_h = 0x0c10,

	.has_sdm = true,
	.pdma_bt_size = PDMA_BT_SIZE_8WORDS,
	.ppe = RA_PPE_NONE,
};

static const struct ralink_fe_soc_data mt7620_data = {
	.name = "mt7620",
	.reg_map = &pdma_v2_regs,
	.pdma_sched = RALINK_PDMA_SCHED_MT7620,
	.txqs = 4,
	.rxqs = 2,

	.tx4_port = RA_TX4_FP,
	.dsa_use_oob = true,
	.has_tx_csum = true,
	.cdm_csg_cfg = 0x0400,
	/* MT7620 GDM: enable checksum verification */
	.rx_csum_ctrl = 0x0600,
	.rx_csum_ctrl_set = GDM_ICS_EN | GDM_TCS_EN | GDM_UCS_EN,
	/* MT7620 GDM forward to CPU */
	.rx_csum_ctrl_clear = 0x7,

	.rx_csum_valid = MT7620_RX4_PKT_L4_VALID,
	.rx_csum_clear = MT7620_RX4_PKT_L4_ERR | MT7620_RX4_PKT_IP_ERR,

	.mac_adr_l = 0x13fe4,
	.mac_adr_h = 0x13ff8,

	.has_sdm = false,
	.pdma_bt_size = PDMA_BT_SIZE_16WORDS,

	.ppe = RA_PPE_NONE,
	.ppe = RA_PPE_V2,
	.foe_entries = 4096,
};

static const struct ralink_fe_soc_data mt76x8_data = {
	.name = "mt76x8",
	.reg_map = &pdma_v2_regs,
	.pdma_sched = RALINK_PDMA_SCHED_RT5350,
	.txqs = 4,
	.rxqs = 2,

	.tx4_port = RA_TX4_NONE,
	.dsa_use_oob = false,
	.has_tx_csum = false,
	/* MT76x8 SDM:
	 * clear drop-on-checksum-error bits so errors are reported in RXD.
	 */
	.rx_csum_ctrl = 0x0c00,
	.rx_csum_ctrl_set = 0,
	.rx_csum_ctrl_clear = SDM_IPCS | SDM_TCPCS | SDM_UDPCS,
	.rx_csum_valid = RX4_DMA_L4FVLD,
	.rx_csum_clear = RX4_DMA_L4F | RX4_DMA_IPF,

	.mac_adr_l = 0x0c0c,
	.mac_adr_h = 0x0c10,

	.has_sdm = true,
	.ppe = RA_PPE_NONE,
	.pdma_bt_size = PDMA_BT_SIZE_16WORDS,
};

static const struct of_device_id ralink_fe_of_match[] = {
	{ .compatible = "ralink,rt2880-fe", .data = &rt2880_data },
	{ .compatible = "ralink,rt305x-fe", .data = &rt305x_data },
	{ .compatible = "ralink,rt3883-fe", .data = &rt3883_data },
	{ .compatible = "ralink,rt5350-fe", .data = &rt5350_data },
	{ .compatible = "mediatek,mt7620-fe", .data = &mt7620_data },
	{ .compatible = "mediatek,mt76x8-fe", .data = &mt76x8_data },
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(of, ralink_fe_of_match);

static struct platform_driver ralink_fe_driver = {
	.probe = ralink_fe_probe,
	.remove = ralink_fe_remove,
	.driver = {
		.name = "ralink_fe",
		.of_match_table = ralink_fe_of_match,
	},
};
module_platform_driver(ralink_fe_driver);

MODULE_AUTHOR("Richard van Schagen <richard@routerwrt.org>");
MODULE_DESCRIPTION("NIC driver for the Ralink/MediaTek FE");
MODULE_LICENSE("GPL");
