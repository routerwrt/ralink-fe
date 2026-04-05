// SPDX-License-Identifier: GPL-2.0
/*
 * Ralink Frame Engine driver
 * Copyright (c) 2026 Richard van Schagen <richard@routerwrt.org>
 */

#include <linux/clk.h>
#include <linux/etherdevice.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>

#include "ralink_fe.h"

static int ralink_fe_open(struct net_device *ndev)
{
	netif_start_queue(ndev);
	return 0;
}

static int ralink_fe_stop(struct net_device *ndev)
{
	netif_stop_queue(ndev);
	return 0;
}

static netdev_tx_t ralink_fe_start_xmit(struct sk_buff *skb,
					struct net_device *ndev)
{
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops ralink_fe_netdev_ops = {
	.ndo_open		= ralink_fe_open,
	.ndo_stop		= ralink_fe_stop,
	.ndo_start_xmit		= ralink_fe_start_xmit,
};

static void ralink_fe_setup_sdm(struct ralink_fe_priv *priv)
{
	u32 v;

	if (priv->sdm) {
		v = SDM_PDMA_FC | SDM_PORT_MAP | SDM_TCI_81XX |
		    FIELD_PREP(SDM_EXT_VLAN, 0x8100);
		v &= ~(SDM_UDPCS | SDM_TCPCS | SDM_IPCS);
		regmap_write(priv->sdm, SDM_CON, v);
	}
}

static int ralink_fe_hw_init(struct platform_device *pdev,
			     struct ralink_fe_priv *priv)
{
	struct device *dev = &pdev->dev;
	struct device_node *sdm_np;
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


	sdm_np = of_parse_phandle(dev->of_node, "ralink,sdm", 0);
	if (!sdm_np) {
		if (priv->soc->needs_sdm) {
			err = dev_err_probe(dev, -EINVAL,
				     "missing required ralink,sdm phandle");
			goto err_reset;
		}

		priv->sdm = NULL;
		return 0;
	} else {
		priv->sdm = syscon_node_to_regmap(sdm_np);
		of_node_put(sdm_np);

		if (IS_ERR(priv->sdm)) {
			err = dev_err_probe(dev, PTR_ERR(priv->sdm),
				    "failed to get SDM regmap");
			goto err_reset;
		}
	}

	ralink_fe_setup_sdm(priv);

	return 0;

err_reset:
	if (priv->rst_fe)
		reset_control_assert(priv->rst_fe);
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
	struct net_device *ndev;
	struct ralink_fe_priv *priv;
	int err;

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

	err = ralink_fe_hw_init(pdev, priv);
	if (err)
		return err;

	ndev->netdev_ops = &ralink_fe_netdev_ops;
	platform_set_drvdata(pdev, priv);

	err = register_netdev(ndev);
	if (err)
		return err;

	dev_info(dev, "Ralink FE: %u TXQ / %u RXQ\n", priv->txqs, priv->rxqs);

	return 0;
}

static void ralink_fe_remove(struct platform_device *pdev)
{
	struct ralink_fe_priv *priv = platform_get_drvdata(pdev);

	unregister_netdev(priv->ndev);
	ralink_fe_hw_cleanup(priv);
}

static const struct ralink_fe_soc_data rt5350_data = {
	.txqs = 4,
	.rxqs = 2,
	.needs_sdm = true,
};

static const struct ralink_fe_soc_data mt7628_data = {
	.txqs = 4,
	.rxqs = 2,
	.needs_sdm = true,
};

static const struct of_device_id ralink_fe_of_match[] = {
	{ .compatible = "ralink,rt5350-fe", .data = &rt5350_data },
	{ .compatible = "mediatek,mt7628-fe", .data = &mt7628_data },
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
MODULE_DESCRIPTION("NIC driver for the Ralink/MediaTek embedded frame engine");
MODULE_LICENSE("GPL");
