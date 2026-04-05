// SPDX-License-Identifier: GPL-2.0
/*
 * Ralink Frame Engine driver
 * Copyright (c) 2026 Richard van Schagen <richard@routerwrt.org>
 */

#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

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
