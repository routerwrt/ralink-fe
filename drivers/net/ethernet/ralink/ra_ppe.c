// SPDX-License-Identifier: GPL-2.0

#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include "ralink_fe.h"
#include "ra_ppe.h"
#include "ra_ppe_offload.h"

int ra_ppe_start(struct ra_ppe *ppe)
{
	if (!ppe || !ppe->ops)
		return -EINVAL;

	if (!ppe->ops->start)
		return 0;

	return ppe->ops->start(ppe);
}

void ra_ppe_stop(struct ra_ppe *ppe)
{
	if (!ppe || !ppe->ops || !ppe->ops->stop)
		return;

	ppe->ops->stop(ppe);
}

int ra_ppe_setup_tc(struct ra_ppe *ppe, struct net_device *dev,
		    void *type_data)
{
	if (!ppe || !ppe->ops || !ppe->ops->offload)
		return -EOPNOTSUPP;

	return ra_ppe_setup_tc_block(ppe, dev, type_data);
}

bool ra_ppe_offload_check(struct ra_ppe *ppe, u16 index, bool keepalive)
{
	if (!ppe || !ppe->ops || !ppe->ops->offload ||
	    !ppe->ops->offload->check)
		return false;

	return ppe->ops->offload->check(ppe, index, keepalive);
}

int ra_ppe_init(struct ralink_fe_priv *priv)
{
	struct ra_ppe *ppe = priv->ppe;
	size_t size;
	int err;

	ppe->dev = priv->dev;
	ppe->fe = priv;
	ppe->base = priv->base;
	ppe->foe_entries = priv->soc->foe_entries;

	if (!ppe->ops || !ppe->ops->foe_entry_size)
		return -EINVAL;

	ppe->foe_entry_size = ppe->ops->foe_entry_size;

	spin_lock_init(&ppe->lock);

	/*
	 * Software flow state must exist before packets can ever be routed
	 * through PPE.
	 */
	err = ra_ppe_offload_init(ppe);
	if (err)
		return err;

	size = (size_t)ppe->foe_entries * ppe->foe_entry_size;

	ppe->foe_table = dma_alloc_coherent(ppe->dev, size,
					    &ppe->foe_phys,
					    GFP_KERNEL);
	if (!ppe->foe_table) {
		err = -ENOMEM;
		goto err_offload;
	}

	/*
	 * Generation-specific initialization is performed after the FOE
	 * table has been allocated, since the hardware may need its DMA
	 * address during initialization.
	 *
	 * PPE generations without persistent hardware initialization can
	 * leave this callback unset.
	 */
	if (ppe->ops->init) {
		err = ppe->ops->init(ppe);
		if (err)
			goto err_foe;
	}

	return 0;

err_foe:
	dma_free_coherent(ppe->dev, size,
			  ppe->foe_table, ppe->foe_phys);

	ppe->foe_table = NULL;
	ppe->foe_phys = 0;

err_offload:
	ra_ppe_offload_deinit(ppe);

	return err;
}

void ra_ppe_deinit(struct ra_ppe *ppe)
{
	size_t size;

	if (!ppe)
		return;

	/*
	 * The FE caller must ensure RX/NAPI has been quiesced before final
	 * destruction. An RX descriptor queued before ra_ppe_stop() may
	 * still carry a PPE reason and FOE index.
	 *
	 * start/stop are optional runtime datapath operations. PPE
	 * generations which remain active for the device lifetime leave
	 * these callbacks unset.
	 */
	ra_ppe_stop(ppe);

	/*
	 * Tear down generation-specific hardware state before destroying
	 * software flow state or releasing the FOE table.
	 */
	if (ppe->ops && ppe->ops->deinit)
		ppe->ops->deinit(ppe);

	ra_ppe_offload_deinit(ppe);

	if (!ppe->foe_table)
		return;

	size = (size_t)ppe->foe_entries * ppe->foe_entry_size;

	dma_free_coherent(ppe->dev, size,
			  ppe->foe_table, ppe->foe_phys);

	ppe->foe_table = NULL;
	ppe->foe_phys = 0;
}
