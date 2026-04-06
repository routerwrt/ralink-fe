# Ralink-fe

net: ethernet: ralink: add FE driver

Add a driver for the Ralink/MediaTek Frame Engine (FE) Ethernet
controller.

The FE provides a DMA-based packet engine used as the CPU port
for SoCs with an integrated Ethernet switch (ESW). The driver
implements TX/RX DMA rings, interrupt handling, NAPI support,
and integration with DSA-based switch drivers.

Features:
- Multi-queue TX/RX with NAPI
- Page pool backed RX path
- Scatter-gather TX support
- Per-queue statistics and ethtool support
- DSA-aware queue selection

The FE does not provide a standalone MAC or PHY interface; link
handling is delegated to the associated switch (e.g. ralink esw).

Signed-off-by: Richard van Schagen <richard@routerwrt.org>
