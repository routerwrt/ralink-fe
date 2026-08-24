# Ralink FE

net: ethernet: ralink: add FE and PPE driver

Add a driver for the Ralink/MediaTek Frame Engine (FE) Ethernet
controller.

The FE provides a DMA-based packet engine used as the CPU port on
SoCs with an integrated Ethernet switch. The driver implements TX/RX
DMA rings, interrupt handling, NAPI support, and integration with
DSA-based switch drivers.

Features:
- Multi-queue TX/RX with NAPI
- Page pool backed RX path
- Scatter-gather TX support
- TX/RX checksum offload where supported
- Per-queue statistics and ethtool support
- DSA-aware queue selection

On SoCs with an integrated switch, link handling is provided by the
associated switch driver. The FE also supports phylink for SoCs and
board configurations where the Frame Engine is connected to an
external PHY.

Initial hardware flow offload support is provided for the Ralink PPEv1
found in the RT2880, RT305x and RT3883 SoCs. The PPE integrates with
DSA and handles the Ralink DSA tag when offloading flows.

Signed-off-by: Richard van Schagen <richard@routerwrt.org>
