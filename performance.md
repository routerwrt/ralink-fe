# Performance

This document contains basic performance measurements for the
Ralink Frame Engine and PPE drivers.

The results are intended as functional and performance validation,
rather than comprehensive benchmarking.

## RT2880 / PPEv1

### Software flow offload

Using the Linux nftables flowtable software path, routed traffic reaches
approximately:

| Direction | Throughput |
|-----------|-----------:|
| Forward   | 88.7 Mbit/s |
| Reverse   | 81.6 Mbit/s |

CPU utilization is effectively saturated, with approximately 99% of CPU
time spent servicing software interrupts.

This provides a useful baseline for the software forwarding performance
of the RT2880 CPU.

### PPEv1 hardware flow offload

With PPEv1 hardware flow offload enabled:

| Test | Throughput |
|------|-----------:|
| Forward | 932 Mbit/s |
| Reverse | 930 Mbit/s |
| Bidirectional TX | 464 Mbit/s |
| Bidirectional RX | 463 Mbit/s |

Single-direction traffic therefore reaches Gigabit Ethernet line rate.

During simultaneous bidirectional traffic the two directions share
approximately 930 Mbit/s of aggregate throughput. This suggests a shared
bandwidth limitation somewhere in the RT2880 FE/PPE datapath.

### iperf3

Single-direction tests were performed with:

    iperf3 -c <server>
    iperf3 -c <server> -R

Bidirectional traffic was tested with:

    iperf3 -c <server> --bidir

Representative PPEv1 results:

    Forward:       ~932 Mbit/s
    Reverse:       ~930 Mbit/s
    Bidirectional: ~464 + ~463 Mbit/s

These results also provide a simple validation of the PPE offload path:
once a flow is bound into the PPE flow table, routed traffic bypasses
the normal CPU forwarding path and reaches hardware forwarding rates.
