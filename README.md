# 📡 Network Packet Sniffer

A **Linux-based network packet sniffer** written in **C** using **libpcap**.  
The tool captures live network traffic, parses **Ethernet, IPv4, TCP, UDP, and ICMP** packets, decodes **DNS traffic**, and displays **packet statistics** when the capture is terminated.

---

## ✨ Features

- Live packet capture using **libpcap**
- Ethernet frame parsing
- IPv4 packet parsing
- TCP / UDP / ICMP analysis
- TCP flags & payload length detection
- DNS query and response decoding
- Traffic statistics summary
- Graceful termination using **Ctrl+C**

> IPv6 and ARP packets are detected and counted as *Other* but not parsed.

---

## 🎯 Packet Filters

This sniffer supports **Berkeley Packet Filters (BPF)** to capture only specific traffic.  
Filters improve **performance**, **readability**, and **analysis accuracy**.

### Supported Filters

- **Protocol filters**
  - TCP packets
  - UDP packets
  - ICMP packets

- **Port-based filters**
  - Capture traffic on a specific port (e.g., DNS, HTTP)

- **IP-based filters**
  - Source IP filter
  - Destination IP filter

Filters are compiled using `pcap_compile()` and applied using `pcap_setfilter()`.

---

## ▶️ Filter Usage Examples

```bash
# Capture only TCP packets
sudo ./sniffer --tcp

# Capture only UDP packets
sudo ./sniffer --udp

# Capture only ICMP packets
sudo ./sniffer --icmp

# Show all available options
sudo ./sniffer --help
```
---
## ⚙️ Requirements

- Linux (Ubuntu recommended)
- GCC (C11 standard)
- libpcap

Install dependencies:

```bash
sudo apt install build-essential libpcap-dev
```
## 🛠 Build & Run
```bash
make
sudo ./sniffer
```
## 🚀 Future Enhancements

- IPv6 packet parsing
- TCP flow tracking
- Packet rate (packets/sec)
- HTTP traffic analysis

## For more info check
```bash
sudo ./sniffer --help
```
