# OSI-Capture

## Usage

#### Build
Compile osi-capture.c
```bash
podman compose up --build
```

#### Check Network Interfaces
List all available network interfaces to choose which one to capture from:
```bash
ip addr
```
Or
```bash
ifconfig
```

#### Run Capture
Start capturing traffic on the chosen interface:
```bash
./output/osi-capture <interface>
```

## Overview

**OSI-Capture: Data Structures Through the OSI Layers**

---

### 1. **Application Layer (Message)**

* Protocols: HTTP, FTP, DNS, SMTP, TLS
* Data unit: **Message**

```
+------------------------+
| Application Data       |  <- e.g., HTTP, DNS, FTP...
+------------------------+
```

---

### 2. **Transport Layer (Segment / Datagram)**

* Protocols: TCP (Segment) / UDP (Datagram)
* Data unit: **Segment / Datagram**

**TCP Header Example:**

```
+------------------------+
| Source Port            |
| Destination Port       |
| Sequence Number        |
| Acknowledgment Number  |
| Data Offset            |
| Flags (SYN, ACK, etc)  |
| Window Size            |
| Checksum               |
| Urgent Pointer         |
+------------------------+
| Application Data       |
+------------------------+
```

**UDP Header Example:**

```
+------------------------+
| Source Port            |
| Destination Port       |
| Length                 |
| Checksum               |
+------------------------+
| Application Data       |
+------------------------+
```

---

### 3. **Network Layer (Packet)**

* Protocols: IPv4, IPv6
* Data unit: **Packet**

**IPv4 Header Example:**

```
+------------------------+
| Version (4 bits)       |
| IHL (Header Length)    |
| Type of Service        |
| Total Length           |
| Identification         |
| Flags + Fragment Offset|
| TTL (Time To Live)     |
| Protocol (TCP/UDP)     |
| Header Checksum        |
| Source IP Address      |
| Destination IP Address |
+------------------------+
| Transport Header       |
+------------------------+
| Application Data       |
+------------------------+
```

---

### 4. **Data Link Layer (Frame)**

* Protocols: Ethernet, ARP
* Data unit: **Frame**

**Ethernet Frame Example:**

```
+------------------------+
| Destination MAC        |
| Source MAC             |
| EtherType / Length     |
+------------------------+
| IP Header              |
+------------------------+
| Transport Header       |
+------------------------+
| Application Data       |
+------------------------+
| Frame Check Sequence   |
+------------------------+
```

---

### 5. **Physical Layer (Bits)**

* Converts the frame into a **stream of bits** for transmission.

```
+--------------------------------------------------+
| 010110101001... (electrical/optical/radio)       |
+--------------------------------------------------+
```
