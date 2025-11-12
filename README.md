# OSI-Capture

A simple network traffic capture tool.

## Build

```bash
podman compose up --build
```

## Check Network Interfaces
List all available network interfaces to choose which one to capture from:
```bash
ip addr
```
Or
```bash
ifconfig
```

## Run Capture
Start capturing traffic on the chosen interface:
```bash
./output/osi-capture <interface>
```
