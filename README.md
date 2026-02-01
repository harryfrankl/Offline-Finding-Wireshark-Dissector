# Offline Finding Wireshark Dissector

A Wireshark dissector plugin for decoding Apple's Offline Finding (OF) protocol, used by AirTags and Find My-enabled devices.

## Features

- Decodes OF advertisement packets (type `0x12`)
- Extracts battery level from status byte
- Displays 22-byte public key fragment
- Reconstructs full 28-byte EC P-224 public key (MAC address + fragment)
- Shows key hint and rotation counter
- Warns on non-standard payload lengths

## Installation

### Linux
```bash
mkdir -p ~/.local/lib/wireshark/plugins
cp offlineFinding.lua ~/.local/lib/wireshark/plugins/
```

### macOS
```bash
mkdir -p ~/.config/wireshark/plugins
cp offlineFinding.lua ~/.config/wireshark/plugins/
```

### Windows
```
Copy offlineFinding.lua to %APPDATA%\Wireshark\plugins\
```

Restart Wireshark after installation.

## Usage

1. Capture BLE traffic using an nRF Sniffer or similar hardware
2. Filter for Offline Finding packets: `offlineFinding`
3. Expand the "Apple Offline Finding Protocol" tree to view decoded fields

## Packet Structure

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Type (`0x12`) |
| 1 | 1 | Payload Length |
| 2 | 1 | Status Byte |
| 3-24 | 22 | Public Key Fragment |
| 25 | 1 | Key Hint |
| 26 | 1 | Rotation Counter |

### Status Byte

| Bits | Field |
|------|-------|
| 7-6 | Battery Level (0=Full, 1=Medium, 2=Low, 3=Critical) |
| 5-0 | Reserved |

### Public Key Reconstruction

The full 28-byte EC P-224 public key is reconstructed by concatenating:
- BLE advertising address (6 bytes)
- Public key fragment (22 bytes)

## Filter Examples

```
offlineFinding
offlineFinding.status.battery == 3
offlineFinding.counter > 10
```

## Requirements

- Wireshark 3.0+
- BLE sniffer hardware (e.g., nRF52840 with nRF Sniffer firmware)

## License

GPL-3.0-or-later

## Author

Harry Frankl
