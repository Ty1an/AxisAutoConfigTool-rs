# AxisAutoConfig

> Automated setup and configuration tool for factory-new Axis network cameras built in pure
> Inspired by [AxisAutoConfig](https://github.com/devakalpa1/AxisAutoConfig/tree/main) - I wanted a version that was portable fast and 100% Rust


## Overview

AxisAutoConfig is a Rust-based GUI application that automates the initial setup and configuration of Axis network cameras. The tool provides a streamlined workflow for configuring multiple cameras simultaneously with DHCP server functionality, firmware upgrades, and network configuration.

## Features

- **DHCP Server Integration** - Built-in DHCP server for factory-new camera discovery
- **Automatic Camera Discovery** - Fast network scanning and Axis camera identification
- **Bulk Configuration** - Configure multiple cameras simultaneously
- **Firmware Management** - Automatic firmware upgrades
- **Network Configuration** - Static IP assignment with validation
- **CSV/Excel Export** - Export configuration results for inventory management
- **Real-time Progress** - Live console logs and progress tracking

## Requirements

- **Operating System**: Windows, macOS, or Linux
- **Administrator Privileges**: Required for DHCP server functionality
- **Network Access**: Direct network access to factory-new Axis cameras
- **Rust** (for building from source): 1.70+ with Cargo

## Installation


### Building from Source
```bash
git clone https://github.com/your-username/axis_config.git
cd axis_config
cargo build --release
```
## Acknowledgments

- Inspired by [AxisAutoConfig](https://github.com/devakalpa1/AxisAutoConfig/tree/main) By [devakalpa1](https://github.com/devakalpa1)
- Built with [egui](https://github.com/emilk/egui) for cross-platform GUI
- Uses [tokio](https://tokio.rs/) for async networking
- Integrates with Axis VAPIX API for camera communication