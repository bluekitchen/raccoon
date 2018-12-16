# Raccoon BLE Sniffer

Raccoon is an open-source Bluetooth Low Energy Sniffer that consists of firmware for the Nordic nRF5x SoCs and a Python command line tool. It can follow connection request on all three advertisement channels by using three sniffer devices.

## Supported Devices

Raccoon was successfully tested on: 
 - Nordic [nRF51 DK (PCA10028)](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF51-DK/GetStarted) with nRF51422
 - Nordic [nRF52 DK (PCA10040)](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52-DK/Getting-Started) with nRF52832
 - Adafruit [Bluefruit LE Friend](https://www.adafruit.com/product/2267) with nRF51822

## Dependencies

The firmware requires the regular ARM-EABI-NONE toolchain.
The Python command line tool was develop on Python 3 and requires the [pySerial module](https://pythonhosted.org/pyserial/)
It requires the nRF5 SDK. If not installed locally, the build system can automatically download it into the project folder.

## Build

With the dependencies in place, run `make` in the main project folder. Make will download the nRF5 SDK if needed.

## Flash

Flashing depends on the used device.

### Nordic DKs

Go to the correct folder:
- nRF51 DK: `firmware/nrf/pca10028/armgcc`
- nRF52 DK: `firmware/nrf/pca10040/armgcc`

Run `make flash`

### Adafruit Bluefruit LE Friend

There's no support to update via the BLE DFU. However, the LE Friend provides the regular SWD interface to upload the firmwware with an JTAG/SWD programmer (e.g. a ST-Link or a SEGGER J-Link). Config files for OpenOCD are provided int the `firmware/nrf/blefriend32` folder.

## Setup

When running raccon.py for the first time, it will create a template config file 'config.py' that lists all serial ports.
Please edit config.py and uncomment the lines that refer to Raccoon sniffer device.

## Usage

After configuration, start raccoon.py. It will list found devices and wait for a connection request. It will follow the first connection request. To follow only a specific device, you can set a BD_ADDR (MAC) filter with the --addr option.

## Status and Outlook

### General
The current version allow to follow all Bluetooth 4.x connections including support for LE Data Length Extension. 

### Security
Encrypted connections are not supported yet. It would be possible to decrypt data on the fly if the stored link key is provided. For LE Legacy Connections, the link key could be retrieved by brute force as there are only 1M possible Passkeys.

### LE 2M/Coded PHY
Logging connections with 2-MBit PHY or Coded PHY is technically possible, but not implemented yet.

### Throughput
The UART of the nRF5x devices only support a maximal baudrate of 1 mbps. This is not enough when the connection intervals are fully used. The new [nRF52840 Dongle (PCA10059)](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-Dongle/GetStarted) supports the USD Device mode, which should be fast enough to even capture LE 2M PHY at max speed.







