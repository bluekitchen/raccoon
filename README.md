# Raccoon BLE Sniffer

Raccoon is an open-source Bluetooth Low Energy Sniffer that consists of firmware for the Nordic nRF5x SoCs and a Python command line tool. It can follow connection request on all three advertisement channels by using three sniffer devices.

## Supported Devices

Raccoon was successfully tested on: 
 - Nordic [nRF51 DK (PCA10028)](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF51-DK/GetStarted) with nRF51422
 - Nordic [nRF52 DK (PCA10040)](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52-DK/Getting-Started) with nRF52832
 - Nordic [nRF52840 DK (PCA10056)](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK/GetStarted) with nRF52840
 - Nordic [nRF52840 Dongle (PCA10059)](https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF52840-Dongle) with nRF52840
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
- nRF52840 DK: `firmware/nrf/pca10056/armgcc`

Run `make flash`

### Nordic nRF52840 Dongle

The nRF52840 Dongle comes with a MBR and a Bootloader that supports firmware update via DFU mode. Here, we use the nRFConnect for Desktop tool:

- Download and install [nRFConnect For Desktop](https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Connect-for-desktop)
- Start nRF Connect and select Programmer
- Enter Bootloader mode by pressing RESET button - the red LED starts pulsing
- Select your device in the 'Select Device' pop-up in the upper left
- Add Hex file: `firmware/nrf/pca10059/armgcc/_build/nrf52840_xxaa.hex`
- Press 'Write'
- After successful write, the warning 'Nordic DFU Trigger Interface was not found' is shown. That's ok - Raccoon was flashed and is ready

### Adafruit Bluefruit LE Friend

There's no support to update via the BLE DFU. However, the LE Friend provides the regular SWD interface to upload the firmware with an JTAG/SWD programmer (e.g. a ST-Link or a SEGGER J-Link). Config files for OpenOCD are provided int the `firmware/nrf/blefriend32` folder.

## Setup

When running raccoon.py for the first time, it will create a template config file 'config.py' that lists all serial ports.
Please edit config.py and uncomment the lines that refer to Raccoon sniffer device.

## Usage

After configuration, start raccoon.py. It will list found devices and wait for a connection request. It will follow the first connection request. To follow only a specific device, you can set a BD_ADDR (MAC) filter with the --addr option.

During scanning, unique advertisements will be listed and a counter displays the total number of received devices.
After connect, the number of Connection Events and the number of non-empty data packets are shown.

Example run:

    $ pyclient/raccoon.py
    [+] Config: output trace.pcap (pcap)
    [-] Sniffer #0: port /dev/cu.usbmodem0006816168181, baud 1000000, rtscts 1, channel 37, version 9957-dirty
    [+]  1. 00:1a:7d:da:71:01         ADV_IND  -46 dBm, Name: 'LE Counter', UUID16: FF10
    [+]  2. 04:52:c7:f8:6e:57         ADV_IND  -97 dBm, UUID16: FEBE
    [+]  3. 5e:5e:fe:16:21:19    ADV_SCAN_IND -102 dBm, UUID16: FE9F
    [+]  4. 00:21:3c:ac:f7:38         ADV_IND  -56 dBm, UUID128: 200c9a66-0800-9e96-e211-818a400b0998
    [+]  5. 1f:3a:8b:7a:e6:b8 ADV_NONCONN_IND  -97 dBm,
    [+] CONNECTION 4a:dc:5a:84:78:fb -> 00:1a:7d:da:71:01 -- aa af9aaa9a, interval 30.00 ms, timeout_us 720.00 ms, latency 0
    [+] TERMINATE, disconnect
    [+] Restart sniffer on channel #37
    [+]

    Thanks for using raccoon


## Status and Outlook

### General
The current version allow to follow all Bluetooth 4.x connections. Optional supported features:
  - LE Data Length Extension (DLE).
  - Channel Selection Algorithm #2 (CSA #2) - *only partially working yet*
  
### Security
Encrypted connections are not supported yet. Sniffing encrypted connections requires the Long Term Key/Link Key to be present on the sniffer hardware. For LE Legacy Connections, the link key can be retrieved by brute force as there are only 1M possible Passkeys.

### LE 2M/Coded PHY
Logging connections with 2-MBit PHY or Coded PHY is not implemented yet.

### Throughput
The UART of the nRF5x devices only support a maximal baudrate of 1 mbps. This is not enough when the connection intervals are fully used. The new [nRF52840 Dongle (PCA10059)](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-Dongle/GetStarted) supports the USD Device mode, which should be fast enough to even capture LE 2M PHY at max speed.







