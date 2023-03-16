---
title: Technical notes for Smart Coffee Machine Prodigio/C70
author: Axelle Apvrille, Fortinet
date: March 2023
linkcolor: blue
urlcolor: blue
citecolor: gray
papersize: a4
---

# Technical notes for Smart Coffee Machine Prodigio/C70

*Disclaimer*
The material and information contained in this technical document is for general information purposes only. You should not rely upon the material or information on the document as a basis for making any business, legal or any other decisions.

*History*

- July 2020: main document release.
- March 2023: updates on eBay links, Mirage is still maintained, nicer print of BLE characteristics tables.

## Hardware

- [Service Manual](https://m.buyspares.co.uk/images/mediator/2752/c75%20service%20manual.pdf)
- [CitiZ teardown](https://www.ifixit.com/Teardown/Nespresso+CitiZ+Teardown/42890)
- [Similar?](https://fccid.io/MSIP-RRM-FL2-Prodigio)
- [B10 coffee maker](https://fccid.io/2AUF9)

### Buttons PCB

Circuit marked: `94V-0 E327373 HQD-K`

- 94V-0: circuits that have met the flammability test
- E327373 : [Q & D MULTILAYER PCB CO LTD](https://iq.ul.com/pwb/Trade.aspx)
- You can buy one online for 36 euros () [ebay](https://www.ebay.com/itm/183595989096)

Onboard, we notice a STM85003 K3T6C 9912N VG MYS 743
This circuit is used with many different names depending on the brand: Krups XN410T, Delonghi EN170, Magimix 11375, Turmix TX190, Nespresso D70...

We also see **BL600-SA-06** with [FCC-ID PI4BL600](https://fccid.io/PI4BL600) which is the Bluetooth Low Energy Module, manufactured by LAIRD Tech. Its [integration guide](https://fccid.io/PI4BL600/Users-Manual/User-Manual-1937726) [or here](https://www.mouser.fr/pdfdocs/Laird_Wireless_BL600_HIG_v1_0.pdf) shows a chip with GPIO, ADC, I2C and SPI. It is based on a ARM Cortex M0 with BLE radio.
In that case, the RF antenna is integrated to the BL600-SA chip. It is a ceramic antenna. It costs [13 euros at Farnell](https://ie.farnell.com/laird/bl600-sa/mod-bluetooth-lo-energy-internal/dp/2321469)
It contains a [Nordic nRF51822 chip](https://www.lairdconnect.com/wireless-modules/bluetooth-modules/bluetooth-42-and-40-modules/bl600-series)

### Flow Meter

Close to the lower chip, there is a QR code with: `46501-1-1.11-D-1609400629`
There is another circuit which is the Flow Meter. We can buy one online for 25 GBP [ebay](https://www.ebay.co.uk/itm/223597085470). 

## Bluetooth security modes

[O'Reilly book](https://www.oreilly.com/library/view/getting-started-with/9781491900550/ch04.html):
*"Insufficient Authentication"
Denotes that the link is not encrypted and that the server does not have a long-term key (LTK, first introduced in Security Keys) available to encrypt the link, or that the link is indeed encrypted, but the LTK used to perform the encryption procedure is not authenticated (generated with man-in-the-middle protection; see Authentication) while the permissions required authenticated encryption.*

[The solution is *pairing*](https://microchipdeveloper.com/wireless:ble-gap-security): "When two devices, which initially do not have security, wish to do something that requires security, the devices must first pair."

[How pairing works](https://medium.com/rtone-iot-security/deep-dive-into-bluetooth-le-security-d2301d640bfc): "Pairing involves authenticating the identity of two devices, encrypting the link using a short-term key (STK) and then distributing long-term keys (LTK) used for encryption. The LTK is saved for faster reconnection in the future, that is termed Bonding."

- **Encryption**. LTK is used with AES-CCM to create a 128-bit shared secret key
- **Authentication** is providing by digitally signing data using the CSRK (connection signature Resolving Key). Sending device places a signature after data pdu, receiver verifies using CSRK.

[Security modes](https://www.oreilly.com/library/view/getting-started-with/9781491900550/ch04.html): we need **security mode 1, level 3**. This is authenticated pairing and AES-CCM encryption.

## Tools

Install BlueZ 5.50: `sudo apt install libdbus-1-dev libudev-dev libical-dev libreadline-dev`

In BlueZ 5.50, hcitool, hciconfig and gatttool no longer exist and have been replaced by bluetoothctl. [setup](https://www.pcsuggest.com/linux-bluetooth-setup-hcitool-bluez/)

### Bluetoothctl

- **BLE scan**: `scan on` (or off to stop)

```
[!781]$ sudo bluetoothctl
[NEW] Controller 00:1A:7D:DA:71:08 alligator [default]
[bluetooth]# scan on
Discovery started
[CHG] Controller 00:1A:7D:DA:71:08 Discovering: yes
...
```

- Connect to a device: `connect MAC-address`
- Pair: `pair MAC-address` (connect first)

```
[Prodigio_D2A74C76F3E0]# pair D2:A7:4C:76:F3:E0
Attempting to pair with D2:A7:4C:76:F3:E0
[CHG] Device D2:A7:4C:76:F3:E0 Paired: yes
Pairing successful
```

- Get information: `info`
- List paired devices: `paired-devices`
- Pairing agents: `agent XXX`, e.g `agent NoInputNoOutput` (see [here](https://www.kynetics.com/docs/2018/pairing_agents_bluez/))
- Power Bluetooth adapter: `power on` (or off)

GATT commands are accessible in the GATT menu: `menu gatt`.
To leave GATT menu, `back`.

- Select the characteristic/service/attribute to work on: `select-attribute NAME`, e.g `select-attribute /org/bluez/hci0/dev_D2_A7_4C_76_F3_E0/service000c/char0013`
- Write: `write "0xde 0xad 0xbe 0xef"`

### Mirage


- [Repository](https://redmine.laas.fr/projects/mirage)
- [Paper](https://www.sstic.org/media/SSTIC2019/SSTIC-actes/mirage_un_framework_offensif_pour_laudit_du_blueto/SSTIC2019-Slides-mirage_un_framework_offensif_pour_laudit_du_bluetooth_low_energy-alata_auriol_roux_cayre_nicomette.pdf)
- [Doc](http://homepages.laas.fr/rcayre/mirage-documentation/index.html)

#### Installation

On Rpi,

```
sudo apt-get install python3-pip
sudo -H pip3 install keyboard psutil pyserial pyusb terminaltables scapy pycryptodomex
```

#### Usage

- Scan: `sudo ~/softs/mirage/mirage_launcher ble_scan`
- List services and characteristics:

```
load ble_connect|ble_discover
set ble_connect1.TARGET d2:a7:4c:76:f3:e0
set ble_connect1.CONNECTION_TYPE  random
set  ble_discover2.GATT_FILE  /tmp/gatt.ini
run
```

- Pairing: the easiest way is to write settings in `.mirage/mirage.cfg`

```
[ble_connect]
TARGET=d2:a7:4c:76:f3:e0
CONNECTION_TYPE=random

[ble_master]
TARGET=d2:a7:4c:76:f3:e0
CONNECTION_TYPE=random

[ble_pair]
IRK=112233445566778899aabbccddeeff
BONDING=yes
LTK=112233445566778899aabbccddeeff
CSRK=112233445566778899aabbccddeeff
DISPLAY=yes
KEYBOARD=yes
YESNO=no
SECURE_CONNECTIONS=no
CT2=no
MITM=yes
```

### hcidump

Install: `sudo apt-get install bluez-hcidump`


## Smart coffee services

We have 7 services:

- Generic Access: `00001800-0000-1000-8000-00805f9b34fb`
- Generic Attribute: `00001801-0000-1000-8000-00805f9b34fb`
- `06aa1910-f22a-11e3-9daa-0002a5d5c51b`: authorization, machine information, pairing key state, onboarding, serial, `COFFEE_MACHINE_SERVICE_UUID`
- `06aa1920-f22a-11e3-9daa-0002a5d5c51b`: factory reset, setup complete, machine status, schedule brew `AEROCCINO_SERVICE_UUID`
- `06aa1930-f22a-11e3-9daa-0002a5d5c51b`: error service
- `06aa1940-f22a-11e3-9daa-0002a5d5c51b`: general user operations. Cup size and volume.
- `06aa1950-f22a-11e3-9daa-0002a5d5c51b`: stock, threshold. `ORDER_SERVICE_UUID`

### Coffee service (0x1910)

| Characteristic Name | UUID | Handle |
| ------------------- | ----- | ------ |
| Machine Information | 0x3a21 | 0x0010 |
| Serial | 0x3a31 | 0x0012 |
| Authorization Key | 0x3a41 | 0x0014 |
| Pairking key state | 0x3a51 | 0x0016. Notif=0x0017 |
| Onboarding? | 0x3a61 | 0x0019 |

- Machine information. Characteristic UUID=0x3A21. Handle=0x0010.  `MachinePropertiesAdapter`: `00 6c 00 6d 00 7d 00 76 d2 a7 4c 76 f3 e0`. Hardware version, bootloader version, firmware, bluetooth firmware, BT MAC

- Serial. Characteristic UUID=0x3A31. Handle=0x0012. `SerialAdapter`. This is ASCII: `31 36 30 36 39 44 37 30 70 31 33 30 33 36 38 32 30 4e 4a` (serial number).

- Authorization Key. Characteristic UUID=0x3A41. Handle=0x0014. `AuthenticationAdapter` - write only.

- Pairing key state. Characteristic UUID=0x3A51. Handle=0x0016.  `MachinePropertiesAdapter`. Possibilities: ABSENT (0), PRESENT(1 or 2), UNDEFINED (3). I got 02. Use handle 0x0017 to activate notifications.

- Onboarding. haracteristic UUID=0x3A61. Handle=0x0019. `OnboardingAdapter`. Cannot be read.


### Aeroccino service (0x1920)


| Characteristic Name | UUID | Handle |
| ------------------- | ----- | ------ |
| ? | 0x3a11 | 0x000e |
| Machine Specific (lid status) | 0x3a22 | 0x001f. Notif=0x0020 |
| Scheduled brew | 0x3a32 | 0x0022 |
| Brew Key (Command) | 0x3a42 | 0x0024 |
| Brew Response | 0x3a52 | 0x0026. Notif=0x0027 |


- 0x3a11 (handle=0x000e): `40 02 01 90 00 00 0e f8`
- **"Machine Specific"** (this is the characteristic name). 0x3a22, handle=0x001f, `SetupCompleteAdapter`. When you open the lid: `00`. When it is closed: `02`. To enable notifications, use handle 0x0020
- **"Scheduled brew"**. 0x3a32, handle=0x0022, `com.nestle.connecteddevices.nespresso.operations.coffeemachine.BrewOperations`. Read programmed brew. Will be `TT TT DD DD DD DD` (T=type, F=temperature, D=duration).  If not scheduled `00 00 00 00 00 00`.


#### Brew Key

Characteristic UUID=0x3a42, handle=0x0024:

- To cancel brew, write: `03 06 01 02`.
- To brew now, write: `03 05 07 04 SS SS SS SS TT TT` where SS is the delay in *seconds* and TT is the coffee type. It is also possible to add temperature: `03 05 07 04 SS SS SS SS TT TT FF` (FF)
- To write a recipe, `01 16 08 00 00 .. recipe`
- **Factory reset**: `03 07 00`


#### Brew responses

Characteristic UUID=0x3a52, handle=0x0026:

- If you brew espresso: `83 05 01 20 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 `
- If you cancel: `83 06 01 20 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00`
- If you brew an americano (not supported) `c3 05 02 36 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00`
- To activate notifications, use handle 0x0027

OK starts with `83`:

- 05 = brewing coffee
- 06 = cancel


ERRORs start with `c3 05 02`.

- 08 = SLIDER_OPEN +1
- 12 = SLIDER_NOT_BEEN_OPENED + 1

Americano:
```
c3 05 02 36 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
c3 05 02 36 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Coffee type 3:
`83 05 01 20 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00`

Espresso:
`83 05 01 20 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00`

Ristretto:
```
83 05 01 20 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
83 05 01 20 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Ristretto with temperature:
```
83 05 01 20 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
83 05 01 20 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Cancel:
```
83 06 01 20 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
83 06 01 20 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Ristretto with open lid:
`c3 05 02 24 08 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00`

Ristretto without opened lid:
`c3 05 02 24 12 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00`

Ristretto without enough water?
`c3 05 03 24 01 04 80 00 00 00 00 00 00 00 00 00 00 00 00 00`

The error codes (which are printed in localized form) are present in `EnumCommandErrorType`.



#### Coffee types

- RISTRETTO 0
- ESPRESSO 1
- LUNGO 2
- AMERICANO 5
- HOT WATER 4

#### Recipes 

(doesn't work on my coffee machine, they are for 'expert' models):

- RECIPE_PREFIX: 01 16 + BrewByteConversion.getSize() = 08
- RECIPE_ID: 00 00
- List of ingredient volumes where you select either coffee or water:
  Coffee: `01 CC CC` where CC is coffee volume in ml
  Water: `02 WW WW` where WW is water volume in ml
- Finish with `00 00 00`

A recipe is normally a given volume in ml of coffee then water, or water then coffee.
With a temperature.
The acceptable range for coffee is 15mL to 130mL.
The acceptable range for water is 25mL to 300mL.




### Error Service 0x1930

| Characteristic name |Characteristic UUID | Handle | Comments | 
| --------------------------- |  -------------------------- | ----------| --------------- |
| Error Selection	   | 0x3A13 | 0x002a | See `ErrorRetrievalOperations`. 00 |
| Error Information  | 0x3A23 | 0x002c | See `ErrorRetrievalOperations`. 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |

### User Options 0x1940

| Characteristic name         | Characteristic UUID | Handle |
| --------------------------- |  -------------------------- | ----------| 
| Write Cup Size  Target     |  0x3A14 | 0x0030 | 
| Volume                    |  0x3A24 | 0x0032 | 
|  ??                        | 0x3A34 | 0x0035 |
| Water Hardness and StandBy Delay | 0x3A44 | 0x0038 |

See `CupSizeOperations`:

- Write Cup Size Target: `CZ CZ` where CZ is cup size (see below)
- Cup Volume: `VV VV FF FF` where `VV` is the volume in ml converted to hex. `FF FF` for -1. 

See `GeneralUserOperations`:

- Water Hardness and StandBy Delay: format is `SS SS HH` where `HH` is water hardness level (int <= 4), and `SS` is the seconds for the stand by delay: `07 08 04 00`

#### Cup size

- RISTRETTO or HOT_WATER_VTP2: 0
- ESPRESSO or ESPRESSO_VTP2: 1
- LUNGO: 2
- AMERICANO_COFFEE or AMERICANO_COFFEE_VTP2: 3
- AMERICANO_WATER: 4
- AMERICANO_XL_COFFEE: 5
- AMERICANO_XL_WATER: 6

Normal volumes are (from doc):

- ristretto 25ml
- espresso 40ml
- lungo 110ml



### 0x1950

| Characteristic name  | Characteristic UUID | Handle | Comments | 
| --------------------------- | -------------------------- | ----------| --------------- |
| Stock                       | 0x3A15 | 0x003c | 00 0e - Corresponds to the app's stock. |
| Stock threshold        |  0x3A25 | 0x003f | StockOperations. 00 05 |
| Stock Key                |  0x3A35 | 0x0041 | StockOperations. 00 00 00 00 |
|    ??                           |  0x3a45 | 0x0043 | 01 |

## References

- [User Manual](https://www.nespresso.com/shared_res/manuals/prodigio/www_PRODIGIO_C_KRUPS(EN_FR_DE_IT_ES_PT_CZ_HU_NL_GR_PL).pdf)
- [Webpresso GitHub project](https://github.com/cryptax/webpresso): makes your smart coffee machine available via a website.
- [Ph0wn](https://ph0wn.org)
- [Me Want Coffee Write-Up for Ph0wn 2019](https://github.com/ph0wn/writeups/tree/master/2019)
