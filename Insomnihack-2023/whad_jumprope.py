import argparse
from whad.ble import Central
from whad.ble.profile import UUID
from whad.device import WhadDevice


def get_arguments():
    parser = argparse.ArgumentParser(prog='ble_jumprope.py')
    parser.add_argument('-a',
                        '--address',
                        help='Device Bluetooth MAC address',
                        action='store',
                        default='DF:E5:34:0E:42:7D')
    '''
    parser.add_argument('-n',
                        '--nb',
                        help='Number Count Down mode',
                        action='store',
                        default=1337,
                        type=int)
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        default=True)
    '''                    
    args = parser.parse_args()
    return args


def menu():
    print('1- Number Count Down Mode')
    print('2- Time Count Down Mode')
    print('3- Free Jump Mode')
    print('4- Buzzer On')
    print('5- Buzzer Off')
    print('6- Read Battery Level')
    print('7- Cancel Mode')
    print('8- Exit')
    answer = int(input("Choice ? "))
    # TODO: catch errors
    nb = None
    if answer == 1:
        nb = int(input("Target Nb of Jumps? "))
    elif answer == 2:
        nb = int(input("Target Time in seconds? "))
    return answer, nb


# from https://stackoverflow.com/questions/69369408/calculating-crc16-in-python-for-modbus
def modbusCrc(msg:str) -> int:
    crc = 0xFFFF
    for n in range(len(msg)):
        crc ^= msg[n]
        for i in range(8):
            if crc & 1:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc


class JumpRope:
    def __init__(self, address):
        self.central = Central(WhadDevice.create('hci0'))
        print(f'Connecting to {address}...')
        self.device = self.central.connect(address)
        self.device.set_disconnect_cb(self.on_disconnect)

    def quit(self):
        print('Disconnecting device...')
        self.device.disconnect()
        print('Closing Central...')
        self.central.stop()
        self.central.close()
        # TO DO: we can't use self.central afterwards...

    def on_disconnect(self):
        print('[+] Disconnected')

    def send_cmd(self, command):
        '''
        Alternative way to send commands:
        To use the UUID, we need to do a prior discovery
        Then, we can send a command using get_characteristic
        and setting c.value
        cmd_uuid = '00005302-0000-0041-4c50-574953450000'
        service_uuid = '00005301-0000-0041-4c50-574953450000'
        c = self.device.get_characteristic(UUID(service_uuid), UUID(cmd_uuid))
        c.value = bytes.fromhex(command)
        '''
        print(f'Sending to 0x0010: {bytes.fromhex(command)}')
        self.device.write_command(0x0010, bytes.fromhex(command))
        print('[+] Command sent!')

    def mode_cmd(self, cmd=0x81, target=300) -> str:
        command = f'020005{cmd:02X}{target:08X}'
        print(f'Command: {command}')
        crc = modbusCrc(bytes.fromhex(command))
        print(f'CRC16/MODBUS: {crc:04X}')
        command = command + f'{crc:04X}'
        print(f'Command with CRC: {command}')
        return command

    def time_countdown_cmd(self, target=300) -> str:
        print(f'Time Count Down mode for {target} seconds')
        return self.mode_cmd(0x82, target)

    def nb_countdown_cmd(self, target_nb=1337) -> str:
        print(f'Nb Count Down mode for {target_nb} jumps')
        return self.mode_cmd(0x81, target_nb)
    
    def free_cmd(self) -> str:
        # cmd = 0x80
        print('Free Jump Mode')
        return '020005800000000059C0'
    
    def buzzer_cmd(self, buzzer_on=True) -> str:
        if buzzer_on:
            print('Buzzer ON')
            return '0800010114C2'
        else:
            print('Buzzer OFF')
            return '08000100D403'

    def cancel_cmd(self) -> str:
        print('Cancel Mode')
        return '020005010000000047FC'
    
    def get_battery(self) -> int:
        print('Read Battery Level')
        level = int.from_bytes(self.device.read(0x0029), 'big')
        print(f'Battery level= {level} %')
        return level


if __name__ == '__main__':
    args = get_arguments()
    print('====== Smart Jump Rope Control (RENPHO R-Q001) ======')
    print(f'Bluetooth MAC address={args.address}')
    jump = JumpRope(args.address)
    while True:
        answer, nb = menu()
        if answer == 8:
            jump.quit()
            quit()
        if answer == 1:
            cmd = jump.nb_countdown_cmd(nb)
        elif answer == 2:
            cmd = jump.time_countdown_cmd(nb)
        elif answer == 3:
            cmd = jump.free_cmd()
        elif answer == 4:
            cmd = jump.buzzer_cmd(True)
        elif answer == 5:
            cmd = jump.buzzer_cmd(False)
        else:  # 7
            cmd = jump.cancel_cmd()
        if answer == 6:
            jump.get_battery()
        else:
            jump.send_cmd(cmd)

