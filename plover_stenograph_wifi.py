from itertools import compress
from more_itertools import grouper
from plover.machine.base import ThreadedStenotypeBase
from plover import log
from struct import Struct, calcsize, pack, unpack
from time import sleep
from typing import Optional

import socket
import sys
import struct

'''
This Plover plugin allows you to use Diamanté or Luminex machines with Wi-Fi capability.
1. Turn on your Diamanté or Luminex and make sure you have both the hardware capability for
Wi-Fi and have it enabled in your settings.
2. Connect to the same Wi-Fi network as your computer running Plover.
3. Begin Plover.
4. If not already selected, select "Stenograph Wi-Fi" from the options.

That's it! If it disconnects, it should already reconnect when you're in range.
But if it's not connecting, try hitting the reconnect button in Plover.

KEITH'S NOTES:

Packet format:
--------------
Name:     Size:       Value Range:
----------------------------------
Sync          2 bytes "SG"
Sequence #    4 bytes 0 - 0xFFFFFFFF (will wrap from 0xFFFFFFFF to 0x00000000)
Packet ID     2 bytes As Defined (used as packet type)
Data Length   4 bytes 0 - size (limited in most writers to 65536 bytes)
Parameter 1   4 bytes As Defined
Parameter 2   4 bytes As Defined
Parameter 3   4 bytes As Defined
Parameter 4   4 bytes As Defined
Parameter 5   4 bytes As Defined
Command 0x13 Read Bytes
-----------------------
Request (from PC)
Description   Packet ID   Data Length       Param 1       Param 2     Param 3     Param 4     Param 5
------------------------------------------------------------------------------------------------------
Read Bytes   0x0013       00000000          File Offset   Byte Count  00000000    00000000    00000000
-Parameter 1 contains the file offset from which the Mira should start returning bytes (or stroke number * 8 since there are 8 bytes returned per stroke (see details of Response))
-Parameter 2 contains the maximum number of bytes the Host wants the Mira to send in response to this request
-The Mira will respond to this packet with a successful Read Bytes packet or an Error packet.
Response (from Mira)
Description   Packet ID   Data Length       Param 1       Param 2     Param 3     Param 4     Param 5
------------------------------------------------------------------------------------------------------
Read Bytes    0x0013      Number of Bytes   File Offset   00000000    00000000    00000000    00000000
-Parameter 1 contains the file offset from which the Mira is returning bytes
-For real-time the data is four bytes of steno and 4 bytes of timestamp - 8 bytes per stroke - repeating for the number of strokes returned.
The format of the eight bytes will be:
-Byte 0: 11^#STKP
-Byte 1: 11WHRAO*
-Byte 2: 11EUFRPB
-Byte 3: 11LGTSDZ
-Bytes 4-7: 'timestamp'
-The steno is in the (very) old SmartWriter format where the top two bits of each of the four bytes are set to 1 and the bottom 6 bits as set according to the keys pressed.
-If the Data Length is zero that indicates there are no more bytes available (real-time).
-If the file has been closed (on the writer) an Error packet (error: FileClosed) will be sent in response to Read Bytes.
Description   Packet ID   Data Length       Param 1       Param 2     Param 3     Param 4     Param 5
------------------------------------------------------------------------------------------------------
Open File     0x0012      Number of Bytes   Disk ID
- Parameter 1 is the disk ID that the file you wish to open is on (disk A for all intents and purposes)
- Data is the filename, probably 'REALTIME.000'
'''

# ^ is the "stenomark"
STENO_KEY_CHART = (
    ('^', '#', 'S-', 'T-', 'K-', 'P-'),
    ('W-', 'H-', 'R-', 'A-', 'O-', '*'),
    ('-E', '-U', '-F', '-R', '-P', '-B'),
    ('-L', '-G', '-T', '-S', '-D', '-Z'),
)

# Arbitrary read limit
MAX_READ = 0x200

# For UDP broadcast. Stenograph machines listen on port 5012 for opening packet.
# BROADCAST_ADDRESS = ("255.255.255.255", 5012)
BROADCAST_ADDRESS = "255.255.255.255"
BROADCAST_ADDRESS_2 = 'FF:FF:FF:FF:FF:FF'
BROADCAST_ADDRESS_3 = '192.168.1.255'
BROADCAST_PORT = 5012

# This is the specific reply by Stenograph machines to indicate their presence.
BATTLE_CRY = b'Calling All Miras...'


class StenoPacket(object):
    """
    Stenograph StenoPacket helper
    Can be used to create packets to send to the writer, as well as
    decode a packet from the writer.
    """
    _SYNC = b'SG'

    """
    Packet header format:
    'SG'     sequence number  packet ID  data length p1,p2,p3,p4,p5
    2 chars  4 bytes          2 bytes    4 bytes     4 bytes each
    """
    _STRUCT_FORMAT = '<2sIH6I'
    HEADER_SIZE = calcsize(_STRUCT_FORMAT)
    _STRUCT = Struct(_STRUCT_FORMAT)

    ID_ERROR = 0x6
    ID_OPEN = 0x11
    ID_READ = 0x13

    sequence_number = 0

    def __init__(self, sequence_number=None, packet_id=0, data_length=None,
                 p1=0, p2=0, p3=0, p4=0, p5=0, data=b''):
        """Create a USB Packet
        sequence_number -- ideally unique, if not passed one will be assigned sequentially.
        packet_id -- type of packet.
        data_length -- length of the additional data, calculated if not provided.
        p1, p2, p3, p4, p5 -- 4 byte parameters that have different roles based on packet_id
        data -- data to be appended to the end of the packet, used for steno strokes from the writer.
        """
        if sequence_number is None:
            sequence_number = StenoPacket.sequence_number
            StenoPacket._increment_sequence_number()
        if data is not None:
            # Data is padded to 8 bytes
            remainder = len(data) % 8
            if remainder:
                data += b'\x00' * (8 - remainder)
        if data_length is None:
            data_length = len(data)
        self.sequence_number = sequence_number
        self.packet_id = packet_id
        self.data_length = data_length
        self.p1 = p1
        self.p2 = p2
        self.p3 = p3
        self.p4 = p4
        self.p5 = p5
        self.data = data

    def __str__(self):
        return (
            'StenoPacket(sequence_number=%s, '
            'packet_id=%s, data_length=%s, '
            'p1=%s, p2=%s, p3=%s, p4=%s, p5=%s, data=%s)'
            % (hex(self.sequence_number), hex(self.packet_id),
               self.data_length, hex(self.p1), hex(self.p2),
               hex(self.p3), hex(self.p4), hex(self.p5),
               self.data[:self.data_length])
        )

    def pack(self):
        """Convert this USB Packet into something that can be sent to the writer."""
        return self._STRUCT.pack(
            self._SYNC, self.sequence_number, self.packet_id, self.data_length,
            self.p1, self.p2, self.p3, self.p4, self.p5
        ) + (
            pack('%ss' % len(self.data), self.data)
        )

    @staticmethod
    def _increment_sequence_number():
        StenoPacket.sequence_number = (
            StenoPacket.sequence_number + 1) % 0xFFFFFFFF

    @staticmethod
    def unpack(usb_packet):
        """Create a USBPacket from raw data"""
        packet = StenoPacket(
            # Drop sync when unpacking.
            *StenoPacket._STRUCT.unpack(usb_packet[:StenoPacket.HEADER_SIZE])[1:]
        )
        if packet.data_length:
            packet.data, = unpack(
                '%ss' % packet.data_length,
                usb_packet[StenoPacket.HEADER_SIZE:StenoPacket.HEADER_SIZE +
                           packet.data_length]
            )
        return packet

    @staticmethod
    def make_open_request(file_name=b'REALTIME.000', disk_id=b'A'):
        """Request to open a file on the writer, defaults to the realtime file."""
        return StenoPacket(
            packet_id=StenoPacket.ID_OPEN,
            # Omitting p1 may use the default drive.
            p1=ord(disk_id) if disk_id else 0,
            data=file_name,
        )

    @staticmethod
    def make_read_request(file_offset=1, byte_count=MAX_READ):
        """Request to read from the writer, defaults to settings required when reading from realtime file."""
        return StenoPacket(
            packet_id=StenoPacket.ID_READ,
            p1=file_offset,
            p2=byte_count,
        )

    def strokes(self):
        """Get list of strokes represented in this packet's data"""

        # Expecting 8-byte chords (4 bytes of steno, 4 of timestamp.)
        assert self.data_length % 8 == 0
        # Steno should only be present on ACTION_READ packets
        assert self.packet_id == self.ID_READ

        strokes = []
        for stroke_data in grouper(8, self.data, 0):
            stroke = []
            # Get 4 bytes of steno, ignore timestamp.
            for steno_byte, key_chart_row in zip(stroke_data, STENO_KEY_CHART):
                assert steno_byte >= 0b11000000
                # Only interested in right 6 values
                key_mask = [int(i) for i in bin(steno_byte)[-6:]]
                stroke.extend(compress(key_chart_row, key_mask))
            if stroke:
                strokes.append(stroke)
        return strokes


class AbstractStenographMachine(object):
    """Simple interface to connect with and send data to a Stenograph machine"""

    def connect(self) -> bool:
        """Connect to machine, returns connection status"""
        raise NotImplementedError('connect() is not implemented')

    def disconnect(self):
        """Disconnect from the machine"""
        raise NotImplementedError('disconnect() is not implemented')

    def send_receive(self, request: StenoPacket) -> Optional[StenoPacket]:
        """Send a StenoPacket to the machine and return the response or None"""
        raise NotImplementedError('send_receive() is not implemented')


class StenographMachine(AbstractStenographMachine):
    def __init__(self):
        super(StenographMachine, self).__init__()
        self._connected = False
        self._sock = None
        self._server_address = None
        self._stenograph_address = None

    def find_stenograph(self):
        # try:
        #     udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        #     udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #     udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #     udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        #     # ttl = struct.pack('b', 1)
        #     # sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        #     udp.settimeout(6)
        #     udp.sendto(BATTLE_CRY, (BROADCAST_ADDRESS, BROADCAST_PORT))
        #     print('Sending to: ', BATTLE_CRY, (BROADCAST_ADDRESS, BROADCAST_PORT))
        #
        #     while True:
        #         response, address = udp.recvfrom(4096)
        #         print('Response: ', response)
        #         print('Address: ', address)
        #
        #         print('Trying again...')
        #
        # except ConnectionError as e:
        #     udp.sendto(BATTLE_CRY, (BROADCAST_ADDRESS_2, BROADCAST_PORT))
        #     print('Sending to: ', BATTLE_CRY, BROADCAST_ADDRESS_2)
        #
        # except IOError as e:
        #     if (self._sock):
        #         self._sock.close()
        #         self._sock = None
        #
        #     print('Socket error: ', e)
        #
        # finally:
        #     udp.close()

        return ("192.168.1.223", 80)



    # def find_stenograph(self):

    #     # The temporary socket used to find the IP address of the Stenograph machine.
    #     udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #     # This socket option is necessary to prevent PermissionErr 13 violation.
    #     udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    #     udp_socket.settimeout(3)

    #     try:
    #         # Find the device's IP address by broadcasting "battle cry."
    #         print('Sending "%s"' % BATTLE_CRY.decode())
    #         udp_socket.sendto(BATTLE_CRY, BROADCAST_ADDRESS)

    #         # Upon battle cry, if a Stenograph machine is present on the network,
    #         # then data should contain "Mira in the neighborhood + machine name"
    #         response, address = udp_socket.recvfrom(5012)
    #         udp_socket.close()

    #     except IOError as e:
    #         if (self._sock):
    #             self._sock.close()
    #             self._sock = None

    #         print('Socket error: %s' % e)

    #     except:
    #         print('Connection lost. Try reconnecting and refreshing.')

    #     # If the response back contains "Mira in the neighborhood," that means it's a Stenograph machine.
    #     # Save the IP address of the machine to pass it along.
    #     if 'Mira in the neighborhood' in response.decode():
    #         self._stenograph_address = address

    #     # Close the UDP socket.
    #     udp_socket.close()

    #     return self._stenograph_address

    def connect(self):
        """Attempt to connect and return connection"""

        # Disconnect device if it's already connected.
        if self._connected:
            self.disconnect()

        # Find IP of Stenograph machine.
        server_address = self.find_stenograph()

        # No IP address = no device found.
        if not server_address:
            return self._connected

        # Now create a TCP connection to the found machine's IP address.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.5)
            sock.connect((server_address[0], 80))
            self._sock = sock
            log.warning('Connected successfully at: %s!' % server_address[0])
        except socket.timeout as e:
            log.warning('Socket timed out: %s' % e)
        except socket.error as exc:
            log.warning('Socket binding error: %s' % exc)

        # Pass 'em as class variables.
        self._connected = True
        self._server_address = server_address

        return self._connected

    def disconnect(self):
        self._sock.close()
        self._connected = False
        self._server_address = None

    def send_receive(self, request):
        assert self._connected, 'Cannot read from machine if not connected.'
        try:
            # Send packet
            self._sock.send(request.pack())

            # Buffer size = MAX_READ + StenoPacket.HEADER_SIZE
            response = self._sock.recv(MAX_READ + StenoPacket.HEADER_SIZE)
        except OSError:
            return None
        except socket.error:
            return None
        except:
            return None
        else:
            if response and len(response) >= StenoPacket.HEADER_SIZE:
                writer_packet = StenoPacket.unpack(response)
                # Ignore data if sequence numbers don't match.
                if writer_packet.sequence_number == request.sequence_number:
                    return writer_packet
            return None


class ProtocolViolationException(Exception):
    """The writer did something unexpected"""
    pass


class UnableToPerformRequestException(Exception):
    """The writer cannot perform the action requested"""
    pass


class FileNotAvailableException(Exception):
    """The writer cannot read from the current file"""
    pass


class NoRealtimeFileException(Exception):
    """The realtime file doesn't exist, likely because the user hasn't started writing"""
    pass


class FinishedReadingClosedFileException(Exception):
    """The closed file being read is complete and cannot be read further"""
    pass


class Stenograph(ThreadedStenotypeBase):

    KEYS_LAYOUT = '''
        #  #  #  #  #  #  #  #  #  #
        S- T- P- H- * -F -P -L -T -D
        S- K- W- R- * -R -B -G -S -Z
              A- O-   -E -U
        ^
    '''
    KEYMAP_MACHINE_TYPE = 'Stentura'

    def __init__(self, params):
        super(Stenograph, self).__init__()
        self._machine = StenographMachine()

    def _on_stroke(self, keys):
        steno_keys = self.keymap.keys_to_actions(keys)
        if steno_keys:
            self._notify(steno_keys)

    def start_capture(self):
        self.finished.clear()
        self._initializing()
        """Begin listening for output from the stenotype machine."""
        if not self._connect_machine():
            log.warning('Not connected. Try clicking refresh.')
            self._error()
        else:
            self._ready()
            self.start()

    def _connect_machine(self):
        connected = False
        try:
            connected = self._machine.connect()
        except AssertionError as e:
            log.warning('Error connecting: %s', e)
            self._error()
        except IOError as e:
            log.warning('Lost connection with Stenograph machine: %s', e)
            self._error()
        finally:
            return connected

    def _reconnect(self):
        self._initializing()
        connected = False
        while not self.finished.isSet() and not connected:
            sleep(0.25)
            connected = self._connect_machine()
        return connected

    def _send_receive(self, request):
        """Send a StenoPacket and return the response or raise exceptions."""
        log.debug('Requesting from Stenograph: %s', request)
        response = self._machine.send_receive(request)
        log.debug('Response from Stenograph: %s', response)
        if response is None:
            """No response implies device connection issue."""
            raise IOError()
        elif response.packet_id == StenoPacket.ID_ERROR:
            """Writer may reply with an error packet"""
            error_number = response.p1
            if error_number == 3:
                raise UnableToPerformRequestException()
            elif error_number == 7:
                raise FileNotAvailableException()
            elif error_number == 8:
                raise NoRealtimeFileException()
            elif error_number == 9:
                raise FinishedReadingClosedFileException()
        else:
            """Writer has returned a packet"""
            if (response.packet_id != request.packet_id
                    or response.sequence_number != request.sequence_number):
                raise ProtocolViolationException()
            return response

    def run(self):

        class ReadState(object):
            def __init__(self):
                self.realtime = False  # Not realtime until we get a 0-length response
                self.realtime_file_open = False  # We are reading from a file
                self.offset = 0  # File offset to read from

            def reset(self):
                self.__init__()

        state = ReadState()

        while not self.finished.isSet():
            try:
                if not state.realtime_file_open:
                    # Open realtime file
                    self._send_receive(StenoPacket.make_open_request())
                    state.realtime_file_open = True
                response = self._send_receive(
                    StenoPacket.make_read_request(file_offset=state.offset)
                )
            except IOError as e:
                log.warning(u'Stenograph machine disconnected, reconnecting…')
                log.debug('Stenograph exception: %s', e)

                # User could start a new file while disconnected.
                state.reset()
                if self._reconnect():
                    log.warning('Stenograph reconnected.')
                    self._ready()
            except NoRealtimeFileException:
                # User hasn't started writing, just keep opening the realtime file
                state.reset()
            except FinishedReadingClosedFileException:
                # File closed! Open the realtime file.
                state.reset()
            else:
                if response.data_length:
                    state.offset += response.data_length
                elif not state.realtime:
                    state.realtime = True
                if response.data_length and state.realtime:
                    for stroke in response.strokes():
                        self._on_stroke(stroke)

        self._machine.disconnect()

    def stop_capture(self):
        """Stop listening for output from the stenotype machine."""
        super(Stenograph, self).stop_capture()
        self._sock = None
        self._machine = None
