"""PyNFC convenience class"""

#  Pynfc is a python wrapper for the libnfc library
#  Copyright (C) 2009  Mike Auty
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import nfc

NDO_HANDLE_CRC = nfc.NDO_HANDLE_CRC
NDO_HANDLE_PARITY = nfc.NDO_HANDLE_PARITY
NDO_ACTIVATE_FIELD = nfc.NDO_ACTIVATE_FIELD
NDO_ACTIVATE_CRYPTO1 = nfc.NDO_ACTIVATE_CRYPTO1
NDO_EASY_FRAMING = nfc.NDO_EASY_FRAMING
NDO_AUTO_ISO14443_4 = nfc.NDO_AUTO_ISO14443_4
NDO_INFINITE_SELECT = nfc.NDO_INFINITE_SELECT
NDO_ACCEPT_INVALID_FRAMES = nfc.NDO_ACCEPT_INVALID_FRAMES
NDO_ACCEPT_MULTIPLE_FRAMES = nfc.NDO_ACCEPT_MULTIPLE_FRAMES

MC_AUTH_A = 0x60
MC_AUTH_B = 0x61
MC_READ = 0x30
MC_WRITE = 0xA0
MC_TRANSFER = 0xB0
MC_DECREMENT = 0xC0
MC_INCREMENT = 0xC1
MC_STORE = 0xC2

NM_ISO14443A_106 = nfc.NM_ISO14443A_106
NM_FELICA_212 = nfc.NM_FELICA_212
NM_FELICA_424 = nfc.NM_FELICA_424
NM_ISO14443B_106 = nfc.NM_ISO14443B_106
NM_JEWEL_106 = nfc.NM_JEWEL_106
NM_ACTIVE_DEP = nfc.NM_ACTIVE_DEP
NM_PASSIVE_DEP = nfc.NM_PASSIVE_DEP

class nfcdevice(object):
    """Standard NFC device"""

    _command_maps = [MC_AUTH_A,
                     MC_AUTH_B,
                     MC_READ,
                     MC_WRITE,
                     MC_TRANSFER,
                     MC_DECREMENT,
                     MC_INCREMENT,
                     MC_STORE]

    def __init__(self):
        self.pdi = None

    def connect(self):
        """Connects to an available NFC device"""
        self.disconnect()
        self.pdi = nfc.nfc_connect(None)
        return self.pdi is not None

    def disconnect(self):
        """Disconnects from the connected NFC device"""
        if self.pdi is not None:
            nfc.nfc_disconnect(self.pdi)
            self.pdi = None

    def configure(self, option, value):
        """Configures options for an NFC device"""
        return nfc.nfc_configure(self.pdi, option, value)

    def get_name(self):
        """Returns the device name for the current NFC device
           Returns None if there is no currently connected device
        """
        if self.pdi is not None:
            return self.pdi.acName
        return None

    def get_handle_parity(self):
        """Returns whether the device currently handles the parity bits during transmission automatically"""
        if self.pdi is not None:
            return self.pdi.bPar
        return None

    def get_handle_crc(self):
        """Returns whether the device currently calculates the necessary CRC for each transmission automatically"""
        if self.pdi is not None:
            return self.pdi.bCrc
        return None

    def get_active(self):
        """Returns whether the device is currently active"""
        if self.pdi is not None:
            return self.pdi.bActive
        return None

class nfc_initiator(nfcdevice):
    """NFC initiator (reader) device"""

    def init(self):
        """Initializes the initiator"""
        if self.pdi is None:
            return False
        return nfc.nfc_initiator_init(self.pdi)

    def select_tag(self, modulation, data):
        """Selects an NFC tag"""
        tag_info = nfc.nfc_target_info_t()
        res = nfc.nfc_initiator_select_passive_target(self.pdi, modulation, data, tag_info)
        if res:
            if modulation == NM_ISO14443A_106:
                return {'atqa': tag_info.nai.get_atqa(),
                        'sak': tag_info.nai.get_sak(),
                        'uid': tag_info.nai.get_uid(),
                        'ats': tag_info.nai.get_ats()}
            elif modulation in [NM_ACTIVE_DEP, NM_FELICA_212, NM_FELICA_424, NM_ISO14443B_106, NM_JEWEL_106, NM_PASSIVE_DEP]:
                # raise NotImplementedError("The tag_information for these devices is not yet implemented")
                return ()
        return None

    def deselect_tag(self):
        """Deselects any currently selected NFC tag"""
        return nfc.nfc_initiator_deselect_target(self.pdi)

    def transceive_bits(self, bits, inlen, par = None):
        """Transceive bits as the reader"""
        res = nfc.nfc_initiator_transceive_bits(self.pdi, bits, inlen, par)
        if not res:
            return res
        (a, b, c) = res
        if self.get_handle_parity():
            return (a, b, None)
        return (a, b, c)

    def transceive_bytes(self, inbytes):
        """Transceive full bytes as the reader"""
        return nfc.nfc_initiator_transceive_bytes(self.pdi, inbytes)

    def mifare_cmd(self, command, block, key = None, uid = None, data = None, value = None):
        """Sends MIFARE commands as an initiator"""
        import binascii
        if command not in self._command_maps:
            raise TypeError("Command type " + type(command) + " not found")
        if block > 255 or block < 0:
            raise TypeError("Value for block is too large")
        inbytes = chr(command) + chr(block)
        if command in [MC_AUTH_A, MC_AUTH_B]:
            if key is not None and uid is not None:
                inbytes += key + uid
        elif command in [MC_READ, MC_WRITE]:
            if data is not None:
                inbytes += data
        elif command in [MC_DECREMENT, MC_INCREMENT, MC_TRANSFER, MC_STORE]:
            if value is not None:
                inbytes += value
        else:
            raise RuntimeError("Should never reach this point!")
        res = self.transceive_bytes(inbytes)
        if res and command == MC_READ:
            return res
        return (res != False)

class nfc_target(nfcdevice):
    """NFC Target (card/emulation) device"""

    def init(self):
        """Initializes the reader as a tag"""
        if self.pdi is None:
            return False
        return nfc.nfc_target_init(self.pdi)

    def receive_bits(self):
        """Receives bits as the tag"""
        res = nfc.nfc_target_receive_bits(self.pdi)
        if not res:
            return res
        (a, b, c) = res
        if self.get_handle_parity():
            return (a, b, None)
        return (a, b, c)

    def receive_bytes(self):
        """Receives bytes as the tag"""
        return nfc.nfc_target_receive_bytes(self.pdi)

    def send_bits(self, bits, inlen, par):
        """Send bits acting as a tag"""
        return nfc.nfc_target_send_bits(self.pdi, bits, inlen, par)

    def send_bytes(self, inbytes):
        """Sends bytes acting as a tag"""
        return nfc.nfc_target_send_bytes(self.pdi, inbytes)
