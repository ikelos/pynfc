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
NDO_INFINITE_SELECT = nfc.NDO_INFINITE_SELECT
NDO_ACCEPT_INVALID_FRAMES = nfc.NDO_ACCEPT_INVALID_FRAMES
NDO_ACCEPT_MULTIPLE_FRAMES = nfc.NDO_ACCEPT_MULTIPLE_FRAMES

MC_AUTH_A = nfc.MC_AUTH_A
MC_AUTH_B = nfc.MC_AUTH_B
MC_READ = nfc.MC_READ
MC_WRITE = nfc.MC_WRITE
MC_TRANSFER = nfc.MC_TRANSFER
MC_DECREMENT = nfc.MC_DECREMENT
MC_INCREMENT = nfc.MC_INCREMENT
MC_STORE = nfc.MC_STORE

NM_ISO14443A_106 = nfc.NM_ISO14443A_106
NM_FELICA_212 = nfc.NM_FELICA_212
NM_FELICA_424 = nfc.NM_FELICA_424
NM_ISO14443B_106 = nfc.NM_ISO14443B_106
NM_JEWEL_106 = nfc.NM_JEWEL_106
NM_ACTIVE_DEP = nfc.NM_ACTIVE_DEP
NM_PASSIVE_DEP = nfc.NM_PASSIVE_DEP

class nfcdevice(object):
    """Standard NFC device"""

    _command_maps = {nfc.MC_AUTH_A    : nfc.mifare_param_auth,
                     nfc.MC_AUTH_B    : nfc.mifare_param_auth,
                     nfc.MC_READ      : nfc.mifare_param_data,
                     nfc.MC_WRITE     : nfc.mifare_param_data,
                     nfc.MC_TRANSFER  : nfc.mifare_param_value,
                     nfc.MC_DECREMENT : nfc.mifare_param_value,
                     nfc.MC_INCREMENT : nfc.mifare_param_value,
                     nfc.MC_STORE     : nfc.mifare_param_value}

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
        res = nfc.nfc_initiator_select_tag(self.pdi, modulation, data, tag_info)
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
        return nfc.nfc_initiator_deselect_tag(self.pdi)
    
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
    
    def mifare_cmd(self, command, block, key=None, uid=None, data=None, value=None):
        """Sends MIFARE commands as an initiator"""
        param_type = self._command_maps.get(command, None)
        if param_type is None:
            raise TypeError("Command type " + type(command) + " not found")
        parameter = nfc.mifare_param()
        if param_type == nfc.mifare_param_auth:
            subparam = param_type()
            subparam.set_key(key)
            subparam.set_uid(uid)
            parameter.mpa = subparam
        elif param_type == nfc.mifare_param_data:
            subparam = param_type()
            subparam.set_data(data)
            parameter.mpd = subparam
        elif param_type == nfc.mifare_param_value:
            subparam = param_type()
            subparam.set_value(value)
            parameter.mpv = subparam 
        else:
            raise RuntimeError("Should never reach this point!")
        res = nfc.nfc_initiator_mifare_cmd(self.pdi, command, block, parameter)
        if res and command == MC_READ:
            return parameter.mpd.get_data()
        return res

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
