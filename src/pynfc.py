'''
Created on 15 Jan 2011

@author: mike
'''

import ctypes
import ctypes.util

_lib = ctypes.CDLL(ctypes.util.find_library('nfc'))

DEVICE_NAME_LENGTH = 256

(NC_PN531, NC_PN532, NC_PN533) = (0x10, 0x20, 0x30)

_size_t = ctypes.c_uint32
_enum_val = ctypes.c_int

class DeviceDescription(ctypes.Structure):
    _fields_ = [("device", ctypes.c_char * DEVICE_NAME_LENGTH),
                ("driver", ctypes.c_char_p),
                ("port", ctypes.c_char_p),
                ("speed", ctypes.c_uint32),
                ("bus_index", ctypes.c_uint32)
                ]

    def connect(self):
        return NfcDevice(self)

class ChipCallbacks(ctypes.Structure):
    _fields_ = [("strerror", ctypes.POINTER(None))
                ]

class InfoIso14443A(ctypes.Structure):
    _fields_ = [("atqa", ctypes.c_ubyte * 2),
                ("sak", ctypes.c_ubyte),
                ("uidlen", _size_t),
                ("uid", ctypes.c_ubyte * 10),
                ("atslen", _size_t),
                ("ats", ctypes.c_ubyte * 254) # Maximal theoretical ATS is FSD - 2, FSD = 256 for FSDI = 8 in RATS
                ]

class InfoFelicia(ctypes.Structure):
    _fields_ = []

class InfoIso14443B(ctypes.Structure):
    _fields_ = []

class InfoJewel(ctypes.Structure):
    _fields_ = []

class InfoDep(ctypes.Structure):
    _fields_ = []

class TargetInfo(ctypes.Union):
    _fields_ = [("nai", InfoIso14443A),
                ("nfi", InfoFelicia),
                ("nbi", InfoIso14443B),
                ("nji", InfoJewel),
                ("ndi", InfoDep)
                ]

class Modulation(ctypes.Structure):
    _fields_ = [("nmt", _enum_val),
                ("nbr", _enum_val)
                ]

class Target(ctypes.Structure):
    _fields_ = [("nti", TargetInfo),
                ("mm", Modulation)
                ]

class DriverCallbacks(ctypes.Structure):
    _fields_ = [("driver", ctypes.c_char_p),
                ("chip_callbacks", ctypes.POINTER(ChipCallbacks)),
                ("pick_device", ctypes.POINTER(None)),
                ("list_devices", ctypes.POINTER(None)),
                ("connect", ctypes.POINTER(None)),
                ("transceive", ctypes.POINTER(None)),
                ("disconnect", ctypes.POINTER(None))
                ]

class _Device(ctypes.Structure):
    _fields_ = [("pdc", ctypes.POINTER(DriverCallbacks)),
                ("name", ctypes.c_char * DEVICE_NAME_LENGTH),
                ("nc", _enum_val),
                ("nds", ctypes.POINTER(None)),
                ("active", ctypes.c_bool),
                ("crc", ctypes.c_bool),
                ("par", ctypes.c_bool),
                ("easy_framing", ctypes.c_bool),
                ("auto_iso14443_4", ctypes.c_bool),
                ("tx_bits", ctypes.c_uint8),
                ("parameters", ctypes.c_uint8),
                ("support_byte", ctypes.c_ubyte)
                ]

_lib.nfc_version.restype = ctypes.c_char_p

_lib.nfc_list_devices.argtypes = (ctypes.POINTER(DeviceDescription), _size_t, ctypes.POINTER(ctypes.c_int))

_lib.nfc_connect.argtypes = (ctypes.POINTER(DeviceDescription),)
_lib.nfc_connect.restype = ctypes.POINTER(_Device)

_lib.nfc_disconnect.argtypes = (ctypes.POINTER(DeviceDescription),)
_lib.nfc_disconnect.restype = None

_lib.nfc_configure.argtypes = (ctypes.POINTER(_Device), _enum_val, ctypes.c_bool)
_lib.nfc_configure.restype = ctypes.c_bool

_lib.nfc_initiator_init.argtypes = (ctypes.POINTER(_Device),)
_lib.nfc_initiator_init.restype = ctypes.c_bool


def get_version():
    res = _lib.nfc_version()
    print res

def list_devices():
    max_device_length = 16
    Devices = DeviceDescription * max_device_length
    pnddDevices = Devices()
    num_devices = ctypes.c_int(0)
    _lib.nfc_list_devices(pnddDevices, max_device_length, ctypes.pointer(num_devices))
    result = []
    for i in range(min(num_devices.value, max_device_length)):
        result.append(pnddDevices[i])
    return result

class NfcDevice(object):
    NDO_HANDLE_CRC = 0x00
    NDO_HANDLE_PARITY = 0x01
    NDO_ACTIVATE_FIELD = 0x10
    NDO_ACTIVATE_CRYPTO1 = 0x11
    NDO_INFINITE_SELECT = 0x20
    NDO_ACCEPT_INVALID_FRAMES = 0x30
    NDO_ACCEPT_MULTIPLE_FRAMES = 0x31
    NDO_AUTO_ISO14443_4 = 0x40
    NDO_EASY_FRAMING = 0x41
    NDO_FORCE_ISO14443_A = 0x42

    NMT_ISO14443A = 0x0
    NMT_ISO14443B = 0x1
    NMT_FELICA = 0x2
    NMT_JEWEL = 0x3
    NMT_DEP = 0x4

    def __init__(self, devdesc = None):
        if devdesc:
            devdesc = ctypes.pointer(devdesc)
        self._device = _lib.nfc_connect(devdesc)

    def __del__(self):
        """Disconnects from the NFC device"""
        _lib.nfc_disconnect(self._device)

    def check_enum(self, prefix, value):
        if value not in [ getattr(self, i) for i in dir(self) if i.startswith(prefix)]:
            raise AttributeError("Failed to locate appropriate configuration option")

    def configure(self, option, value):
        """Configures the NFC device options"""
        self.check_enum('NDO', option)
        return _lib.nfc_configure(self._device, option, value)

    def initiator_init(self):
        """Initializes the NFC device for initiator"""
        return _lib.nfc_initiator_init(self._device)

    def initiator_select_passive_target(self, modulation, initdata):
        """Selects a passive target"""
        self.check_enum('NMT', modulation)
        pinitdata = ""
        pinitdatalen = ctypes.pointer(ctypes.c_int(len(initdata)))
        ptarget = ctypes.pointer()
        _lib.nfc_initiator_select_passive_target(self._device, modulation, pinitdata, pinitdatalen, ptarget)
