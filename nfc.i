/*

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

*/

 %module nfc
 %{
 /* Includes the header in the wrapper code */
 #include <nfc/nfc.h>
 #include <nfc/nfc-types.h>
 
 #define MAX_FRAME_LEN 264
 
 %}
 
 /** IN/OUT: nfc_initiator_transceive_bits and nfc_target_receive_bits **/
 %typemap(in) (const byte_t* pbtTx) {
    if (!PyString_Check($input)) {
	    PyErr_SetString(PyExc_ValueError, "Expecting a string (pbtTx)");
	    return NULL;
    }
    $1 = PyString_AsString($input);
 }

 %typemap(in) (const byte_t* pbtTxPar) {
    if ($input == Py_None) {
        $1 = NULL;
    } else {
        if (!PyString_Check($input)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a string or None (pbtTxPar)");
            return NULL;
        } 
        $1 = PyString_AsString($input);
    }
 }

 %typemap(in) (const size_t szTxBits) {
    $1 = PyInt_AsLong($input);
 }

 %typemap(in, numinputs=0) (byte_t* pbtRx, size_t* pszRxBits, byte_t* pbtRxPar) {
    byte_t abtRx[MAX_FRAME_LEN];
    byte_t abtRxPar[MAX_FRAME_LEN];
    uint32_t len = 0 ;
    $1 = (byte_t*)&abtRx;
    $2 = &len;
    $3 = (byte_t*)&abtRxPar;
 }

 %typemap(argout) (byte_t* pbtRx, size_t* pszRxBits, byte_t* pbtRxPar) {
    PyObject* tempobj1 = 0;
    PyObject* tempobj2 = 0;
    if (result) {
        int x = *$2 / 8;
        if (*$2 % 8) { x++; }
        tempobj1 = PyString_FromStringAndSize($1,x);
        tempobj2 = PyString_FromStringAndSize($3,x);
        $result = PyTuple_New(3);
        PyTuple_SetItem($result, 0, tempobj1);
        PyTuple_SetItem($result, 1, PyInt_FromLong(*$2));
        PyTuple_SetItem($result, 2, tempobj2);
    }
 }

 /** IN/OUT: nfc_initiator_transceive_bytes/nfc_target_receive_bytes/nfc_target_send_bytes **/
 %typemap(in) (const byte_t* pbtTx, const size_t szTxLen) {
    if (!PyString_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a string (pbtTx, szTxLen)");
        return NULL;
    }
    $1 = PyString_AsString($input);
    $2 = PyString_Size($input);
 }

 %typemap(in, numinputs=0) (byte_t* pbtRx, size_t* pszRxLen) {
    byte_t abtRx[MAX_FRAME_LEN];
    uint32_t len = 0 ;
    $1 = (byte_t*)&abtRx;
    $2 = &len;
 }

 %typemap(argout) (byte_t* pbtRx, size_t* pszRxLen) {
    if (result) {
        $result = PyString_FromStringAndSize($1,*$2);
    }
 }

 /** IN/OUT: nfc_target_init **/
 %typemap(in, numinputs=0) (byte_t* pbtRx, size_t* pszRxBits) {
    byte_t abtRx[MAX_FRAME_LEN];
    uint32_t len = 0 ;
    $1 = (byte_t*)&abtRx;
    $2 = &len;
 }
 
 %typemap(argout) (byte_t* pbtRx, size_t* pszRxBits) {
    PyObject* tempobj1 = 0;
    if (result) {
        int x = *$2 / 8;
        if (*$2 % 8) { x++; }
        tempobj1 = PyString_FromStringAndSize($1,x);
        $result = PyTuple_New(2);
        PyTuple_SetItem($result, 0, tempobj1);
        PyTuple_SetItem($result, 1, PyInt_FromLong(*$2));
    }
 }

/** IN: nfc_initiator_select_tag **/
%typemap(in) (const byte_t* pbtInitData, const size_t szInitDataLen) {
    if ($input == Py_None) {
        $1 = NULL;
        $2 = 0;
    } else {
        if (!PyString_Check($input)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a string (pbtInitData, szInitDataLen)");
            return NULL;
        }
        $1 = PyString_AsString($input);
        $2 = PyString_Size($input);
    }
}

%typemap(in) (const uint8_t ui8Block) {
    if (!PyInt_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a number (ui8Block)");
        return NULL;
    }
    long x = PyInt_AsLong($input);
    if (x >= 256 || x < 0) {
        PyErr_SetString(PyExc_ValueError, "Expecting a number between 0 and 256");
        return NULL;
    }
    $1 = (int) x;
}

 /* Parse the header file to generate wrappers */
 %include <nfc/nfc.h>
 %include <nfc/nfc-types.h>
 
%extend nfc_iso14443a_info_t {
    PyObject* get_atqa() {
        return PyString_FromStringAndSize($self->abtAtqa, 2);
    }
    PyObject* get_sak() {
        return PyString_FromFormat("%c", $self->btSak);
    }
    PyObject* get_uid() {
        return PyString_FromStringAndSize($self->abtUid, $self->szUidLen);
    }
    PyObject* get_ats() {
        return PyString_FromStringAndSize($self->abtAts, $self->szAtsLen);
    }
}

%define MIFARE_PARAM_HELPER(pname, name, maxsize, varname)
%extend mifare_param_ ## pname {
    bool set_ ## name (PyObject* input) {
        int bufSize;
        if (input == Py_None) {
            memset($self-> ## varname , 0, maxsize );
        } else {
            if (!PyString_Check(input)) {
                PyErr_SetString(PyExc_ValueError, "Expecting a string ( pname : name )");
                return NULL;
            }
            bufSize = PyString_Size(input);
            if ( bufSize > maxsize ) {
                bufSize = maxsize ;
            }
            memcpy($self-> ## varname , PyString_AsString(input), bufSize);
        }
        return true;
    }
    PyObject* get_ ## name () {
        return PyString_FromStringAndSize($self-> ## varname , maxsize );
    }
}
%enddef

MIFARE_PARAM_HELPER(value, value, 4, abtValue)
MIFARE_PARAM_HELPER(data, data, 16, abtData) 
MIFARE_PARAM_HELPER(auth, key, 6, abtKey)
MIFARE_PARAM_HELPER(auth, uid, 4, abtUid)
