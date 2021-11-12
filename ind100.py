# coding=utf-8

import os
import struct
from collections import namedtuple

# parser = struct.Struct("9s23s29s26s19BBB8s16sII")
# parser = struct.Struct(">9s23s29s26s19sBB8s16sII")
>9s23s29s26s19sBB8s16sII
IHH640s1024s1024s

parser = struct.Struct(">9s23s29s26s19sBB8s16sIIIHH640s1024s1024s")
cdi_parser = struct.Struct(">16sBB2s3sB3sB3sB32sIIBB6s")
len_parser = struct.calcsize(">9s23s29s26s19sBB8s16sIIIHH640s1024s1024s")
len_cdi_parser = struct.calcsize(">16sBB2s3sB3sB3sB32sIIBB6s")


PJL_Header = {
    '1_UniversalExitCommand': '9s',
    '2_PJL_JOB_MODE': '23s',
    '3_PJL_USTATUS_DEVICE': '29s',
    '4_PJL_SET_JOBATTR': '26s',
    '5_Reserved1': '19s',
    '6_CryptFlag': 'B',
    '7_KeyInfo': 'B',
    '8_ProducID': '8s',
    '9_SetVersion': '16s',
    'A_TotalBytes': 'I',
    'B_NumberOfROMImage': 'I',
    'C_DescriptionBytes': 'I',
    'D_SignatureSize': 'H',
    'E_ControllerSignatureSize': 'H',
    'F_DownloadFileDescription': '640s',
    'G_Signature': '1024s',
    'H_Reserved2': '1024s',
}

_f = ['>']
for key in sorted(PJL_Header.keys()):
    _f.append(PJL_Header[key])
header_format = "".join(_f)
header_parser = struct.Struct(header_format)
len_header_parser = struct.calcsize(header_format)
_f = [_n[2:] for _n in sorted(PJL_Header.keys())]

file_header = namedtuple('file_header', _f)


header_parser.unpack_from(fw_data)
ff = file_header(*header_parser.unpack_from(fw_data))


CDI_Header = {
    '1_FileID': '16s',
    '2_Target': 'B',
    '3_Module': 'B',
    '4_Reserved1': '2s',
    '5_SWVersion': '3s',
    '6_Reserved2': 's',
    '7_MinHWVersion': '3s',
    '8_Reserved3': 's',
    '9_MaxHWVersion': '3s',
    'A_Reserved4': 's',
    'B_ModelName': '32s',
    'C_FlashSize': 'I',
    'D_NextHeader': 'I',
    'E_DCSpecificSize': 'B',
    'F_Interface': 's',
    'G_Reserved5': '6s',
}

def parse(header_def, data):
    _keys = sorted(header_def.keys())
    #
    _f = [header_def[key] for key in _keys]
    _f.insert(0, '>')
    #
    _format = "".join(_f)
    _parser = struct.Struct(_format)
    #
    _header = namedtuple('_header', [key[2:] for key in _keys])
    #
    return _header(*_parser.unpack_from(data)), struct.calcsize(_format)




PJL_Header = namedtuple('PJL_Header', [
    'UniversalExitCommand',
    'PJL_JOB_MODE',
    'PJL_USTATUS_DEVICE',
    'PJL_SET_JOBATTR',
    'Reserved1',
    '',
    '',
    '',
    '',
])


# PJL_Header = namedtuple('PJL_Header', [
#     'UniversalExitCommand',
#     'PJL_JOB_MODE',
#     'PJL_USTATUS_DEVICE',
#     'PJL_SET_JOBATTR',
#     'Reserved',
#     'Encryption_Info',
#     'Key_Info',
#     'ProductID',
#     'SetVersion',
#     'TotalBytes',
#     'NumberOfROM',
#     '',
#     '',
#     '',
#     '',
#
# ])


def main(file_path=r"C:\Users\m-shi\Downloads\crypt\crypt\IND-10\海外版TOE1-4で実施\210917_A_4570G_AP_E正式版.bin"):
    with open(file_path, "rb") as f:
        fw_data = f.read(4000)

    # head = fw_data[:144]
    # uec_1, p_2, p_3, p_4, r_5, c_6, k_7, d_8, s_9, tb_10, nri_11, s_12 = parser.unpack(head)
    # res = parser.unpack(head)

    # return uec_1, p_2, p_3, p_4, r_5, c_6, k_7, d_8, s_9, tb_10, nri_11
    return fw_data[:len_parser+len_cdi_parser+256], parser.unpack_from(fw_data), cdi_parser.unpack_from(fw_data[2836:])


SIGNATURE_POS = int(0x314, 16)
ROM_IMAGE_POS = int(0xC70, 16)


def make(basefile_path):
    with open(basefile_path, "rb") as f:
        fw_data = f.read()

    pos = namedtuple('pos', ['Signature', 'ROM'])
    pos.Signature = SIGNATURE_POS
    pos.ROM = ROM_IMAGE_POS

    fn = os.path.splitext(basefile_path)[0] + "_1_Sig" + os.path.splitext(basefile_path)[-1]
    _write(fn, fw_data, pos.Signature)
    fn = os.path.splitext(basefile_path)[0] + "_2_Rom" + os.path.splitext(basefile_path)[-1]
    _write(fn, fw_data, pos.ROM)


def _write(outfile_path, data_list, index, chg_byte=b'\x00'):
    with open(outfile_path, "wb") as f:
        f.write(data_list[:index]+chg_byte+data_list[index+1:])

