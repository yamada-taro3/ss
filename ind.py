# coding=utf-8

from collections import namedtuple
import os


def tamper(from_filepath: str):
    '''
    改竄ファイルを作成する。
    :param from_filepath: 改竄元のファイル
    '''

    # sig_pos = 0x314
    # rom_pos = 0xC70
    # chg_val = b'\x00'

    with open(from_filepath, 'rb') as f:
        df_data = f.read()

    filepath, extension = os.path.splitext(from_filepath)

    write_file(df_data, filepath + '_1_署名改竄' + extension, chg_pos=788, chg_val=b'\0')
    write_file(df_data, filepath + '_2_ROM改竄' + extension, chg_pos=3184, chg_val=b'\0')

    # tamper_file = namedtuple('tamper_file', ['name', 'chg_pos', 'chg_val'])
    # for tf in [tamper_file('_1_署名改竄', 788, b'\0'),
    #            tamper_file('_2_ROM改竄', 3184, b'\0')]:
    #     write_file(df_data, filepath + tf.name + extension, tf.chg_pos, tf.chg_val)


def write_file(df_data: bytes, to_filepath: str, chg_pos: int, chg_val=b'\0'):
    '''
    :param df_data:
    :param to_filepath:
    :param chg_pos:
    :param chg_val:
    :return:
    '''

    print(f'⇒{to_filepath}')

    with open(to_filepath, 'wb') as f:
        f.write(df_data[:chg_pos] + chg_val + df_data[chg_pos+1:])

    print(f'  0x{chg_pos:>04x}({chg_pos:>4}): 0x{df_data[chg_pos]:>2x} -> {chg_val[0]:>2x}')
