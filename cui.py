# coding=utf-8
import logging
import time

from PIL import ImageGrab, Image
from pynput import keyboard
import pyperclip

logger = logging.getLogger(__name__)


class SaveWindow:
    def __init__(self):
        self.file_no = 0
        self.filename = 'ScreenShot'

    def listen(self):
        with keyboard.Listener(
                on_press=self._on_press,
                on_release=self._on_release) as listener:
            listener.join()

    @staticmethod
    def _on_press(key):
        logger.debug(f'{key} on')

    def _on_release(self, key):
        logger.debug(f'{key} off')
        if key == keyboard.Key.print_screen:  # PrintScreenが離された場合
            self.paste_img_from_clipboard()

        elif key == keyboard.Key.ctrl_l:  # 左Ctrlが離された場合
            self.paste_text_from_clipboard()

        elif key == keyboard.Key.esc:  # escが押された場合
            return False

    def paste_img_from_clipboard(self, wait=1):
        time.sleep(wait)

        im = ImageGrab.grabclipboard()
        if isinstance(im, Image.Image):
            filename = f"{self.file_no:03}_{self.filename}.jpg"
            im.save(filename)
            print(f'{filename}に保存しました')
            self.file_no += 1
        else:
            logger.info('Not image')

    def paste_text_from_clipboard(self, wait=1):
        time.sleep(wait)

        content = pyperclip.paste()
        if content:
            self.filename = content[:64]
            print(f'ベースファイル名-> {self.filename}')
        else:
            logger.info('Not text')


def main():
    SaveWindow().listen()


# def on_activate():
#     print('Global hotkey activated!')
#
#
# def for_canonical(f):
#     return lambda k: f(keyboard.Listener.canonical(k))
#
#
# def test2():
#     hotkey = keyboard.HotKey(
#         keyboard.HotKey.parse('<ctrl>+<alt>+h'),
#         on_activate)
#     with keyboard.Listener(
#             on_press=for_canonical(hotkey.press),
#             on_release=for_canonical(hotkey.release)) as _l:
#         _l.join()
#
#
# def on_activate_cp():
#     print('<ctrl>+c pressed')
#
#
# def on_activate_i():
#     print('<alt>+<print_screen> pressed')
#
#
# def test():
#     with keyboard.GlobalHotKeys({'<ctrl>+c': on_activate_cp, '<alt>': on_activate_i}) as h:
#         h.join()


if __name__ == '__main__':
    main()
