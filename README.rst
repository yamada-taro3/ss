=======
sc_copy
=======
スクリーンコピー(PrintScreenまたはalt＋PrintScreen)実施時に
画像をファイル(jpeg)に保存する。


=========
インストール
=========
適当なフォルダに解凍する。フォルダに移動しコマンドプロンプトで以下を実行する

.. code-block:: console

    > python setup.py install

※アンストール
　pip uninstall sc_copy


======
使い方
======
コマンドプロンプトで以下を実施するとツールが起動する。

.. code-block:: console

    > python -m sc_copy.gui

まずは、保存フォルダ、ベースファイルなどを設定してください。
前通番、後通番は保存するごとに自動的にインクリメントされます。

「開始する」ボタンをクリックすると
スクリーンコピー(PrintScreenまたはalt＋PrintScreen)実施時に
画像を設定したファイル(jpeg)に保存する動作になります。

「中止する」ボタンをクリックすると保存しない動作に戻ります。


============
Requirements
============
sc_copy 1.0.0 requires

* Python >=3.8
* Pillow >=9.0.1
* pynput >=1.7.6
* pyperclip >=1.8.2