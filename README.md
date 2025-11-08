# はじめに
OpenSSL を利用しているプログラムにおいて、
SSL/TLS接続で生成された鍵情報を指定ファイルに出力します。

Wireshark などに読み込むことにより、
暗号化パケットが解読されたパケットを追加表示できるようになります。

OpenSSL 1.1.1 以降(TLS 1.3) に対応しております。

# OpenSSL によるサポート
OpenSSL Version 3.5 (2025年4月) にて、SSLKEYLOGFILE 環境変数がサポートされました。
OpenSSL ビルド時に、enable-sslkeylog を有効にすることで、
SSLKEYLOGIFLE 環境変数を設定すると、鍵情報をファイルに出力します。

ただ、古い OpenSSL が利用されている、OpenSSL の差し替え、再ビルドが大変といった場合、
本ファイルを利用すると、比較的簡単に鍵情報を出力可能です。

# ビルド方法
基本的なビルド環境がそろっていれば、次のコマンドでビルド可能です。
(libssl-dev : version 1.1.0 以降が必要です。)
```
make
```
必要に応じて、適宜 Makefile を修正ください。


# 利用方法
target : 暗号化された通信を見たい対象アプリケーション

```
# export LD_PRELOAD=<libsslkeylog.soのパス>
# export SSLKEYLOGFILE=<鍵情報を出力するファイルパス>
# <対象アプリケーションを実行>
#
# root ユーザー以外で実行する場合、<libsslkeylog.soのパス> は絶対パスで指定する必要があります。
#
# 例)
export LD_PRELOAD=/path/to/libsslkeylog.so
export SSLKEYLOGFILE=./sslkey.log
./target-apl
```

実行後、SSLKEYLOGFILE 環境変数で指定したファイル名 (sslkey.log) のファイルが生成されます。
生成されたファイルを Wireshark などに読み込むと解読されたパケットが追加表示されます。

※ Wireshark の場合、[編集(E)] -> [設定...(P)] -> Protocols -> TLS の
(Pre)-Master-Secret log filename に出力されたファイルを指定します。
