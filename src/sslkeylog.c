/**
 * OpenSSL による SSL/TLS 通信の秘密鍵を指定ファイルに出力する。
 * 
 * OpenSSL 1.1.1 以降の場合は、SSL_CTX_set_keylog_callback が用意されているため、
 * SSL_CTX_set_keylog_callback にコールバックを登録し、(TLS 1.3 まで対応した)
 * キー情報を SSLKEYLOGFILE に出力する。
 *
 * OpenSSL 1.1.0 の場合、SSL_CTX_set_keylog_callback が存在しないため、
 * SSL_connect/SSL_accept/SSL_do_handshake を フックし、(TLS 1.2 まで対応した)
 * キー情報を SSLKEYLOGFILE に出力する。
 * (※ OpenSSL 1.1.0 は、TLS 1.2 までしか対応していない)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/ssl.h>
#include <fcntl.h>
#include <threads.h>


// =============================================================================
//  マクロ定義
// =============================================================================
#define CLIENT_RANDOM "CLIENT_RANDOM "
#define CLIENT_RANDOM_LEN (sizeof(CLIENT_RANDOM) - 1)
#define CLIENT_RANDOM_LINE_LENGTH (CLIENT_RANDOM_LEN + (SSL3_RANDOM_SIZE * 2) + 1 + (SSL_MAX_MASTER_KEY_LENGTH * 2) + 2)


// =============================================================================
//  構造体定義
// =============================================================================
/** マスターキー格納用構造体 */
typedef struct
{
    unsigned char value[SSL_MAX_MASTER_KEY_LENGTH];
    size_t length;
} SslMasterKey; 

/** クライアントランダム格納用構造体 */
typedef struct
{
    unsigned char value[SSL3_RANDOM_SIZE];
    size_t length;
} SslClientRandom;


// =============================================================================
//  プロトタイプ宣言
// =============================================================================
static void init_openssl_hooks(void);
static void logging_key(SSL *ssl, SslMasterKey *before_key);
static void *load_function(const char* sym);
static void *load_function_or_die(const char *sym);

static void KeyLogFile_init(void);
static void KeyLogFile_finalize(void);
static void KeyLogFile_callback(const SSL *ssl, const char *line);
static void KeyLogFile_raw_dump(const SslClientRandom *client_random, const SslMasterKey *master_key);


// =============================================================================
//  内部変数
// =============================================================================
once_flag openssl_init_flag = ONCE_FLAG_INIT;

// オリジナル OpenSSL 関数用
// 備考: _ex 系は、基本的に _ex 無しを呼び出す実装のため、Hook 不要。
static SSL *(*_SSL_new)(SSL_CTX *ctx) = NULL;
static int (*_SSL_connect)(SSL *ssl) = NULL;
static int (*_SSL_do_handshake)(SSL *ssl) = NULL;
static int (*_SSL_accept)(SSL *ssl) = NULL;
static size_t (*_SSL_get_client_random)(const SSL *ssl, unsigned char *out, size_t outlen) = NULL;
static size_t (*_SSL_SESSION_get_master_key)(const SSL_SESSION *session, unsigned char *out, size_t outlen) = NULL;
static SSL_SESSION *(*_SSL_get_session)(const SSL *ssl) = NULL;

typedef void (*_SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);
static void (*_SSL_CTX_set_keylog_callback)(SSL_CTX *ctx, _SSL_CTX_keylog_cb_func cb);


// =============================================================================
//  OpenSSL 関数群のフック
// =============================================================================

/**
 * SSL/TLS 通信するためのSSL構造体を生成する際に呼び出される。
 *
 * @param ctr
 *		接続設定をまとめたコンテキスト。
 *		SSL_CTX_new() で生成されたものが渡される。
 * @return 新しい SSL オブジェクトへのポインタ。失敗時は NULL を返す。
 */
SSL *SSL_new(SSL_CTX *ctx)
{
    // 初期化: 1回だけ実行する
    call_once(&openssl_init_flag, init_openssl_hooks);

    if (_SSL_CTX_set_keylog_callback != NULL)
    {   // OpenSSL 1.1.1 以降は、SSL_CTX_set_keylog_callback が用意されている。
        // => コールバックを登録して、キー情報を SSLKEYLOGFILE デバッグ出力に出力する。
        _SSL_CTX_set_keylog_callback(ctx, KeyLogFile_callback);
    }

    return _SSL_new(ctx);
}

/**
 * OpenSSL 関数のフック。
 * TLS/SSL サーバーとの TLS/SSL ハンドシェイクを開始する際に呼び出されます。
 *
 * @param ssl SSL オブジェクト
 * @return
 *	0: TLS/SSLハンドシェイク失敗した。プロトコル仕様に従いシャットダウンされた。
 *	1: TLS/SSLハンドシェイクが正常に完了し、TLS/SSL接続が確率された。
 *	<0: TLS/SSLハンドシェイクが失敗した。致命的なエラー発生または、接続に失敗した。
 */

int SSL_connect(SSL *ssl)
{
    if (_SSL_CTX_set_keylog_callback != NULL)
    {   // OpenSSL 1.1.1 以降は、callback が利用可能なため、そのまま呼び出す。
        return _SSL_connect(ssl);
    }

    // 以前のマスターキーを取得する。
    SslMasterKey before_key = { 0 };
    before_key.length = _SSL_SESSION_get_master_key(_SSL_get_session(ssl), before_key.value, SSL_MAX_MASTER_KEY_LENGTH);

    // 本来の関数を呼び出す。
    int ret = _SSL_connect(ssl);
    if (ret == 1)
    {   // 成功の場合、ログ出力する。
        logging_key(ssl, &before_key);
    }
    return ret;
}

int SSL_do_handshake(SSL *ssl)
{
    if (_SSL_CTX_set_keylog_callback != NULL)
    {   // OpenSSL 1.1.1 以降は、callback が利用可能なため、そのまま呼び出す。
        return _SSL_do_handshake(ssl);
    }

    // 以前のマスターキーを取得する。
    SslMasterKey before_key = { 0 };
    before_key.length = _SSL_SESSION_get_master_key(_SSL_get_session(ssl), before_key.value, SSL_MAX_MASTER_KEY_LENGTH);

    // 本来の関数を呼び出す。
    int ret = _SSL_do_handshake(ssl);
    if (ret == 1)
    {   // 成功の場合、ログ出力する。
        logging_key(ssl, &before_key);
    }
    return ret;
}

int SSL_accept(SSL *ssl)
{
    // 以前のマスターキーを取得する。
    SslMasterKey before_key = { 0 };
    before_key.length = _SSL_SESSION_get_master_key(_SSL_get_session(ssl), before_key.value, SSL_MAX_MASTER_KEY_LENGTH);
    // 本来の関数を呼び出す。
    int ret = _SSL_accept(ssl);
    if (ret == 1)
    {   // 成功の場合、ログ出力する。
        logging_key(ssl, &before_key);
    }
    return ret;
}

// =============================================================================
//  内部関数
// =============================================================================

/**
 * OpenSSL のフック初期化。
 * 本関数は、SSL_new が実行された際に一度だけ呼び出されます。
 */
static
void init_openssl_hooks(void)
{
    // オリジナル関数のロード
    _SSL_new = (SSL *(*)(SSL_CTX *)) load_function_or_die("SSL_new");
    _SSL_connect = (int (*)(SSL *)) load_function_or_die("SSL_connect");
    _SSL_do_handshake = (int (*)(SSL *)) load_function_or_die("SSL_do_handshake");
    _SSL_accept = (int (*)(SSL *)) load_function_or_die("SSL_accept");
    _SSL_get_client_random = (size_t (*)(const SSL *, unsigned char *, size_t)) load_function_or_die("SSL_get_client_random");
    _SSL_SESSION_get_master_key = (size_t (*)(const SSL_SESSION *, unsigned char *, size_t)) load_function_or_die("SSL_SESSION_get_master_key");
    _SSL_get_session = (SSL_SESSION *(*)(const SSL *)) load_function_or_die("SSL_get_session");

    // OpenSSL 1.1.1 以降対応の関数ロード
    _SSL_CTX_set_keylog_callback = (void (*)(SSL_CTX *, _SSL_CTX_keylog_cb_func)) load_function("SSL_CTX_set_keylog_callback");

    // KeyLogFile を初期化
    KeyLogFile_init();
}

/**
 * SSL のログを残します。(OpenSSL 1.1.0 以前対応)
 * 現在の master key が、指定された before_key と同じ場合はログ出力しません。
 */
static
void logging_key(SSL *ssl, SslMasterKey *before_key)
{
    SslMasterKey after_key = { 0 };
    after_key.length = _SSL_SESSION_get_master_key(_SSL_get_session(ssl), after_key.value, SSL_MAX_MASTER_KEY_LENGTH);
    if ((after_key.length > 0) && memcmp(after_key.value, before_key->value, after_key.length) != 0)
    {   // master key が変化した。
        SslClientRandom crandom = { 0 };
        crandom.length = _SSL_get_client_random(ssl, crandom.value, SSL3_RANDOM_SIZE);
        KeyLogFile_raw_dump(&crandom, &after_key);
    }
    else
    {   // NOP
        // セッションが再利用されたため、ログ出力不要。
        // Wireshark は、重複してキーが出力されても問題なく解析可能であるが、
        // 冗長なログとなるため、出力しない。
    }
}

/**
 * 指定されたシンボルのオリジナル関数を取得します。
 * オリジナル関数を取得できない場合、NULL を返します。
 *
 * @param sym シンボル
 * @return オリジナル関数
 */
static
void *load_function(const char *sym)
{
    // 次に見つかるシンボルを探す。
    // 本プログラム(libsslkeylog.so)は、LD_PRELOAD により最初にロードされるため、
    // 次に見つかる同名のシンボルが、本来の OpenSSL によるシンボルとなる。
    void *func = dlsym(RTLD_NEXT, sym);
    if (!func)
    {   // 関数が見つからない場合は、libssl.so をロードして探してみる。
        void *handle = dlopen("libssl.so", RTLD_LAZY);
        if (handle)
        {
            func = dlsym(handle, sym);
        }
        dlclose(handle);
    }
    return func;
}

/**
 * 指定されたシンボルのオリジナル関数を取得します。
 * オリジナル関数を取得できない場合、処理を中断 (abort) します。
 *
 * @param sym シンボル
 * @return オリジナル関数
 */
static
void *load_function_or_die(const char *sym)
{
    void *func = load_function(sym);
    if (!func)
    {
        abort();
    }
    return func;
}


////////////////////////////////////////////////////////////////////////////////
//
// キーログファイル管理
//

static int KeyLogFile_fd = -1;

/**
 * キーログファイル管理を初期化します。
 */
static
void KeyLogFile_init(void)
{
    if (KeyLogFile_fd >= 0)
    {   // すでに初期化済みのためなにもしない。
        return;
    }

    const char *sslkeylogfile_name = getenv("SSLKEYLOGFILE");
    if (sslkeylogfile_name)
    {   // カーネルレベルでアトミックに追記したいため、fopen の "a" ではなく、
        // open の O_APPEND にてファイルを開く。
        KeyLogFile_fd = open(sslkeylogfile_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
        atexit(KeyLogFile_finalize);
    }
}

/**
 * キーログファイル管理を終了します。
 */
static
void KeyLogFile_finalize(void)
{
    if (KeyLogFile_fd >= 0)
    {
        close(KeyLogFile_fd);
    }
}

/**
 * TLS キーが生成、受信された際に呼び出されるコールバック関数。
 * 引数より渡されたキー情報を SSLKEYLOGFILE デバッグ出力に出力します。
 *
 * @param ssl SSL オブジェクト
 * @param line キー情報 (NSS が SSLKEYLOGFILE デバッグ出力に使用する形式のキーマテリアルを含む文字列)
 */
static
void KeyLogFile_callback(const SSL *ssl, const char *line)
{
    (void) ssl;
    if (KeyLogFile_fd >= 0)
    {
        write(KeyLogFile_fd, line, strlen(line));
        write(KeyLogFile_fd, "\n", strlen("\n"));
    }
}

/**
 * 指定されたクライアントランダムとマスタキーを SSLKEYLOGFILE デバッグ出力に出力します。
 *
 * @param client_random クライアントランダム
 * @param master_key マスターキー
 */
static
void KeyLogFile_raw_dump(const SslClientRandom *client_random, const SslMasterKey *master_key)
{
    if (client_random->length != 0 && master_key->length != 0)
    {   // クライアントランダム、マスターキーともに有効な場合ログ出力する。
        unsigned char line[CLIENT_RANDOM_LINE_LENGTH] = { 0 };
        char *p = (char*) line;
        memcpy(p, CLIENT_RANDOM, CLIENT_RANDOM_LEN);
        p += CLIENT_RANDOM_LEN;

        // クライアントランダムを出力する。
        for (size_t i = 0; i < client_random->length; i++)
        {
            sprintf(p, "%02x", client_random->value[i]);
            p += 2;
        }

        *p++ = ' ';

        // マスターキーを出力する。
        for (size_t i = 0; i < master_key->length; i++)
        {
            sprintf(p, "%02x", master_key->value[i]);
            p += 2;
        }

        *p++ = '\n';

        size_t len = p - (char*) line;
        ssize_t written = write(KeyLogFile_fd, line, len);
        (void) written;
    }
}
