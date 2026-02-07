# =============================================================================
# HTTPS/TLSを理解する
#
# これまで学んだ全ての技術がどう組み合わさるかの総まとめ。
# ブラウザで https:// にアクセスするたびに起きていること。
#
# TLS = Transport Layer Security
# SSL（Secure Sockets Layer）の後継。現在はTLS 1.3が最新。
# =============================================================================

require 'openssl'
require 'digest'
require 'securerandom'

puts "=== HTTPS/TLSとは？ ==="
puts

puts <<~TEXT
ブラウザで https://example.com にアクセスすると...

  1. DH鍵交換で共通鍵を作る        ← 06で学んだ
  2. RSAデジタル署名で相手を認証    ← 05で学んだ
  3. AESで通信を暗号化              ← 07で学んだ
  4. ハッシュで改ざんを検知          ← 01, 02で学んだ

全部つながった！
TEXT
puts

# =============================================================================
puts "=== TLSハンドシェイクの全体像 ==="
puts

puts <<~TEXT
  Client（ブラウザ）                    Server（Webサーバー）
       │                                     │
  1.   │──── ClientHello ────────────────→    │
       │    「TLS 1.3で通信したい」            │
       │    「対応する暗号スイート一覧」        │
       │    「DHの公開値」                      │
       │                                      │
  2.   │    ←──── ServerHello ────────────│
       │         「この暗号スイートを使おう」   │
       │         「DHの公開値」                 │
       │         「証明書（公開鍵+署名）」      │
       │                                      │
  3.   │  （両者がDH共有鍵を計算）              │
       │  （共有鍵からAESの鍵を導出）           │
       │                                      │
  4.   │←─── 暗号化通信開始（AES）────→│
       │                                      │
TEXT
puts

# =============================================================================
puts "=== ステップ1: ClientHello（クライアントの挨拶） ==="
puts

# -----------------------------------------------------------------------------
# ClientHelloで送る情報
#
# 1. 対応するTLSバージョン
# 2. 暗号スイート一覧（どの暗号の組み合わせが使えるか）
# 3. DH鍵交換の公開値
# 4. ランダムな値（リプレイ攻撃対策）
# -----------------------------------------------------------------------------

# 暗号スイートの例
cipher_suites = [
  "TLS_AES_256_GCM_SHA384",       # AES-256 + GCMモード + SHA-384
  "TLS_AES_128_GCM_SHA256",       # AES-128 + GCMモード + SHA-256
  "TLS_CHACHA20_POLY1305_SHA256", # ChaCha20（AESの代替）
]

# DHの公開値を生成
p_val = 7919
g = 7
client_secret = rand(2..p_val - 2)
client_public = g.pow(client_secret, p_val)

# クライアントのランダム値
client_random = SecureRandom.hex(16)

puts "Client → Server: ClientHello"
puts "  TLSバージョン: TLS 1.3"
puts "  暗号スイート候補:"
cipher_suites.each { |cs| puts "    - #{cs}" }
puts "  DHの公開値: #{client_public}"
puts "  クライアントランダム: #{client_random[0..15]}..."
puts

# =============================================================================
puts "=== ステップ2: ServerHello + 証明書 ==="
puts

# -----------------------------------------------------------------------------
# ServerHelloで送る情報
#
# 1. 選んだ暗号スイート
# 2. DHの公開値
# 3. サーバー証明書
#    - サーバーの公開鍵
#    - 認証局（CA）のデジタル署名
#    → 「このサーバーは本物」という証明
# -----------------------------------------------------------------------------

# サーバーのDH鍵ペア
server_secret = rand(2..p_val - 2)
server_public = g.pow(server_secret, p_val)

# サーバーのランダム値
server_random = SecureRandom.hex(16)

puts "Server → Client: ServerHello"
puts "  選んだ暗号スイート: TLS_AES_256_GCM_SHA384"
puts "  DHの公開値: #{server_public}"
puts "  サーバーランダム: #{server_random[0..15]}..."
puts

# 証明書のシミュレーション
puts "Server → Client: 証明書"
puts "  サーバー: example.com"
puts "  公開鍵:   (RSA 2048ビット)"
puts "  発行者:   Let's Encrypt（認証局）"
puts "  署名:     認証局の秘密鍵で署名済み"
puts "  有効期限: 2026-01-01 〜 2026-12-31"
puts

puts <<~TEXT
証明書の検証（ブラウザが行う）:
  1. 認証局の公開鍵で署名を検証（05のデジタル署名）
  2. ドメイン名が一致するか確認
  3. 有効期限内か確認
  4. 認証局が信頼リストに含まれるか確認
  → 全部OKなら「このサーバーは本物」と判断
TEXT
puts

# =============================================================================
puts "=== ステップ3: 共有鍵の生成 ==="
puts

# -----------------------------------------------------------------------------
# DH鍵交換で共有鍵を作る（06で学んだ）
#
# さらにHKDF（HMAC-based Key Derivation Function）で
# 共有鍵からAESの鍵、IV、MACの鍵を導出する
# → 1つの共有鍵から複数の目的別の鍵を安全に作る
# -----------------------------------------------------------------------------

# DH鍵交換
client_shared = server_public.pow(client_secret, p_val)
server_shared = client_public.pow(server_secret, p_val)

puts "DH鍵交換:"
puts "  Client計算: #{server_public}^#{client_secret} mod #{p_val} = #{client_shared}"
puts "  Server計算: #{client_public}^#{server_secret} mod #{p_val} = #{server_shared}"
puts "  一致？ #{client_shared == server_shared ? 'OK！' : 'NG'}"
puts

# 鍵導出（簡易版: 実際はHKDFを使う）
shared_secret = client_shared.to_s
master_key = Digest::SHA256.hexdigest("master_#{shared_secret}_#{client_random}_#{server_random}")
aes_key = Digest::SHA256.digest("aes_key_#{master_key}")[0..31]   # 256ビット
aes_iv = Digest::SHA256.digest("aes_iv_#{master_key}")[0..15]     # 128ビット
mac_key = Digest::SHA256.digest("mac_key_#{master_key}")[0..31]   # 256ビット

puts "鍵導出（共有鍵 → 目的別の鍵）:"
puts "  AES鍵: #{aes_key.unpack1('H*')[0..31]}...（256ビット）"
puts "  AES IV: #{aes_iv.unpack1('H*')}（128ビット）"
puts "  MAC鍵: #{mac_key.unpack1('H*')[0..31]}...（256ビット）"
puts

# =============================================================================
puts "=== ステップ4: 暗号化通信 ==="
puts

# -----------------------------------------------------------------------------
# ハンドシェイク完了後、AESで暗号化通信
#
# 各メッセージに対して:
#   1. AESで暗号化（機密性）
#   2. HMACで認証タグを付ける（改ざん検知）
# -----------------------------------------------------------------------------

# HTTPリクエストを暗号化して送る
http_request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

# AES暗号化
cipher = OpenSSL::Cipher::AES256.new(:CBC)
cipher.encrypt
cipher.key = aes_key
cipher.iv = aes_iv

encrypted_request = cipher.update(http_request) + cipher.final

# HMAC（改ざん検知用のタグ）
hmac = OpenSSL::HMAC.hexdigest("SHA256", mac_key, encrypted_request)

puts "Client → Server（暗号化通信）:"
puts
puts "  平文（HTTPリクエスト）:"
puts "    #{http_request.lines.first.strip}"
puts "    #{http_request.lines[1].strip}"
puts
puts "  暗号文: #{encrypted_request.unpack1('H*')[0..47]}..."
puts "  HMAC:   #{hmac[0..31]}..."
puts

# サーバー側で復号
decipher = OpenSSL::Cipher::AES256.new(:CBC)
decipher.decrypt
decipher.key = aes_key
decipher.iv = aes_iv

decrypted_request = decipher.update(encrypted_request) + decipher.final

# HMAC検証
verify_hmac = OpenSSL::HMAC.hexdigest("SHA256", mac_key, encrypted_request)

puts "Server側の処理:"
puts "  HMAC検証: #{hmac == verify_hmac ? 'OK（改ざんなし）' : 'NG（改ざん検知！）'}"
puts "  復号結果: #{decrypted_request.lines.first.strip}"
puts

# =============================================================================
puts "=== ステップ5: 改ざん検知のデモ ==="
puts

# -----------------------------------------------------------------------------
# もし攻撃者が暗号文を1バイトでも変えたら？
# → HMACが一致しなくなる → 改ざんを検知できる
# -----------------------------------------------------------------------------

# 暗号文を改ざん
tampered = encrypted_request.dup
tampered.setbyte(0, tampered.getbyte(0) ^ 0xFF)  # 最初のバイトを反転

# 改ざんされた暗号文のHMAC
tampered_hmac = OpenSSL::HMAC.hexdigest("SHA256", mac_key, tampered)

puts "攻撃者が暗号文を1バイト改ざんした場合:"
puts "  元のHMAC:     #{hmac[0..31]}..."
puts "  改ざん後HMAC: #{tampered_hmac[0..31]}..."
puts "  一致？ #{hmac == tampered_hmac ? 'YES' : 'NO → 改ざん検知！通信を拒否'}"
puts

# =============================================================================
puts "=== 全体のまとめ ==="
puts

puts <<~TEXT
HTTPS/TLSで使われている技術と、学んだファイルの対応:

  ┌─────────────────────────────────────────────────┐
  │              TLSハンドシェイク                    │
  │                                                  │
  │  DH鍵交換（06）  → 共通鍵を安全に共有            │
  │  RSA署名（05）   → サーバーが本物か認証           │
  │  ハッシュ（01,02）→ 鍵導出、改ざん検知            │
  │                                                  │
  ├─────────────────────────────────────────────────┤
  │              暗号化通信                           │
  │                                                  │
  │  AES（07）       → データの暗号化                 │
  │  HMAC（ハッシュ） → 改ざん検知                    │
  │                                                  │
  └─────────────────────────────────────────────────┘

  これが https:// でアクセスするたびに起きている！

学習の振り返り:
  01: ハッシュ関数の基本         → 改ざん検知の基盤
  02: ハッシュの仕組み           → なぜ一方向なのか
  03: Proof of Work              → ハッシュの応用（ブロックチェーン）
  04: XOR暗号                    → 暗号化の基礎概念
  05: RSA暗号                    → 公開鍵暗号、デジタル署名
  06: Diffie-Hellman鍵交換       → 鍵を安全に共有
  07: AES暗号                    → 実際のデータ暗号化
  08: HTTPS/TLS                  → 全部を組み合わせた完成形
TEXT
