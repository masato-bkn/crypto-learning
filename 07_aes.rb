# =============================================================================
# AES（Advanced Encryption Standard）を理解する
#
# 現代の対称鍵暗号の標準。XOR暗号の「超進化版」。
# 2001年にNISTが標準化。元の名前はRijndael（ラインダール）。
# 発明者: Vincent Rijmen と Joan Daemen（ベルギーの暗号学者）
# =============================================================================

require 'openssl'

puts "=== AESとは？ ==="
puts

puts <<~TEXT
XOR暗号の問題（04で学んだ）:
  - 短い鍵 → ブルートフォースで破られる
  - 鍵の使い回し → 鍵が消えてバレる

AESの解決策:
  - 128/192/256ビットの鍵（十分に長い）
  - XOR + 置換 + シフト + 混合を10〜14ラウンド繰り返す
  - 同じ鍵でも安全に何度も使える仕組み（モード）
TEXT
puts

# =============================================================================
puts "=== ステップ1: AESの4つの操作 ==="
puts

# -----------------------------------------------------------------------------
# AESの1ラウンドで行う4つの操作
#
# 1. SubBytes（バイト置換）
#    各バイトをS-Boxという変換表で別の値に置き換える
#    → 非線形性を加える（パターンを壊す）
#
# 2. ShiftRows（行シフト）
#    4×4のブロックの各行を左にずらす
#    → バイトの位置を拡散させる
#
# 3. MixColumns（列混合）
#    各列を数学的に混ぜる（有限体上の行列演算）
#    → 1バイトの変化を列全体に広げる
#
# 4. AddRoundKey（ラウンド鍵の加算）
#    ラウンドごとに異なる鍵とXOR
#    → 鍵の情報を混ぜ込む
# -----------------------------------------------------------------------------

puts <<~TEXT
AESの1ラウンド（4つの操作）:

  ┌──────────────────────────┐
  │  SubBytes（バイト置換）   │ 各バイトをS-Boxで変換
  │   ↓                      │ → パターンを壊す
  │  ShiftRows（行シフト）    │ 行を左にずらす
  │   ↓                      │ → 位置を拡散
  │  MixColumns（列混合）     │ 列を数学的に混ぜる
  │   ↓                      │ → 1バイトの変化を列全体に
  │  AddRoundKey（鍵の加算）  │ ラウンド鍵とXOR
  └──────────────────────────┘
         ↓ これを10〜14回繰り返す
TEXT
puts

# =============================================================================
puts "=== ステップ2: SubBytes（バイト置換）を体験 ==="
puts

# -----------------------------------------------------------------------------
# S-Box（置換表）
#
# 256通りの入力それぞれに対して出力が決まっている
# 例: 0x00 → 0x63, 0x01 → 0x7C, ...
#
# なぜ必要？
#   XORやシフトは「線形」な操作
#   → 線形だけだと数学的に解析されやすい
#   S-Boxは「非線形」→ 解析を困難にする
#
# S-Boxの値は恣意的ではない
#   有限体GF(2^8)上の逆元 + アフィン変換で数学的に構成
# -----------------------------------------------------------------------------

# AESの実際のS-Box（最初の2行だけ表示）
sbox = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
]

puts "S-Boxの例（入力 → 出力）:"
[0x00, 0x01, 0x05, 0x10, 0x11].each do |input|
  output = sbox[input]
  puts "  0x#{input.to_s(16).rjust(2, '0')} → 0x#{output.to_s(16).rjust(2, '0')}"
end
puts
puts "→ 入力が1変わるだけで出力が大きく変わる（非線形）"
puts

# =============================================================================
puts "=== ステップ3: ShiftRows（行シフト）を体験 ==="
puts

# -----------------------------------------------------------------------------
# AESは16バイト（128ビット）のブロックを4×4の行列として扱う
#
# ShiftRowsの操作:
#   行0: シフトなし
#   行1: 左に1バイトシフト
#   行2: 左に2バイトシフト
#   行3: 左に3バイトシフト
#
# なぜ？
#   各列のバイトを異なる列に散らすことで「拡散」を実現
# -----------------------------------------------------------------------------

def shift_rows(state)
  result = state.map(&:dup)
  (0..3).each do |row|
    # 各行を左にrow回シフト（配列のrotate）
    result[row] = state[row].rotate(row)
  end
  result
end

def print_state(label, state)
  puts "#{label}:"
  state.each do |row|
    puts "  [#{row.map { |b| b.to_s(16).rjust(2, '0') }.join(', ')}]"
  end
end

# 4×4の状態行列
state = [
  [0x01, 0x02, 0x03, 0x04],  # 行0: シフトなし
  [0x05, 0x06, 0x07, 0x08],  # 行1: 左に1シフト
  [0x09, 0x0a, 0x0b, 0x0c],  # 行2: 左に2シフト
  [0x0d, 0x0e, 0x0f, 0x10],  # 行3: 左に3シフト
]

print_state("ShiftRows前", state)
puts
shifted = shift_rows(state)
print_state("ShiftRows後", shifted)
puts
puts "→ 各行が異なる量だけ左にシフト（バイトが散らばる）"
puts

# =============================================================================
puts "=== ステップ4: AddRoundKey（XOR）を体験 ==="
puts

# -----------------------------------------------------------------------------
# 各ラウンドで「ラウンド鍵」をXOR
#
# ラウンド鍵は元の鍵から「鍵スケジュール」で生成
# → 1つの鍵から10〜14個の異なるラウンド鍵を作る
# → 毎ラウンド違う鍵でXORするので、04で学んだ「鍵の使い回し」問題が起きない
# -----------------------------------------------------------------------------

data_block = [0x48, 0x65, 0x6c, 0x6c]   # "Hell"
round_key  = [0x2b, 0x7e, 0x15, 0x16]   # ラウンド鍵の一部

xored = data_block.zip(round_key).map { |d, k| d ^ k }

puts "AddRoundKey（XOR）:"
puts "  データ:     #{data_block.map { |b| b.to_s(16).rjust(2, '0') }.join(' ')}  (\"Hell\")"
puts "  ラウンド鍵: #{round_key.map { |b| b.to_s(16).rjust(2, '0') }.join(' ')}"
puts "  XOR結果:    #{xored.map { |b| b.to_s(16).rjust(2, '0') }.join(' ')}"
puts
puts "→ 04で学んだXOR暗号と同じ操作！AESの核心部分"
puts

# =============================================================================
puts "=== ステップ5: AESの全体の流れ ==="
puts

puts <<~TEXT
AES-128の場合（鍵128ビット）:

  平文（16バイト = 128ビット）
    ↓
  AddRoundKey（初回の鍵XOR）
    ↓
  ┌─── 10ラウンド繰り返し ───┐
  │ 1. SubBytes   （置換）    │
  │ 2. ShiftRows  （シフト）  │
  │ 3. MixColumns （混合）    │ ← 最終ラウンドでは省略
  │ 4. AddRoundKey（鍵XOR）   │
  └───────────────────────────┘
    ↓
  暗号文（16バイト）

鍵の長さとラウンド数:
  AES-128: 鍵128ビット → 10ラウンド
  AES-192: 鍵192ビット → 12ラウンド
  AES-256: 鍵256ビット → 14ラウンド
TEXT
puts

# =============================================================================
puts "=== ステップ6: RubyでAES暗号化（本物） ==="
puts

# -----------------------------------------------------------------------------
# OpenSSLライブラリを使って実際にAES暗号化してみる
#
# AES-256-CBC:
#   AES-256: 鍵の長さ256ビット
#   CBC: Cipher Block Chaining（暗号ブロック連鎖モード）
#     → 前のブロックの暗号文を次のブロックに混ぜる
#     → 同じ平文でも毎回違う暗号文になる
#
# IV（初期化ベクトル）:
#   CBCモードで最初のブロックに混ぜるランダム値
#   → 同じ平文+同じ鍵でも、IVが違えば暗号文が変わる
# -----------------------------------------------------------------------------

# 暗号化
cipher = OpenSSL::Cipher::AES256.new(:CBC)
cipher.encrypt

key = cipher.random_key  # 256ビットのランダムな鍵
iv = cipher.random_iv    # 初期化ベクトル

plaintext = "Hello, AES! This is a secret message."
encrypted = cipher.update(plaintext) + cipher.final

puts "平文:   #{plaintext}"
puts "鍵:     #{key.unpack1('H*')[0..31]}...（256ビット）"
puts "IV:     #{iv.unpack1('H*')}"
puts "暗号文: #{encrypted.unpack1('H*')[0..47]}..."
puts

# 復号
decipher = OpenSSL::Cipher::AES256.new(:CBC)
decipher.decrypt
decipher.key = key
decipher.iv = iv

decrypted = decipher.update(encrypted) + decipher.final
puts "復号:   #{decrypted}"
puts

# =============================================================================
puts "=== ステップ7: なぜ「モード」が必要？ ==="
puts

# -----------------------------------------------------------------------------
# AESは16バイトのブロック単位で暗号化する
# 長いメッセージをどう処理する？→「モード」が決める
#
# ECB（Electronic Codebook）: 各ブロックを独立に暗号化
#   → 同じ平文ブロック → 同じ暗号文（パターンが漏れる！）
#
# CBC（Cipher Block Chaining）: 前の暗号文ブロックをXORしてから暗号化
#   → 同じ平文でも違う暗号文になる（パターンが隠れる）
# -----------------------------------------------------------------------------

puts <<~TEXT
ECBモード（危険）:
  ブロック1: "Hello, World!..." → 暗号化 → XXXX
  ブロック2: "Hello, World!..." → 暗号化 → XXXX  ← 同じ！
  → 同じ平文は同じ暗号文になるのでパターンがバレる

CBCモード（安全）:
  ブロック1: "Hello, World!..." XOR IV   → 暗号化 → XXXX
  ブロック2: "Hello, World!..." XOR XXXX → 暗号化 → YYYY  ← 違う！
  → 前のブロックの暗号文が次に影響するので毎回変わる
TEXT
puts

# ECBの問題を実演
puts "--- ECBの問題を実演 ---"
cipher_ecb = OpenSSL::Cipher::AES128.new(:ECB)
cipher_ecb.encrypt
ecb_key = cipher_ecb.random_key

# 同じ16バイトのブロックを2つ暗号化
block = "AAAAAAAAAAAAAAAA"  # ちょうど16バイト

cipher_ecb.padding = 0  # パディングなし（ちょうど16バイトなので）
enc1 = cipher_ecb.update(block)

cipher_ecb2 = OpenSSL::Cipher::AES128.new(:ECB)
cipher_ecb2.encrypt
cipher_ecb2.key = ecb_key
cipher_ecb2.padding = 0
enc2 = cipher_ecb2.update(block)

puts "同じブロック \"#{block}\" をECBで2回暗号化:"
puts "  1回目: #{enc1.unpack1('H*')}"
puts "  2回目: #{enc2.unpack1('H*')}"
puts "  一致？ #{enc1 == enc2 ? 'YES → パターンがバレる！' : 'NO'}"
puts

# =============================================================================
puts "=== まとめ ==="
puts

puts <<~TEXT
AESのポイント:
  1. 置換(SubBytes) + シフト(ShiftRows) + 混合(MixColumns) + XOR(AddRoundKey)
  2. これを10〜14ラウンド繰り返して徹底的に混ぜる
  3. 04で学んだXOR暗号の超進化版

XOR暗号との違い:
  XOR暗号: XORだけ → 線形 → 解析可能
  AES:     XOR + 非線形置換 + 拡散 → 解析不可能

モードの重要性:
  ECB → 同じ平文が同じ暗号文（危険）
  CBC → 前のブロックが影響（安全）

現在の使われ方:
  - HTTPS/TLS: 通信の暗号化
  - ファイル暗号化: ZIP, disk encryption
  - VPN: トンネル通信の暗号化
  - ほぼ全ての暗号通信でAESが使われている！
TEXT
