# =============================================================================
# XOR暗号を理解する
#
# 02で学んだXOR（排他的論理和）を使った暗号化。
# 「暗号化と復号が同じ操作」という不思議な性質を体験します。
# =============================================================================

puts "=== XOR暗号の核心 ==="
puts

# -----------------------------------------------------------------------------
# XORの重要な性質（復習）
#
#   A ^ B ^ B = A （BでXORを2回やると元に戻る）
#
# これが暗号に使える理由:
#   平文 ^ 鍵 = 暗号文
#   暗号文 ^ 鍵 = 平文    ← 同じ鍵でもう一度XORすれば復号！
# -----------------------------------------------------------------------------

puts "XORの「元に戻る」性質:"
value = 42
key = 123
encrypted = value ^ key
decrypted = encrypted ^ key
puts "  元の値:   #{value}"
puts "  鍵:       #{key}"
puts "  暗号化:   #{value} ^ #{key} = #{encrypted}"
puts "  復号:     #{encrypted} ^ #{key} = #{decrypted}"
puts "  元に戻った！"
puts

# =============================================================================
puts "=== ステップ1: 1バイトXOR暗号 ==="
puts

# -----------------------------------------------------------------------------
# 最もシンプルなXOR暗号
#
# 仕組み:
#   - 1バイト（0〜255）の鍵を用意
#   - 平文の各バイトと鍵をXOR
#
# 暗号化も復号も同じ関数でOK（XORの性質のおかげ）
# -----------------------------------------------------------------------------

def xor_single(text, key)
  text.bytes.map { |byte| (byte ^ key).chr }.join
end

message = "Hello!"
key = 0x5A  # 鍵: 90（16進数で5A）

encrypted = xor_single(message, key)
decrypted = xor_single(encrypted, key)

puts "平文:     #{message}"
puts "鍵:       0x5A (#{key})"
puts "暗号化:   #{encrypted.inspect}"
puts "復号:     #{decrypted}"
puts
puts "暗号化と復号が同じ関数！（xor_singleを2回呼ぶだけ）"
puts

# バイト単位で何が起きているか
puts "--- バイト単位の様子 ---"
message.bytes.each_with_index do |byte, i|
  enc = byte ^ key
  dec = enc ^ key
  puts "  '#{byte.chr}' (#{byte}) ^ #{key} = #{enc} → #{enc} ^ #{key} = #{dec} ('#{dec.chr}')"
end
puts

# =============================================================================
puts "=== ステップ2: 1バイト鍵の弱点 ==="
puts

# -----------------------------------------------------------------------------
# 1バイト鍵の問題点
#
# 鍵が0〜255の256通りしかない
# → 全部試せば必ず解読できる（ブルートフォース攻撃）
# -----------------------------------------------------------------------------

secret = xor_single("Secret Message", 0xAB)
puts "暗号文を傍受した！: #{secret.inspect}"
puts "鍵は256通りしかないので全部試す..."
puts

(0..255).each do |try_key|
  result = xor_single(secret, try_key)
  # 全部ASCIIの表示可能文字なら正解の可能性が高い
  if result.bytes.all? { |b| b.between?(32, 126) }
    puts "  鍵=0x#{try_key.to_s(16).upcase}: #{result}"
  end
end
puts
puts "→ 鍵が短いと簡単に解読されてしまう！"
puts

# =============================================================================
puts "=== ステップ3: 複数バイト鍵（繰り返しキー暗号） ==="
puts

# -----------------------------------------------------------------------------
# 鍵を長くして強化
#
# 仕組み:
#   平文:   H  e  l  l  o  ,     W  o  r  l  d
#   鍵:     K  E  Y  K  E  Y  K  E  Y  K  E  Y  ← 繰り返す
#   暗号文: (各文字をXOR)
#
# 鍵が3文字なら256^3 = 16,777,216通り
# → ブルートフォースがかなり難しくなる
# -----------------------------------------------------------------------------

def xor_repeat_key(text, key)
  text.bytes.map.with_index { |byte, i|
    # key[i % key.length] で鍵を繰り返し使う
    # 例: 鍵"KEY"(3文字)に対して i=0→K, i=1→E, i=2→Y, i=3→K, ...
    (byte ^ key.bytes[i % key.length]).chr
  }.join
end

message = "Hello, World! This is XOR cipher."
key = "KEY"

encrypted = xor_repeat_key(message, key)
decrypted = xor_repeat_key(encrypted, key)

puts "平文:     #{message}"
puts "鍵:       #{key}"
puts "暗号化:   #{encrypted.bytes.map { |b| b.to_s(16).rjust(2, '0') }.join(' ')}"
puts "復号:     #{decrypted}"
puts

# 鍵がどう繰り返されるか可視化
puts "--- 鍵の繰り返しの様子 ---"
message.chars.each_with_index do |c, i|
  k = key[i % key.length]
  puts "  '#{c}' ^ '#{k}' = 0x#{(c.ord ^ k.ord).to_s(16).rjust(2, '0')}"
end
puts

# =============================================================================
puts "=== ステップ4: ワンタイムパッド（究極のXOR暗号） ==="
puts

# -----------------------------------------------------------------------------
# ワンタイムパッド（One-Time Pad）
#
# 条件:
#   1. 鍵が平文と同じ長さ
#   2. 鍵が完全にランダム
#   3. 鍵を一度しか使わない
#
# この3条件を満たすと「情報理論的に解読不可能」
# → どんなコンピュータでも、どんな時間をかけても絶対に解けない
#
# なぜ？→ 暗号文から考えられる平文の候補が全て等しい確率で存在するため
# "Hello"かもしれないし"ZZZZZ"かもしれない。区別する手がかりがゼロ。
# -----------------------------------------------------------------------------

message = "Hello"

# 平文と同じ長さのランダムな鍵を生成
random_key = Array.new(message.length) { rand(0..255) }

# 暗号化
encrypted_bytes = message.bytes.zip(random_key).map { |m, k| m ^ k }

# 復号
decrypted = encrypted_bytes.zip(random_key).map { |e, k| (e ^ k).chr }.join

puts "平文:       #{message}"
puts "ランダム鍵: #{random_key.map { |b| b.to_s(16).rjust(2, '0') }.join(' ')}"
puts "暗号文:     #{encrypted_bytes.map { |b| b.to_s(16).rjust(2, '0') }.join(' ')}"
puts "復号:       #{decrypted}"
puts

puts <<~TEXT
ワンタイムパッドは理論上最強。でも実用的じゃない:
  - 平文と同じ長さの鍵が必要（巨大なファイルなら巨大な鍵）
  - 鍵を安全に共有する方法が必要（それ自体が難問）
  - 鍵を使い回すと一気に弱くなる
TEXT
puts

# =============================================================================
puts "=== ステップ5: 鍵の使い回しが危険な理由 ==="
puts

# -----------------------------------------------------------------------------
# 同じ鍵で2つのメッセージを暗号化するとどうなる？
#
#   暗号文1 = 平文1 ^ 鍵
#   暗号文2 = 平文2 ^ 鍵
#
#   暗号文1 ^ 暗号文2 = (平文1 ^ 鍵) ^ (平文2 ^ 鍵)
#                      = 平文1 ^ 平文2  ← 鍵が消える！
#
# 攻撃者は鍵を知らなくても、2つの平文のXORを得られてしまう
# → 片方の内容を推測できれば、もう片方も分かる
# -----------------------------------------------------------------------------

key = "SECRETKEY"
msg1 = "Attack!!!"
msg2 = "Retreat!!"

enc1 = xor_repeat_key(msg1, key)
enc2 = xor_repeat_key(msg2, key)

# 暗号文同士をXORすると...
xored = enc1.bytes.zip(enc2.bytes).map { |a, b| a ^ b }

puts "メッセージ1: #{msg1}"
puts "メッセージ2: #{msg2}"
puts
puts "同じ鍵で暗号化して、暗号文同士をXORすると:"
puts "  暗号文1 ^ 暗号文2 = #{xored.inspect}"
puts
puts "これは平文同士のXORと同じ:"
plain_xored = msg1.bytes.zip(msg2.bytes).map { |a, b| a ^ b }
puts "  平文1 ^ 平文2     = #{plain_xored.inspect}"
puts
puts "一致した！ → 鍵が完全に消えてしまう"
puts "→ だから鍵の使い回しは絶対ダメ！"
puts

# =============================================================================
puts "=== まとめ: なぜAESが必要か ==="
puts

puts <<~TEXT
XOR暗号の学び:
  ✓ XORだけで暗号化・復号ができる
  ✓ ワンタイムパッドは理論上最強

でも現実には:
  ✗ 短い鍵はブルートフォースで破られる
  ✗ 鍵の使い回しは致命的
  ✗ ワンタイムパッドは鍵の管理が非現実的

→ 短い鍵でも安全に暗号化できる仕組みが必要
→ それがAES（Advanced Encryption Standard）！
  - 128/192/256ビットの鍵で安全
  - XOR + シフト + 置換を複雑に組み合わせる
  - ハッシュ関数と似た発想（混ぜて混ぜて混ぜまくる）
TEXT
