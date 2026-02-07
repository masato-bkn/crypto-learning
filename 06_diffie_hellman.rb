# =============================================================================
# Diffie-Hellman鍵交換を理解する
#
# 「盗聴されている通信路で、共通の秘密を作る」という魔法のような仕組み。
# 1976年にWhitfield DiffieとMartin Hellmanが発表。
# RSA（1977年）より前に公開鍵暗号の概念を世に出した先駆者。
# =============================================================================

puts "=== Diffie-Hellman鍵交換とは？ ==="
puts

puts <<~TEXT
問題:
  AliceとBobが暗号通信したい
  でも盗聴者Eve（Eavesdropper）がいる
  → AESの鍵をどうやって安全に共有する？

RSAの方法:
  Bobの公開鍵で鍵を暗号化して送る

Diffie-Hellmanの方法:
  お互いの「公開情報」を交換するだけで、
  共通の秘密の鍵が生まれる（鍵そのものは送らない！）
TEXT
puts

# =============================================================================
puts "=== ステップ1: 色の混合で直感的に理解 ==="
puts

puts <<~TEXT
絵の具のアナロジー:

  1. 共通の色を決める（黄色）    ← 公開情報（盗聴者も知ってる）
  2. Alice: 秘密の色を混ぜる（+赤）→ オレンジを送る
     Bob:   秘密の色を混ぜる（+青）→ 緑を送る
  3. Alice: 受け取った緑 + 自分の赤  → 茶色
     Bob:   受け取ったオレンジ + 自分の青 → 茶色

  → 同じ「茶色」ができる！

  盗聴者Eveが知っているのは:
    黄色、オレンジ、緑 だけ
    → 混合色から元の秘密の色を分離するのは困難
TEXT
puts

# =============================================================================
puts "=== ステップ2: 数学で実現する ==="
puts

# -----------------------------------------------------------------------------
# Diffie-Hellmanの仕組み
#
# 使う演算: べき乗のmod（離散対数問題）
#
# g^a mod p = A  ← aからAを求めるのは簡単
# Aからaを求めるのは非常に困難（離散対数問題）
#
# これがRSAの「素因数分解の困難さ」に対応する
# -----------------------------------------------------------------------------

puts "準備: 公開パラメータを決める"
puts

# p: 大きな素数（実際は2048ビット以上）
# g: 生成元（primitive root）
p_val = 23  # 小さな素数で実験
g = 5       # 生成元

puts "  p = #{p_val}（素数）← 公開"
puts "  g = #{g}（生成元）← 公開"
puts

# -----------------------------------------------------------------------------
# 鍵交換の手順
#
# 1. Alice: 秘密の数 a を選ぶ → A = g^a mod p を計算して送る
# 2. Bob:   秘密の数 b を選ぶ → B = g^b mod p を計算して送る
# 3. Alice: 共有鍵 = B^a mod p を計算
# 4. Bob:   共有鍵 = A^b mod p を計算
#
# なぜ同じ値になる？
#   B^a mod p = (g^b)^a mod p = g^(ab) mod p
#   A^b mod p = (g^a)^b mod p = g^(ab) mod p
#   → 両方 g^(ab) mod p になる！
# -----------------------------------------------------------------------------

puts "=== 鍵交換スタート ==="
puts

# Aliceの秘密
a = 6  # Aliceの秘密の数（実際はランダムな巨大数）
big_a = g.pow(a, p_val)  # g^a mod p
puts "Alice:"
puts "  秘密の数 a = #{a}  ← 誰にも教えない"
puts "  公開値   A = g^a mod p = #{g}^#{a} mod #{p_val} = #{big_a}  ← Bobに送る"
puts

# Bobの秘密
b = 15  # Bobの秘密の数
big_b = g.pow(b, p_val)  # g^b mod p
puts "Bob:"
puts "  秘密の数 b = #{b}  ← 誰にも教えない"
puts "  公開値   B = g^b mod p = #{g}^#{b} mod #{p_val} = #{big_b}  ← Aliceに送る"
puts

# 共有鍵の計算
alice_shared = big_b.pow(a, p_val)  # B^a mod p
bob_shared = big_a.pow(b, p_val)    # A^b mod p

puts "=== 共有鍵の計算 ==="
puts
puts "Alice: B^a mod p = #{big_b}^#{a} mod #{p_val} = #{alice_shared}"
puts "Bob:   A^b mod p = #{big_a}^#{b} mod #{p_val} = #{bob_shared}"
puts
puts "一致した！ 共有鍵 = #{alice_shared}"
puts

# =============================================================================
puts "=== ステップ3: 盗聴者Eveの視点 ==="
puts

# -----------------------------------------------------------------------------
# Eveが知っている情報
#
#   p = 23, g = 5（公開パラメータ）
#   A = 8（Aliceの公開値）
#   B = 19（Bobの公開値）
#
# Eveが共有鍵を知るには:
#   A = g^a mod p から a を求める（離散対数問題）
#   → 小さい数なら総当たりで解けるが、巨大な数では計算上不可能
# -----------------------------------------------------------------------------

puts "Eveが知っている情報:"
puts "  p=#{p_val}, g=#{g}, A=#{big_a}, B=#{big_b}"
puts
puts "Eveの攻撃: aを総当たりで探す"

(1..p_val - 1).each do |try_a|
  if g.pow(try_a, p_val) == big_a
    puts "  a=#{try_a} で A=#{big_a} になった！"
    eve_shared = big_b.pow(try_a, p_val)
    puts "  → 共有鍵 = #{eve_shared}"
    break
  end
end

puts
puts "p=#{p_val} は小さいのですぐ見つかる"
puts "でも p が2048ビット（617桁）なら？ → 実質不可能！"
puts

# =============================================================================
puts "=== ステップ4: もう少し大きな数で体験 ==="
puts

# より現実的なサイズ（それでもまだ小さい）
p_big = 7919  # 素数
g_big = 7     # 生成元

a_secret = rand(2..p_big - 2)
b_secret = rand(2..p_big - 2)

a_public = g_big.pow(a_secret, p_big)
b_public = g_big.pow(b_secret, p_big)

alice_key = b_public.pow(a_secret, p_big)
bob_key = a_public.pow(b_secret, p_big)

puts "パラメータ: p=#{p_big}, g=#{g_big}"
puts
puts "Alice: 秘密=#{a_secret}, 公開値=#{a_public}"
puts "Bob:   秘密=#{b_secret}, 公開値=#{b_public}"
puts
puts "Alice計算の共有鍵: #{alice_key}"
puts "Bob計算の共有鍵:   #{bob_key}"
puts "一致？ #{alice_key == bob_key ? 'OK！' : 'NG'}"
puts

# =============================================================================
puts "=== ステップ5: DHの弱点と対策 ==="
puts

puts <<~TEXT
DHの弱点: 中間者攻撃（Man-in-the-Middle）

  Alice ←→ Eve ←→ Bob

  1. EveがAliceとBobの間に割り込む
  2. Alice-Eve間で鍵交換、Eve-Bob間で鍵交換
  3. Eveが2つの鍵を持ち、中継しながら盗み読み

対策:
  → 公開値に「デジタル署名」をつける（RSAなどで）
  → 相手が本物であることを証明する
  → これが「認証付きDH」（TLSで使われる方式）
TEXT
puts

# =============================================================================
puts "=== まとめ ==="
puts

puts <<~TEXT
Diffie-Hellman鍵交換:
  1. 公開情報だけを交換して共通の秘密鍵を作る
  2. 離散対数問題の困難さが安全性の根拠
  3. RSAとは別のアプローチで鍵配送問題を解決

TLSでの使われ方:
  DH鍵交換でAESの鍵を共有
  → その鍵でAES暗号化
  → RSAのデジタル署名で認証

次に学ぶAESと組み合わせると:
  DH → 「鍵を安全に共有」
  AES → 「その鍵でデータを暗号化」
TEXT
