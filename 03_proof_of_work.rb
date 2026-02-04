# =============================================================================
# Proof of Work（作業証明）を理解する
#
# ハッシュ関数の「一方向性」を利用した仕組み。
# ビットコインのマイニングの基礎となる概念です。
# =============================================================================

require 'digest'

puts "=== Proof of Workとは？ ==="
puts
puts <<~TEXT
問題: 「ハッシュ値が特定の条件を満たす入力を見つけよ」

例: SHA-256のハッシュ値が "0000" で始まる入力を探せ

なぜ難しい？
  - ハッシュは一方向（出力から入力を逆算できない）
  - 「当てずっぽう」で試すしかない
  - 条件が厳しいほど、見つけるのに時間がかかる

これが「作業（計算）した証明」になる！
TEXT
puts

# =============================================================================
puts "=== ステップ1: 最もシンプルなPoW ==="
puts

# -----------------------------------------------------------------------------
# 基本的なProof of Work
#
# 仕組み:
#   1. 元のデータに「ナンス（nonce）」という数値を付け加える
#   2. そのハッシュを計算
#   3. 条件を満たすまでナンスを1ずつ増やして繰り返す
#
# ナンス（nonce）とは:
#   "number used once" の略
#   ハッシュ値を変えるために使い捨てる数値
# -----------------------------------------------------------------------------

def simple_pow(data, difficulty)
  # difficulty = 先頭に必要な"0"の数
  target = "0" * difficulty
  nonce = 0

  loop do
    # データ + ナンスを連結してハッシュ化
    input = "#{data}#{nonce}"
    hash = Digest::SHA256.hexdigest(input)

    # 先頭がtarget（例: "00"）で始まるかチェック
    if hash.start_with?(target)
      return { nonce: nonce, hash: hash, input: input }
    end

    nonce += 1
  end
end

puts "データ: 'hello' のハッシュ値が '0' で始まるナンスを探す"
puts

result = simple_pow("hello", 1)
puts "見つかった！"
puts "  ナンス: #{result[:nonce]}"
puts "  入力:   #{result[:input]}"
puts "  ハッシュ: #{result[:hash]}"
puts

# =============================================================================
puts "=== ステップ2: 難易度を上げてみる ==="
puts

# -----------------------------------------------------------------------------
# 難易度（difficulty）の影響
#
# 先頭の"0"が1つ増えるごとに:
#   - 見つかる確率が1/16になる（16進数だから）
#   - 平均して16倍の試行が必要
#
# 例:
#   difficulty=1 ("0"で始まる)  → 平均16回
#   difficulty=2 ("00"で始まる) → 平均256回
#   difficulty=3 ("000"で始まる) → 平均4096回
#   difficulty=4 ("0000"で始まる) → 平均65536回
# -----------------------------------------------------------------------------

puts "難易度を1〜4まで変えて、必要な試行回数を比較:"
puts

[1, 2, 3, 4].each do |diff|
  start_time = Time.now
  result = simple_pow("hello", diff)
  elapsed = Time.now - start_time

  puts "難易度#{diff}（#{"0" * diff}で始まる）:"
  puts "  ナンス: #{result[:nonce]}（#{result[:nonce] + 1}回試行）"
  puts "  時間: #{(elapsed * 1000).round(2)}ms"
  puts "  ハッシュ: #{result[:hash][0..15]}..."
  puts
end

# =============================================================================
puts "=== ステップ3: なぜこれが「証明」になる？ ==="
puts

puts <<~TEXT
重要なポイント:

1. 見つけるのは大変（何万回も計算が必要）
2. 検証は一瞬（1回のハッシュ計算だけ）

この「非対称性」がProof of Workの本質！

例: 難易度4のナンスを見つけるのに65536回かかっても、
    検証は「hello + ナンス」を1回ハッシュするだけ。
TEXT
puts

# 検証のデモ
puts "--- 検証のデモ ---"
result = simple_pow("hello", 4)
puts "マイナーが見つけた: ナンス=#{result[:nonce]}"
puts

puts "検証者の作業:"
verify_input = "hello#{result[:nonce]}"
verify_hash = Digest::SHA256.hexdigest(verify_input)
puts "  入力: #{verify_input}"
puts "  ハッシュ: #{verify_hash}"
puts "  先頭4文字が0000? → #{verify_hash.start_with?("0000") ? "OK!" : "NG"}"
puts

# =============================================================================
puts "=== ステップ4: ビットコインのマイニング（概念） ==="
puts

puts <<~TEXT
ビットコインのブロックに含まれるもの:
  - 前のブロックのハッシュ
  - トランザクション（取引）のリスト
  - タイムスタンプ
  - ナンス ← これを探す！

マイナーの仕事:
  1. ブロックデータ + ナンスのハッシュを計算
  2. 難易度条件を満たすナンスを見つける
  3. 見つけたら報酬（ビットコイン）をもらえる

難易度の自動調整:
  - 約10分で1ブロック見つかるように調整される
  - マイナーが増える → 難易度UP
  - マイナーが減る → 難易度DOWN
TEXT
puts

# =============================================================================
puts "=== ステップ5: 簡易ブロックチェーン体験 ==="
puts

# -----------------------------------------------------------------------------
# ブロックの構造（簡易版）
#
# 各ブロックが「前のブロックのハッシュ」を含むことで、
# チェーン（鎖）のようにつながる。
#
# 改ざんするとどうなる？
#   → そのブロックのハッシュが変わる
#   → 次のブロックの「前のハッシュ」と合わなくなる
#   → 全部やり直しが必要（膨大な計算）
# -----------------------------------------------------------------------------

class Block
  attr_reader :index, :data, :previous_hash, :nonce, :hash

  def initialize(index, data, previous_hash)
    @index = index
    @data = data
    @previous_hash = previous_hash
    @nonce, @hash = mine(difficulty: 3)
  end

  def mine(difficulty:)
    target = "0" * difficulty
    nonce = 0

    loop do
      hash = calculate_hash(nonce)
      if hash.start_with?(target)
        return [nonce, hash]
      end
      nonce += 1
    end
  end

  def calculate_hash(nonce)
    content = "#{@index}#{@data}#{@previous_hash}#{nonce}"
    Digest::SHA256.hexdigest(content)
  end
end

puts "3つのブロックをマイニング（難易度3）..."
puts

# ジェネシスブロック（最初のブロック）
genesis = Block.new(0, "Genesis Block", "0" * 64)
puts "ブロック0（Genesis）:"
puts "  データ: #{genesis.data}"
puts "  ナンス: #{genesis.nonce}"
puts "  ハッシュ: #{genesis.hash[0..20]}..."
puts

# 2番目のブロック
block1 = Block.new(1, "Alice -> Bob: 10 BTC", genesis.hash)
puts "ブロック1:"
puts "  データ: #{block1.data}"
puts "  前ハッシュ: #{block1.previous_hash[0..20]}..."
puts "  ナンス: #{block1.nonce}"
puts "  ハッシュ: #{block1.hash[0..20]}..."
puts

# 3番目のブロック
block2 = Block.new(2, "Bob -> Charlie: 5 BTC", block1.hash)
puts "ブロック2:"
puts "  データ: #{block2.data}"
puts "  前ハッシュ: #{block2.previous_hash[0..20]}..."
puts "  ナンス: #{block2.nonce}"
puts "  ハッシュ: #{block2.hash[0..20]}..."
puts

puts <<~TEXT
--- チェーンの特徴 ---
各ブロックが前のブロックのハッシュを含んでいる。
もしブロック1のデータを改ざんすると：
  → ブロック1のハッシュが変わる
  → ブロック2の「前ハッシュ」と一致しなくなる
  → ブロック2も再マイニングが必要
  → 以降の全ブロックも...

だから改ざんは（実質的に）不可能！
TEXT
