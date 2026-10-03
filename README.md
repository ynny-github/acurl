# acurl

AI agent 用の HTTP client CLI。宛先のアクセス制御はせず、リクエストの方法と送受信の内容で制御する。

- 書き込み系メソッド（GET/HEAD 以外）は、設定で許可した host + method だけ通す
- 送信内容に既知のトークン形式（AWS / GitHub / `sk-` / Slack / 秘密鍵）があれば拒否する
- 実行形式は常に拒否する。アーカイブとバイナリは、テキストに変換するか許可した場合だけ通す
- HTML は hidden 要素・script・コメントを除去してから markitdown で Markdown に変換する
- 不可視文字や制御文字を除去し、出力を nonce 付きのマーカー（spotlighting）で囲む

## インストール

[mise](https://mise.jdx.dev/) で GitHub Releases のビルド済みバイナリを入れる（Linux x86_64/aarch64、macOS aarch64）。

```sh
mise use -g github:ynny-github/acurl
mise use -g pipx:markitdown   # 変換に使う
acurl doctor                  # 設定とフィルターを確認する
```

ソースからビルドする場合は `cargo install --path .`。

変換には [markitdown](https://github.com/microsoft/markitdown) を使う。フィルターは acurl を実行した環境（PATH など）を引き継いで実行される。`acurl doctor` で、現在の設定とフィルターが使える状態かを確認できる。

インジェクション検知などのセキュリティ用フィルターは、agent が PATH を書き換えて差し替えられないよう、`[[filter]]` に絶対パスで書く。

## 使い方

curl のサブセット（`-X -H -d -o -i -L`）。未対応のフラグはエラーになる。

```sh
acurl https://example.com/
acurl -i -L https://example.com/docs
acurl -X POST -H 'Content-Type: application/json' -d @body.json https://api.example.com/items
acurl -o report.md https://example.com/report.pdf    # 変換後のテキストを保存（allow_binary の形式は生のまま）
```

| 終了コード | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 通信エラー、HTTP 4xx/5xx（本文は出力する） |
| 2 | ポリシーによる拒否（stderr: `acurl: denied: <理由> (<許可できる設定項目>)`） |
| 64 | 不正な引数 |

## 設定（`.acurl.toml`）

リポジトリに置き、commit して共有できる。カレントディレクトリから親へ探索する。agent が書き換えられないよう、**root が承認したハッシュと一致する場合だけ**読み込む。未承認または変更済みの場合は、最も厳しいデフォルトで動く。

```sh
sudo acurl trust   # 内容を表示し、確認後に sha256 を /etc/acurl/trusted に追記する
```

```toml
# トップレベルのキーはテーブルより前に書く
allow_binary = ["image/png"]      # 生で通す MIME。実行形式・アーカイブは書いても拒否
max_response_bytes = 10_000_000
max_output_bytes = 200_000

[[allow_write]]
host = "api.example.com"
methods = ["POST", "PUT"]

# 指定するとデフォルト（markitdown）を置き換える。上から順にパイプでつなぐ。
# 本文は stdin で渡され、0 以外で終了すると拒否になる。
[[filter]]
match = ["text/html", "application/pdf", "image/*"]
command = ["/home/me/.local/bin/markitdown", "-m", "{mime}"]
```

## Claude Code で使う

`.claude/settings.json` で WebFetch を禁止する。

```json
{
  "permissions": {
    "deny": ["WebFetch"]
  }
}
```

agent 向けの説明文を CLAUDE.md に追記する。

```sh
acurl prompt >> CLAUDE.md
```

## nono と併用する前提

acurl は agent と同じ sandbox の中で動く。次の2点は nono 側で担う。

- **秘密情報**：credential proxy（`--credential`）と filesystem の制限で、秘密情報を sandbox の外に置く。acurl はトークン形式のパターン検知しか行わない。
- **acurl を経由しない通信**：`curl` / `wget` / スクリプトからの直接通信は、nono のネットワーク制御で塞ぐ。acurl の制御は、agent が acurl 以外で外部と通信できない場合にだけ強制力を持つ。

## ライセンス

[MIT](LICENSE)
