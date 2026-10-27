# セキュリティ情報ボード

脆弱性・セキュリティ事件の情報を複数の情報源から自動で集め、1 ページに整理して表示する。
GitHub Actions が 1 時間ごとに `collect.py` を実行し、GitHub Pages に公開する。

## 情報源

| 情報源 | 内容 |
|---|---|
| IPA 重要なセキュリティ情報 | 緊急対策情報・注意喚起 |
| JPCERT/CC | 注意喚起・Weekly Report |
| JVN | 国内外製品の脆弱性情報 |
| CISA KEV | 悪用が確認された脆弱性の一覧（米国） |
| Microsoft Security Update Guide | Microsoft 製品の脆弱性 |
| Security NEXT | セキュリティニュース |
| piyolog | 国内インシデントのまとめ |
| FIRST EPSS | 悪用予測スコア（補助） |

## 手元で動かす

```
python collect.py          # site/index.html ができる（標準ライブラリのみ）
python collect.py --days 7 # 期間を変える
```

## ファイル

- `collect.py` — 取得・まとめ・重要度づけ・ページ生成
- `template.html` — ページのひな形（データは生成時に埋め込む）
- `.github/workflows/update.yml` — 1 時間ごとの更新と公開
- `STATUS.md` — 進み具合（管理者への報告）
