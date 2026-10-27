# STATUS — PG security
更新: 2026-10-27 23:00

## 目的（1行）
仕事のために、脆弱性・セキュリティ事件の情報を複数の情報源から自動で集め、1 つの Web ページで整理して見られるようにする（最終的には誰でも見られる形で公開）。

## 今の状態
- 2026-10-27 に試作版（モックアップ）ができた。`python collect.py` で取得し、`site/index.html` を作る（標準ライブラリだけで動く）。
- 情報源（7 + 補助 1）: IPA 重要なセキュリティ情報、JPCERT/CC（注意喚起・Weekly Report）、JVN、CISA KEV、Microsoft（Security Update Guide）、Security NEXT、piyolog、補助に FIRST EPSS（悪用予測）。
- JVN iPedia / MyJVN API は 2026-10-27 時点で提供元が全面停止中（再開時期未定）のため未接続。
- 同じ話題は CVE 番号・製品名・脆弱性の通称でまとめて 1 枚のカードにする（例: PHP2Shell は 8 件の情報源を 1 枚に）。
- 重要度は 3 段階（緊急: IPA・JPCERT の注意喚起か悪用確認済み／注意: JVN・Microsoft・piyolog／参考: ニュース）。
- CISA と Microsoft の英語の題名は、脆弱性の種類を辞書で日本語にしている（文章の要約はまだ）。
- Microsoft は件数が多い（14 日で約 1,400 件）ので、他の情報源と重ならない分は 1 枚のまとめカードにしている。

## 止まっている点・ユーザーの判断待ち
- 2026-10-27 ユーザーの判断: 公開は A 案（GitHub Pages、公開リポジトリ `user551030-bit/security-board`）。対象は全製品の脆弱性（製品での絞り込みはしない）。
- 公開用の準備（ニュースサイトの説明文を外す・注意書き・1 時間ごとの自動更新 `.github/workflows/update.yml`）と、最初の git コミットは済んだ。
- GitHub のリポジトリ作成と Pages の有効化が未完了。保存済みの GitHub のログイン情報をプログラムから使う操作が、自動の安全確認で止められた。ユーザーの許可待ち。

## 次にやること
- 英語の情報と各カードの要約を AI で日本語にする（公開版では他サイトの説明文の転載をやめ、自前の要約に置き換える）。
- 情報源の追加候補: 国家サイバー統括室（旧 NISC）、警察庁、主要メーカー（Apple・Google Chrome・Cisco・Fortinet など）、GitHub Security Advisories。
- 製品名での突き合わせの精度を上げる（今はルールベース）。

## 管理者への連絡
- なし
