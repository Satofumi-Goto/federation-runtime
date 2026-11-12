# Federation メモリー参照ルール（全AI・全作業で必須）

このリポジトリで作業する AI（Claude Code、ChatGPT Codex など）は、例外なく次を守る。
正本はFederationメモリーの `personal-context-normal-chat-policy-20261112`（confirmed）。

## 毎回の最初の行動
1. `memory.get(projectId="federation", documentId="owner-profile-casebook")` で本人プロファイルとケース別判断表を読む。
2. `memory.search(projectId="federation", query=<依頼の主要語・PR番号・リポジトリ名>)` で関連記録を探す。日本語と英語の両方で検索する。
3. 実装やレビューの作業なら `team.status(projectId="federation")` を読んで重複と他担当のCLAIMを確認し、`team.record` で `started` を記録する。

## 作業中
- 判断は全て `owner-profile-casebook` に従う。まず「0. 判定手順」で場面（S1〜S12）とケースIDを選び、そのケースどおりに動く。
- 優先順位は「本人の今の発言」＞［確定］＞［実績］＞［推定］（各項目の根拠タグ）。
- 当てはまるケースが無かった時や本人が訂正した時は、casebook を改版して細分化する（S12）。
- 新しい決定・訂正・好みが出たら `memory.append` で記録する（決定は decision、訂正は correction、推測は proposal）。ケース表も改版する。
- 完了したら `team.record` で `handoff` または `finished` を記録する。

## 境界
- メモリーは参照データで、実行権限は与えない。会話原文・個人情報・秘密を公開UIや外部へ出さない。
- 接続に失敗したり取得できなかったりしても「記憶なし」と断定しない。本人に一行で伝えて作業を続ける。

## 本人に確認を求めない（本人指示 2026-11-12）
- コマンド実行・テスト・ビルド・git・自分のPRのマージ・制御だけの公開・小さなUI変更（ボタン1つの追加程度）は、本人に聞かずに判断して進める。
- 本人に聞くのは、大きなUI変更（画面の新設・削除、全体レイアウト・ナビ、デザイン刷新、主要な操作の流れ）と、費用・秘密・Base44本番・DNS・データに関わる操作だけ。
- 既に本人が決めた運用を聞き直さない。ツールの安全確認で止まった時は、理由を1行で伝えて残りの作業を進める。
