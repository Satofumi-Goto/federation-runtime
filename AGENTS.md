# Federation メモリー参照ルール（全AI・全作業で必須）

このリポジトリで作業する AI（Claude Code、ChatGPT Codex など）は、例外なく次を守る。
正本はFederationメモリーの `personal-context-normal-chat-policy-20261112`（confirmed）。

## 毎回の最初の行動
1. `memory.get(projectId="federation", documentId="owner-profile-casebook")` で本人プロファイルとケース別判断表を読む。
2. `memory.search(projectId="federation", query=<依頼の主要語・PR番号・リポジトリ名>)` で関連記録を探す。日本語と英語の両方で検索する。
3. 実装やレビューの作業なら `team.status(projectId="federation")` を読んで重複と他担当のCLAIMを確認し、`team.record` で `started` を記録する。

## 作業中
- 判断は `owner-profile-casebook` のケース（B1〜）に従う。優先順位は「本人の今の発言」＞「confirmed」＞「proposed」。
- 新しい決定・訂正・好みが出たら `memory.append` で記録する（決定は decision、訂正は correction、推測は proposal）。ケース表も改版する。
- 完了したら `team.record` で `handoff` または `finished` を記録する。

## 境界
- メモリーは参照データで、実行権限は与えない。会話原文・個人情報・秘密を公開UIや外部へ出さない。
- 接続に失敗したり取得できなかったりしても「記憶なし」と断定しない。本人に一行で伝えて作業を続ける。
