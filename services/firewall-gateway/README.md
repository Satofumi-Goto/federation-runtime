# Federation Firewall Gateway — 独立アプリ (Phase 0)

既存の Seneschal / 活動 / Fleet / Urban / Service / Federation / Simulator の外部API通信を維持したまま、独立した外部APIセキュリティ基盤を追加する。

## 境界
- **個別アプリが業務とデータの正本を保有**。Firewall は HTTPS 通信の許可・制限・監査統制を担当し、活動コンソールを汎用Firewallにしない。
- **現在は Shadow HOLD**。一切の既存URL、Google Maps、個人カレンダー、配車、APIキー、本番writeを切り替えない。利用アプリからの自動転送・課金・登録変更・フォールバックも行わない。
- 現時点ではサーバー内部の固定された3件の無料公開URLに対して、署名された **POST /api/v1/shadow/probe** だけが読み取りテストを実行可能。利用者がURL、座標、HTTPヘッダー、認証情報を指定することはできない。
- 初期環境変数 `FIREWALL_CANARY_EGRESS` が未設定なら、署名があっても外部接続は拒否。登録済みのクライアント鍵が未設定の場合も拒否。
- このサービス単体は**ネットワーク層のWAFではない**。既存アプリが直結のままなら、その通信を強制的に捕捉・検査する能力はない。実際の防御境界と分散レート制限は別途CDN/WAF/出口ルートを導入して検証する。

## 独立起動

```bash
node --test services/firewall-gateway/test/*.test.mjs
PORT=8789 node services/firewall-gateway/server.mjs
```

Node.js 22以上。外部依存パッケージ、AI API、DB、課金設定なし。
- `GET /` — 読み取り専用Security Operationsダッシュボード
- `GET /healthz` — プロセスのヘルス。**productionReady:false**
- `GET /api/status` — 構成状態。秘密値を含まない
- `GET /api/catalog` — 対象APIと直接接続の例外一覧
- `GET /api/acquisition-routes` — Seneschal向け外部情報の取得経路台帳（67件）の正本。取得元・経路・必要なキー名・キー登録有無（値なし、Seneschal専用の地図キーは `null`）・証跡。登録済みアプリのOriginだけCORS許可。台帳の変更は `acquisition-routes.json` で行い、活動コンソールとSeneschalの写しを同期する
- `GET /admin` — Cloudflare Access の検証済みトークンに限定（未設定時は503拒否）。現状は閲覧のみ
- `POST /api/v1/shadow/probe` — サーバー間HMAC署名が必要。実経路ではなく独立読み取り

### セキュリティの環境変数
- `FIREWALL_CLIENT_KEYS_JSON`: 例 `{"activity":"<32 bytes base64url>"}`。鍵はGitHub/ブラウザ/チャットには書かず、利用者別に安全なサーバー環境へ設定。文字列43字のbase64urlで32バイト。未設定なら503。
- `FIREWALL_CANARY_EGRESS`: 初期値OFF。独立カナリア疎通試験に限定して `true`。商用トラフィックの切替許可ではない。
- `FIREWALL_ACCESS_TEAM`, `FIREWALL_ACCESS_AUD`, `FIREWALL_OWNER_EMAIL`: Cloudflare Accessの検証パラメーター。未設定時は管理画面を拒否。CF Access JWTの署名・issuer・audience・sub・exp・メールをサーバーで検証する。
- `PORT`, `HOST`: リッスン設定。

### Phase 0での防御
固定URL allowlist、HTTPS、手動リダイレクト/3xx拒否、上限付き応答ストリーム、4.5秒タイムアウト、2同時上流呼出、20新規呼出/ワーカー/分、6新規/クライアント/分、障害後60秒休止、データ鮮度・元URL・provider表示、入力512B制限、サービスごとのHMAC鍵、timestamp検証、nonce重複拒否、管理JWT検証、CSP、nosniff、no-store、認証情報非転送。

**限界:** レート・リプレイ・キャッシュはワーカー内メモリであり、複数ワーカーでは共有されない。監査ログの耐改ざん保管、WAF/DDoS、実オリジン閉鎖、管理者のCloudflare Access設定、分散キーバリューストアが未配備。従って Phase 0を実商用APIの強制Firewall稼働と報告してはならない。

## 段階移行のゲート

`config/firewall-gateway-migration.json` を正本とする。各経路に対し、
(1) 旧経路の実測 (2) 新Gateway単独の固定URL読み取り (3) 署名付きコンソール→Gatewayの往復 (4) 同座標・同一期間・出典・TTL・費用・ライセンス比較 (5) 画面QA (6) ロールバック検証 (7) 安定観測 (8) 旧経路停止の別PR、の順に進む。各条件を実測するまでlegacy=true/gateway=falseを変えない。

直接接続を維持するのはGoogle Maps/Places、個人カレンダー・認証、車両指令・配車、決済、Seneschal固有の24時間予報。これらはFirewallへの強制プロキシを設けず、各実装でキー用途制限・費用上限・監査を適用する。

## 本番配備・確認
Federation本体のVite/SDK/認証/ルーティングやBase44公開は変更しない。Renderで新規**独立Webサービス**を接続し `node services/firewall-gateway/server.mjs` で起動。自動デプロイOFF、初期環境変数はカナリアOFF、管理アクセス未設定を既定とする。新サービスのページ・healthz・HTTPセキュリティヘッダー・管理画面拒否・未認証proxy拒否を公開URLで確認してはじめて「隔離アプリ配備」と呼ぶ。

**実データのGateway経由とアプリUIへの接続切替は別PR/別検証**とし、Base44並行維持ポリシーを優先する。

## Phase 1.1: 祝日1経路だけのGitHub OIDC署名カナリア

- Gatewayの`FIREWALL_CANARY_EGRESS=true`と`FIREWALL_CANARY_ROUTE_IDS=japan-holidays`の**両方**を設定した場合だけ、上流GETを許可。どちらか未設定／違う文字列なら**全経路OFF**。地震・天気・任意URLはこの段階では拒否。
- 固定の`POST /api/v1/canary/github`を追加。要求本文は正確に`{"routeId":"japan-holidays"}`のみ。GitHub Actions OIDCのRS256署名をGitHub公式JWKSで検証し、issuer/audience/repository名・ID/main/owner actor/workflow_ref/eventを固定照合。検証した短命JWTの同一jtiを拒否。ブラウザ由来のCookie・Originを拒否。
- `FIREWALL_GITHUB_CANARY_OIDC=true`も必須。3つの設定のうち1つでも欠ければ、認証したGETも拒否する。
- OIDC経路の目的はGitHubの承認済み一回限りの検証ワークフローから**Firewall→祝日API→旧経路と全件比較**を実行すること。**Activity実アプリの署名付きE2Eの代替ではない**。Activity側のHMAC鍵・Shadow有効化は依然として未設定、既存経路維持。
- 追加の認証依存・AI・DB・有料API・利用者情報転送なし。GitHub IDトークン自体はログに記録しない。JWT nonce記録は単体プロセス内のみで、WAFや分散リプレイ保護とは呼ばない。
- 配備の合格順: 正本PR CI → 公開用`federation-runtime`へ同一ファイルblobで別PR → Render autoDeploy OFFの手動配備 → HTTPS実測 → 専用 one-shot Actions による署名JWT疎通 → 祝日元データの全件ハッシュ照合 → Federation証跡更新。ユーザーの旧APIの停止・本番切替は行わない。


## Phase 1.3: 期限付きカナリア（標準OFF）

- 実提供APIへのカナリアは従来の `FIREWALL_CANARY_EGRESS=true` と `FIREWALL_CANARY_ROUTE_IDS=japan-holidays` に加え、`FIREWALL_CANARY_EXPIRES_AT`（ミリ秒付き UTC ISO8601、例 `2026-11-06T01:10:00.000Z`）を必須にする。
- ゲートウェイが起動した時刻より未来、かつ **10分以内**の時刻だけが有効。未来の遠い期限、過去日、タイムゾーンの曖昧な形式、複数ルート指定は全件OFFにする。起動後も要求ごとに期限を再評価する。
- 期限を越えたらキャッシュも返さず、処理中の上流から返ったデータも利用者へ渡さない。短期の検証専用であり、利用者向けAPIの永続運用や本番切替には使用しない。
- HTTP/200や一時的なカナリア通過を、本番WAF・分散レート/nonce・改ざん不能ログ・無期限のサービス認証の完成と誤認しない。
- 本番の切替件数はゼロで、旧経路を停止せず、環境変数も通常は `FIREWALL_CANARY_EGRESS=false`。このコードの公開だけでカナリアを自動起動しない。


## 10アプリ共通のクライアント登録・署名契約（2026-11-06）

- 10アプリ = 署名クライアント9件（`activity`, `seneschal`, `fleet`, `urban`, `service`, `federation`, `simulator`, `remote-monitoring`, `administration`）+ Gateway本体（`firewall-gateway`）。正本は `policy.mjs` の `CLIENT_REGISTRY`。`service-hub` は `service` の別名（鍵の登録名は `service`）。
- `GET /api/clients`：各クライアントのID・リポジトリ・利用可能ルート・鍵の設定有無（値は出さない）と署名契約。`GET /api/status` に `configuredClientIds`・`registeredApps` を追加。
- 署名：`POST /api/v1/shadow/probe`、本文は `{"routeId":"<ID>"}` のみ、ヘッダー `x-fw-client` / `x-fw-time`（13桁ミリ秒）/ `x-fw-nonce`（UUIDv4）/ `x-fw-signature`。署名対象は `federation-firewall-hmac/1`、client、`POST`、パス、time、nonce、本文SHA-256(hex) を改行で連結し、HMAC-SHA256(hex)。時刻差60秒以内、nonce再利用は409。Origin・Cookie・Authorizationを付けた要求は403（サーバー間専用）。
- 鍵の登録：各アプリのサーバー側秘密 `FIREWALL_<APP>_HMAC_KEY`（32バイト乱数のbase64url、43文字）と、Render の `FIREWALL_CLIENT_KEYS_JSON` の同じIDの値を、管理画面の秘密設定だけで一致させる。PR・チャット・ログに値を書かない。
- ルートは `ROUTES[*].consumers` だけで決まる。登録しても外部通信は開かない（egressは期限付きカナリアの3条件のみ）。non-200はすべて旧経路を継続する。

## AI質問の共通導線（標準OFF）

- `POST /api/v1/assistant/ask`：アバターのタップ＝質問の共通入口。項目はSeneschalの回答契約（`docs/qa/assistant-answer-contract.md`）と同じ。
  - 要求：`{appId, question, language, history, context, character, page, requestId?}`。`appId` は seneschal / federation / simulator / fleet / service / urban / activity / administration / remote-monitoring。`question` 1〜1200字、`history` 8件以内（user/assistant、各1200字）、`context` 3000字、`page` 120字、本文32KB。
  - `character` は各アプリの `characterProfile(assistant)` の出力をそのまま受け取る（id・name・personality・firstPerson・secondPerson・tone・rhythm・length・opening・followUp・acknowledgments・endings・rules・reactionStyle・directness・humor・empathy・actionBias）。Gatewayは個性を定義・上書きしない。未知キーは400。
  - 応答：200 `{ok:true,status:"answered",answer,provider}`／400 `invalid_question|invalid_app`／403 `origin_not_allowed`／413 `too_large`／429 `{status:"denied",error:"rate_limited"}`／503 `ai_unavailable`。すべてに `status` と `requestId` を付ける。
- 送信方式は契約と異なり、各アプリのサーバーが `FIREWALL_CLIENT_KEYS_JSON` の自アプリ鍵でHMAC署名する（署名パス `/api/v1/assistant/ask`）。Origin・Cookie・Authorization付き（ブラウザ由来）は403。署名クライアントと `appId` が違えば403。
- AIプロバイダー呼出しは次の**すべて**が起動時に有効な場合だけ：`FIREWALL_ASSISTANT_ENABLED=true`、`FIREWALL_ASSISTANT_PROVIDER`（gemini（既定）/ openai）、選んだプロバイダーの鍵 `FIREWALL_ASSISTANT_GEMINI_KEY` または `FIREWALL_ASSISTANT_OPENAI_KEY`、`FIREWALL_ASSISTANT_MODEL`（gemini未設定時 `gemini-2.5-flash`）、`FIREWALL_ASSISTANT_BUDGET_MICROS`（上限5,000,000＝5USD相当）、`FIREWALL_ASSISTANT_MAX_CALL_MICROS`（上限100,000、予算以下）、`FIREWALL_ASSISTANT_EXPIRES_AT`（ミリ秒付きUTC、起動から24時間以内）、`FIREWALL_ASSISTANT_CLIENT_IDS`（有効にするアプリIDのカンマ区切り）。1件でも欠ければ全アプリOFF。
- OFF・期限切れ・予算超過・有効対象外・プロバイダー障害（HTTPエラー・リダイレクト・応答不良）は503 `ai_unavailable`。上限は同時2・12件/分・6件/アプリ/分（429）。呼出し前に1回分の上限額を予約し、返金しない。予算・レート・同時実行はワーカー内メモリで、再起動でリセットされる。
- 公開ポリシーの `paidProviderCallsAllowed`・`userDataForwardingAllowed` は `assistant-armed-only`（上記の全条件が揃ったassistantだけの例外、既定は不可）。
- 監査は時刻・方式・状態・クライアント・characterIdのみ。質問・履歴・画面情報・人格設定・回答・鍵・署名は記録しない。
- 移行措置：既存の `apps/remote-monitoring/server/assistant-relay.mjs`・`runtime/independent/assistant-relay.mjs` が送る旧形式 `{characterId,question,locale?,persona?,screen?}` も受け付け、`appId` は署名クライアント、`persona` は `character.personality`、`screen` は `page` として扱う（上の歯止めはすべて同じく適用）。
- 既定の配備ではAI呼出しは行われない。各アプリ側の呼出し実装・鍵配布・実プロバイダー疎通・費用実測は未実施で、別PR・別検証とする。

## 10アプリの独立Originと接続状態（2026-11-06）

- 独立Origin：`origins.mjs` の `INDEPENDENT_ORIGINS`（各アプリの `/_status/parent` の origin、ソース固定値）。Gateway `https://federation-firewall-gateway.onrender.com`、Seneschal `https://seneschal-runtime.com`、他8件 `https://<id>-standalone-staging.onrender.com`（activity・fleet・urban・service・federation・simulator・remote-monitoring・administration）。`servingHost`：Seneschal `https://seneschal-standalone-staging.onrender.com`、他は origin と同じ。`plannedCustomOrigin`：Federation `https://federation-runtime.com`。全件 `dnsVerified:false`。
- `/healthz`・`/api/status`・`/api/catalog` の `independentApps`：10アプリのOriginと接続状態（`origin-unassigned`／`not-connected`／`key-configured-no-signed-request`／`signed-request-verified-this-process`／`self`）。`productionE2EVerified` は常に `false`。

## 独立オリジンの状態エンドポイント（2026-11-06）

- `GET /healthz` — `ok:true`、`stage:shadow-hold`、`productionReady:false`、`cutoverEnabled:false`
- `GET /git-head.json` — 配信中SHA。Renderが付与する `RENDER_GIT_COMMIT`（40桁）だけを使い、無い・不正なら `sha:null`／`sourceState:unverified-no-platform-sha`。配布リポジトリ `Satofumi-Goto/federation-runtime` と、配布側 `source-attestation.json` の正本コミット（無ければ `null`）
- `GET /_status/parent` — schema `federation.runtime-child/1`、`service:firewall-standalone`（Gateway名は `gatewayService`）、`parentOrigin:https://federation-runtime.com`、`origin:https://federation-firewall-gateway.onrender.com`、`parentVerified`・`productionReady`・`authenticatedE2E`・`dnsVerified` はすべて false
- `GET /_status/readiness` — schema `federation.independent-readiness/1`、`app:firewall`、`frontendHostIndependent:true`（運用画面・状態ページをこのNodeプロセスが配信）、`backendIndependent:true`（Node標準のみ、Base44 SDK・バックエンドなし）、`storageIndependent:false`、`authenticatedE2E:false`、`dnsVerified:false`、`productionReady:false`、`verifiedCutovers:0`。false の項目は `pending` に未達理由
- 既存の `/`、`/api/status`、`/api/catalog`、`/api/clients` は変更なし

## AI質問 仕様v1.1：#1015形式に任意の会話履歴（2026-11-06）

- `#1015` 形式 `{characterId,question,locale?,persona?,screen?}` に任意の `history` を追加：`[{"role":"user"|"assistant","content":"…"}]`、1〜12件、各1200字以内、キーは role と content のみ。他のキーは従来どおり400。
- 本文上限：history なし 4096バイト（従来どおり）、history あり 16384バイト。超過は413 `too_large`。
- プロバイダへは history を順番どおりに会話として渡し、最後に question を置く。
- 監査には `historyCount`（件数）だけを足し、履歴の本文は記録しない。


## Render Key Value（無料・非永続）の共有防御モード

- `FIREWALL_STORE=render-valkey`、`FIREWALL_STORE_INTERNAL_URL=redis://red-<private-render-id>:6379` で同じRender workspace/region の**内部ネットワーク**に直接接続する。外部接続・パス指定・URL認証情報・汎用ホスト・任意ポートは拒否。
- Node内蔵のRESP2を使い、共有nonceのSET NX PX、INCR/PEXPIRE NXの回数制限、本文を含まない監査メタデータだけをLPUSH/LTRIMで保管する。Redisが未設定/停止/異常応答/タイムアウトなら、署名済みHTTP入口も**403/503側に閉じ、上流へ送らない**。
- `render-valkey` モードは自動的に分散ストア必須となり、別途 `FIREWALL_REQUIRE_DISTRIBUTED_STORE=true` を忘れても保護を無効化できない。通常のShadowメモリモードは変更しない。
- Render Key Value **Free はメモリのみで、インスタンス再起動でnonce・レートカウント・監査ログが消える。** これは無料の分散検証であって、商用の耐改ざん監査/永続的リプレイ保護ではない。Key Valueを本番の永続ストアへ切り替える際は別PR・予算承認・再検証が必要。
- Storeの内部URLはサーバー環境変数にだけ設定し、チャット/画面/ブラウザに転送しない。APIルーティングは `gateway=false / legacy=true / HOLD` を保持。

## Keyless free AI relay (default OFF)

- `POST /api/v1/free-ai/chat` relays OpenAI-style chat to providers that need **no account or API key**: OVHcloud AI Endpoints (anonymous), LLM7.io (anonymous) and Kilo AI Gateway (`:free` models only). No credential is stored or forwarded.
- HMAC server-to-server only (`federation` client by default, `FIREWALL_FREE_AI_CLIENT_IDS`), Origin/Cookie/Authorization rejected. OFF unless `FIREWALL_FREE_AI_ENABLED=true`.
- Per-provider ceilings at or below the anonymous limits; 429/5xx cool down 60 s, 401/402/403 or any reported cost stop that provider for the day. LLM7 and Kilo may log prompts, so `plan`/`implement`/`review`/`test` roles are refused for them.
- `GET /api/free-ai` and `/api/clients` (`freeAi`) publish the provider list, limits and today's counts. Prompts and answers are never logged.
