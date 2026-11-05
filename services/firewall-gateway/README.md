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
