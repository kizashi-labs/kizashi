'use client'

import { useState, useRef, useMemo } from 'react'
import { Copy, Check, ChevronRight, BookOpen, Search, Play, X, Loader2 } from 'lucide-react'

const BASE_URL = typeof window !== 'undefined'
  ? `${window.location.protocol}//${window.location.hostname}:8080`
  : 'https://edr.example.com'

// ─── Types ─────────────────────────────────────────────────────────────────

interface Parameter {
  name: string
  type: string
  required: boolean
  description: string
}

interface Endpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'
  path: string
  description: string
  parameters?: Parameter[]
  requestBody?: string
  response: string
}

interface EndpointGroup {
  id: string
  label: string
  endpoints: Endpoint[]
}

// ─── Method badge colors ────────────────────────────────────────────────────

const METHOD_COLORS: Record<string, string> = {
  GET:    'bg-green-500/20 text-green-400 border border-green-500/30',
  POST:   'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  PUT:    'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  PATCH:  'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  DELETE: 'bg-red-500/20 text-red-400 border border-red-500/30',
}

// ─── API Data ───────────────────────────────────────────────────────────────

const endpointGroups: EndpointGroup[] = [
  {
    id: 'authentication',
    label: 'Authentication',
    endpoints: [
      {
        method: 'POST',
        path: '/api/v1/auth/login',
        description: 'ユーザー資格情報で JWT を取得します。**リフレッシュトークンは返りません**（token 1 本と expires_in のみ）。MFA が有効なアカウントでは代わりに mfa_required / pre_auth_token を含む応答が返るので、続けて MFA 検証エンドポイントを呼びます。',
        parameters: [],
        requestBody: JSON.stringify({
          email: 'admin@example.com',
          password: 'yourpassword'
        }, null, 2),
        response: JSON.stringify({
          token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
          expires_in: 86400,
          must_change_password: false,
          user: {
            id: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
            email: 'admin@example.com',
            full_name: '管理者',
            role: 'admin',
            mfa_enabled: false,
            must_change_password: false
          }
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/auth/logout',
        description: '現在のセッションを無効化してトークンをブラックリストに登録します。',
        parameters: [],
        requestBody: JSON.stringify({ refresh_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...' }, null, 2),
        response: JSON.stringify({ message: 'ログアウトしました' }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/auth/refresh',
        description: 'リフレッシュトークンを使用して新しいアクセストークンを発行します。',
        parameters: [],
        requestBody: JSON.stringify({ refresh_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...' }, null, 2),
        response: JSON.stringify({
          token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
          expires_in: 3600
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/users/me',
        description: '現在認証されているユーザーのプロファイル情報を返します。環境変数で設定した管理者（DBレコードを持たない）の場合は id/email/role の3項目のみが返ります。プロファイルの更新は PATCH /api/v1/users/me です。',
        parameters: [],
        response: JSON.stringify({
          id: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
          email: 'admin@example.com',
          full_name: '管理者',
          role: 'admin',
          created_at: '2026-01-01T00:00:00Z',
          last_login: '2026-03-18T09:00:00Z'
        }, null, 2),
      },
    ],
  },
  {
    id: 'agents',
    label: 'Agents',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/agents',
        description: '登録済みエンドポイントエージェントの一覧を取得します。フィルタリングとページネーションに対応。値が無いフィールド（last_seen / group_id 等）はレスポンスから省略されます。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号 (デフォルト: 1)' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数 (デフォルト: 20, 最大: 1000。別名 limit も可)' },
          { name: 'status',   type: 'string',  required: false, description: 'ステータスフィルタ: online | offline | isolated | error | inactive (inactive = 30日以上ハートビートなし)' },
          { name: 'search',   type: 'string',  required: false, description: 'ホスト名・IPアドレスのキーワード検索' },
          { name: 'group_id', type: 'string',  required: false, description: '特定グループのエージェントのみを返す' },
          { name: 'os',       type: 'string',  required: false, description: 'OSフィルタ: windows | linux | darwin | unknown' },
        ],
        response: JSON.stringify({
          data: [
            {
              id: '2df91291-9178-4d3c-8dcd-4ea4ea21289d',
              hostname: 'WORKSTATION-01',
              os_type: 'windows',
              os_version: 'Windows 11 Pro',
              agent_version: '2.1.0',
              ip_addresses: ['192.168.1.100'],
              status: 'online',
              last_seen: '2026-03-18T09:30:00Z',
              enrolled_at: '2026-01-15T08:00:00Z',
              group_id: '8f14e45f-ceea-467a-9575-1b0d1f0b0a11',
              config_version: 3,
              tags: ['finance', 'critical']
            },
            {
              id: 'a7c11e02-3f52-4a90-9c1e-6b2f0d4e88aa',
              hostname: 'OLD-LAPTOP-07',
              os_type: 'windows',
              os_version: 'Windows 10 Pro',
              agent_version: '1.9.2',
              ip_addresses: ['192.168.1.212'],
              status: 'inactive',
              last_seen: '2026-03-22T05:19:27Z',
              enrolled_at: '2025-11-02T02:41:00Z',
              config_version: 1,
              tags: []
            }
          ],
          total: 142,
          page: 1,
          per_page: 20,
          has_more: true
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/agents/:id',
        description: '指定されたIDのエージェントの詳細情報を取得します。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'エージェントのUUID' },
        ],
        response: JSON.stringify({
          id: '2df91291-9178-4d3c-8dcd-4ea4ea21289d',
          hostname: 'WORKSTATION-01',
          os_type: 'windows',
          os_version: 'Windows 11 Pro 22H2',
          agent_version: '2.1.0',
          ip_addresses: ['192.168.1.100', '10.0.0.55'],
          status: 'online',
          last_seen: '2026-03-18T09:30:00Z',
          enrolled_at: '2026-01-15T08:00:00Z',
          group_id: '8f14e45f-ceea-467a-9575-1b0d1f0b0a11',
          policy_id: '3c9a71d4-22b8-4f6e-8a01-77e5c9b3d240',
          config_version: 3,
          tags: ['finance', 'critical']
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/agents/:id/commands',
        description: 'エージェントにライブレスポンス・コマンドをキューイングします。command_type は shell / file_list / file_get / file_put / process_list / process_kill / network_list / reg_query のいずれかで、それ以外は 400 になります。ネットワーク隔離はこのエンドポイントではなく POST /api/v1/agents/:id/isolate を使います。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'エージェントのUUID' },
        ],
        requestBody: JSON.stringify({
          command_type: 'process_list',
          command: 'process_list',
          args: { filter: 'powershell' }
        }, null, 2),
        response: JSON.stringify({
          id: 'e91b6d3a-5c7e-4f11-9b02-1d8a4c7e3f55',
          agent_id: '2df91291-9178-4d3c-8dcd-4ea4ea21289d',
          command_type: 'process_list',
          command: 'process_list',
          args: { filter: 'powershell' },
          status: 'pending',
          created_at: '2026-03-18T09:31:00Z',
          timeout_at: '2026-03-18T09:36:00Z'
        }, null, 2),
      },
      {
        method: 'PUT',
        path: '/api/v1/agents/:id',
        description: 'エージェントのメタデータを更新します。更新できるのは tags と group_id のみで、他のフィールドは無視されます。PUT は指定された値で置換、PATCH は指定されたフィールドのみ更新します。レスポンスは更新後のエージェント全体です。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'エージェントのUUID' },
        ],
        requestBody: JSON.stringify({
          group_id: '8f14e45f-ceea-467a-9575-1b0d1f0b0a11',
          tags: ['finance', 'critical', 'vip']
        }, null, 2),
        response: JSON.stringify({
          id: '2df91291-9178-4d3c-8dcd-4ea4ea21289d',
          hostname: 'WORKSTATION-01',
          os_type: 'windows',
          os_version: 'Windows 11 Pro 22H2',
          agent_version: '2.1.0',
          ip_addresses: ['192.168.1.100', '10.0.0.55'],
          status: 'online',
          last_seen: '2026-03-18T09:30:00Z',
          enrolled_at: '2026-01-15T08:00:00Z',
          group_id: '8f14e45f-ceea-467a-9575-1b0d1f0b0a11',
          config_version: 3,
          tags: ['finance', 'critical', 'vip']
        }, null, 2),
      },
      {
        method: 'DELETE',
        path: '/api/v1/agents/:id',
        description: 'エージェントをシステムから削除します。関連するイベントとアラートは保持されます。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'エージェントのUUID' },
        ],
        response: JSON.stringify({
          message: 'エージェントを削除しました',
          id: '2df91291-9178-4d3c-8dcd-4ea4ea21289d'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/agents/:id/events',
        description: '特定エージェントのイベントログを取得します。',
        parameters: [
          { name: 'id',         type: 'string',  required: true,  description: 'エージェントのUUID' },
          { name: 'page',       type: 'integer', required: false, description: 'ページ番号' },
          { name: 'per_page',   type: 'integer', required: false, description: '1ページあたりの件数' },
          { name: 'event_type', type: 'string',  required: false, description: 'イベントタイプフィルタ' },
          { name: 'since',      type: 'string',  required: false, description: '開始日時 (RFC3339)' },
          { name: 'until',      type: 'string',  required: false, description: '終了日時 (RFC3339)' },
        ],
        response: JSON.stringify({
          data: [
            {
              id: '01HX8888EVT1',
              event_type: 'process_create',
              timestamp: '2026-03-18T09:28:00Z',
              process_name: 'cmd.exe',
              command_line: 'cmd.exe /c whoami',
              parent_process: 'explorer.exe',
              severity: 3
            }
          ],
          total: 1420,
          page: 1,
          per_page: 20,
          has_more: true,
          total_capped: false
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/metrics/agent-stats',
        description: 'エージェントの集計統計を返します。判定は status カラムではなく last_seen ベースで、online = 5分以内、stale = 5分〜1時間、offline = 1時間超または未受信です。status="inactive"（30日以上未確認）とは独立した別軸の集計である点に注意してください。',
        parameters: [],
        response: JSON.stringify({
          total: 142,
          online: 128,
          stale: 2,
          offline: 12
        }, null, 2),
      },
    ],
  },
  {
    id: 'alerts',
    label: 'Alerts',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/alerts',
        description: 'セキュリティアラートの一覧を取得します。ステータス・深刻度・日付でフィルタリング可能。',
        parameters: [
          { name: 'page',       type: 'integer', required: false, description: 'ページ番号' },
          { name: 'per_page',   type: 'integer', required: false, description: '1ページあたりの件数' },
          { name: 'status',     type: 'string',  required: false, description: 'open | closed | in_progress | suppressed' },
          { name: 'severity',   type: 'integer', required: false, description: '深刻度 1-10' },
          { name: 'agent_id',   type: 'string',  required: false, description: '特定エージェントのアラートのみ' },
          { name: 'since',      type: 'string',  required: false, description: '開始日時 (RFC3339)' },
          { name: 'until',      type: 'string',  required: false, description: '終了日時 (RFC3339)' },
          { name: 'q',          type: 'string',  required: false, description: 'タイトル・説明のキーワード検索' },
        ],
        response: JSON.stringify({
          data: [
            {
              id: '01HX2222ALT1',
              title: '不審なPowerShellの実行',
              description: 'エンコードされたコマンドを含むPowerShellが検出されました',
              severity: 8,
              status: 'open',
              agent_id: '01HX5678AGNT',
              hostname: 'WORKSTATION-01',
              created_at: '2026-03-18T09:00:00Z',
              updated_at: '2026-03-18T09:01:00Z',
              rule_id: '01HXRULE001',
              mitre_techniques: ['T1059.001']
            }
          ],
          total: 87,
          page: 1,
          per_page: 20,
          has_more: true
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/alerts/:id',
        description: '指定されたIDのアラートの詳細情報を取得します。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'アラートのUUID' },
        ],
        response: JSON.stringify({
          id: '01HX2222ALT1',
          title: '不審なPowerShellの実行',
          description: 'エンコードされたコマンドを含むPowerShellが検出されました',
          severity: 8,
          status: 'open',
          agent_id: '01HX5678AGNT',
          hostname: 'WORKSTATION-01',
          rule_id: '01HXRULE001',
          rule_name: 'PowerShell Encoded Command',
          mitre_techniques: ['T1059.001'],
          raw_event: { process_name: 'powershell.exe', command_line: 'powershell.exe -enc ...' },
          comments: [],
          created_at: '2026-03-18T09:00:00Z',
          updated_at: '2026-03-18T09:01:00Z',
          assigned_to: null
        }, null, 2),
      },
      {
        method: 'PUT',
        path: '/api/v1/alerts/:id',
        description: 'アラートの status と assigned_to を更新します（**severity は更新できません**）。レスポンスは更新後のアラート全体で、再取得に失敗した場合のみ {message, id} が返ります。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'アラートのUUID' },
        ],
        requestBody: JSON.stringify({
          status: 'investigating',
          assigned_to: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93'
        }, null, 2),
        response: JSON.stringify({
          id: 'c1f0a8d2-4b6e-4a91-9f33-2e5b7c81d004',
          title: 'Suspicious PowerShell Encoded Command',
          severity: 8,
          status: 'investigating',
          assigned_to: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
          agent_hostname: 'WORKSTATION-01',
          created_at: '2026-03-18T09:28:00Z',
          updated_at: '2026-03-18T09:45:00Z'
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/alerts/:id/comments',
        description: 'アラートにコメントを追加します。インシデント対応の記録に使用。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'アラートのUUID' },
        ],
        requestBody: JSON.stringify({ content: '調査を開始しました。プロセスツリーを確認中。' }, null, 2),
        response: JSON.stringify({
          id: '6e3b9d15-8a02-4c74-b1f6-5d9c7e2a0348',
          alert_id: 'c1f0a8d2-4b6e-4a91-9f33-2e5b7c81d004',
          content: '調査を開始しました。プロセスツリーを確認中。',
          user_id: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
          created_at: '2026-03-18T09:50:00Z'
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/alerts/bulk-update',
        description: '複数のアラートを一括更新します。更新できるのは status と assigned_to で、どちらも指定しないと 400 になります。レート制限あり。',
        parameters: [],
        requestBody: JSON.stringify({
          ids: [
            'c1f0a8d2-4b6e-4a91-9f33-2e5b7c81d004',
            '7a2e5b19-8c3d-4f07-b512-9d6a0e4c3311'
          ],
          status: 'resolved'
        }, null, 2),
        response: JSON.stringify({
          updated: 2,
          failed: [],
          total: 2
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/alerts/stats',
        description: 'アラートの集計統計を返します。ダッシュボードのウィジェット用。深刻度別の内訳は by_severity（キーが深刻度の数値）で返ります。',
        parameters: [],
        response: JSON.stringify({
          total: 342,
          open: 42,
          investigating: 15,
          resolved: 250,
          false_positive: 35,
          today_count: 12,
          by_severity: { '8': 20, '5': 32, '3': 10 }
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/suppressions',
        description: '抑制ルールを登録し、条件に合致するアラートを今後抑制します。アラート単位ではなく条件（conditions）で定義するリソースです。抑制候補の提示は GET /api/v1/suppressions/candidates、一覧は GET /api/v1/suppressions、有効/無効の切替は PUT /api/v1/suppressions/:id/toggle です。',
        parameters: [],
        requestBody: JSON.stringify({
          name: 'テスト環境の既知アクティビティ',
          description: 'ステージング環境の定常スキャンを抑制',
          conditions: { rule_name: 'Suspicious PowerShell', hostname: 'STG-*' },
          duration_h: 720,
          is_active: true
        }, null, 2),
        response: JSON.stringify({
          message: '抑制ルールを作成しました'
        }, null, 2),
      },
    ],
  },
  {
    id: 'incidents',
    label: 'Incidents',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/incidents',
        description: 'インシデントの一覧を取得します。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数' },
          { name: 'status',   type: 'string',  required: false, description: 'open | closed | investigating' },
          { name: 'severity', type: 'integer', required: false, description: '深刻度 1-10' },
        ],
        response: JSON.stringify({
          data: [
            {
              id: '01HXINC00001',
              title: 'ランサムウェア感染の疑い',
              severity: 10,
              status: 'investigating',
              alert_count: 15,
              assigned_to: '01HX1234ABCD',
              created_at: '2026-03-18T08:00:00Z'
            }
          ],
          total: 5,
          page: 1,
          per_page: 20,
          has_more: false
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/incidents',
        description: '新しいインシデントを作成します。複数のアラートを関連付けることができます。',
        parameters: [],
        requestBody: JSON.stringify({
          title: 'ランサムウェア感染の疑い',
          description: '複数のエンドポイントで不審なファイル暗号化活動が検出されました',
          severity: 10,
          alert_ids: ['01HX2222ALT1', '01HX2222ALT2']
        }, null, 2),
        response: JSON.stringify({
          message: 'インシデントを作成しました',
          id: '8d2c4a71-6b90-4e35-a7f1-0c53e8b2d947'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/incidents/:id',
        description: '指定されたインシデントの詳細と、それに紐づくアラート一覧を返します。インシデント本体は incident キーの下に入ります（トップレベルに展開されません）。タイムラインは別途 /api/v1/timeline を参照してください。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'インシデントのUUID' },
        ],
        response: JSON.stringify({
          incident: {
            id: '8d2c4a71-6b90-4e35-a7f1-0c53e8b2d947',
            title: 'ランサムウェア感染の疑い',
            description: '詳細な説明...',
            severity: 10,
            status: 'investigating',
            assigned_to: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
            created_at: '2026-03-18T08:00:00Z'
          },
          alerts: [
            { id: 'c1f0a8d2-4b6e-4a91-9f33-2e5b7c81d004', title: 'Suspicious file encryption', severity: 9 }
          ]
        }, null, 2),
      },
      {
        method: 'PUT',
        path: '/api/v1/incidents/:id',
        description: 'インシデントのステータス、深刻度、担当者を更新します。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'インシデントのUUID' },
        ],
        requestBody: JSON.stringify({
          status: 'closed',
          resolution: 'ランサムウェアを隔離し、影響を受けたシステムをリストアしました'
        }, null, 2),
        response: JSON.stringify({
          message: 'インシデントを更新しました',
          id: '8d2c4a71-6b90-4e35-a7f1-0c53e8b2d947'
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/incidents/:id/alerts',
        description: '既存のインシデントにアラートを追加関連付けします。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'インシデントのUUID' },
        ],
        requestBody: JSON.stringify({ alert_ids: ['01HX2222ALT3', '01HX2222ALT4'] }, null, 2),
        response: JSON.stringify({
          message: 'アラートをリンクしました'
        }, null, 2),
      },
    ],
  },
  {
    id: 'rules',
    label: 'Rules',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/rules',
        description: '検知ルール（Sigmaルール等）の一覧を取得します。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数' },
          { name: 'enabled',  type: 'boolean', required: false, description: '有効なルールのみ取得' },
          { name: 'severity', type: 'integer', required: false, description: '深刻度フィルタ' },
          { name: 'q',        type: 'string',  required: false, description: 'キーワード検索' },
        ],
        response: JSON.stringify({
          rules: [
            {
              id: '5b8e2f14-7c03-4a6d-9218-3f0c7d5a1e46',
              name: 'PowerShell Encoded Command',
              description: 'エンコードされたコマンドを含むPowerShellの実行を検出',
              severity: 8,
              enabled: true,
              type: 'sigma',
              mitre_tags: ['T1059.001'],
              created_at: '2026-01-01T00:00:00Z'
            }
          ],
          total: 350,
          page: 1,
          per_page: 20,
          has_more: true
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/rules',
        description: '新しい検知ルールを作成します。Sigmaルール形式またはカスタム形式に対応。',
        parameters: [],
        requestBody: JSON.stringify({
          name: 'カスタムルール: 不審なnetsh実行',
          description: 'netshによるファイアウォール変更を検出',
          severity: 7,
          type: 'custom',
          conditions: [
            { field: 'process_name', operator: 'equals', value: 'netsh.exe' },
            { field: 'command_line', operator: 'contains', value: 'firewall' }
          ],
          mitre_techniques: ['T1562.004']
        }, null, 2),
        response: JSON.stringify({
          id: '9c4e7a12-5f83-4b60-a271-8d0f3e6c5b94',
          name: 'カスタムルール: 不審なnetsh実行',
          type: 'custom',
          platform: ['windows'],
          severity: 7,
          content: '...',
          enabled: true,
          source: 'custom',
          mitre_tags: ['T1562.004'],
          auto_isolate: false,
          auto_kill: false,
          auto_quarantine: false,
          description: 'netshによるファイアウォール変更を検出',
          false_positive_rate: 0,
          created_at: '2026-03-18T11:00:00Z',
          updated_at: '2026-03-18T11:00:00Z'
        }, null, 2),
      },
      {
        method: 'PUT',
        path: '/api/v1/rules/:id',
        description: '既存の検知ルールを更新します。レスポンスは更新後のルール全体です。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'ルールのUUID' },
        ],
        requestBody: JSON.stringify({
          severity: 9,
          enabled: false,
          description: '更新された説明'
        }, null, 2),
        response: JSON.stringify({
          id: '5b8e2f14-7c03-4a6d-9218-3f0c7d5a1e46',
          name: 'PowerShell Encoded Command',
          type: 'sigma',
          platform: ['windows'],
          severity: 9,
          content: '...',
          enabled: false,
          source: 'sigmahq',
          mitre_tags: ['T1059.001'],
          auto_isolate: false,
          auto_kill: false,
          auto_quarantine: false,
          description: '更新された説明',
          false_positive_rate: 0.02,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-03-18T11:30:00Z'
        }, null, 2),
      },
      {
        method: 'DELETE',
        path: '/api/v1/rules/:id',
        description: '指定した検知ルールを削除します。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'ルールのUUID' },
        ],
        response: JSON.stringify({
          message: 'ルールを削除しました',
          id: '5b8e2f14-7c03-4a6d-9218-3f0c7d5a1e46'
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/rules/import',
        description: 'Sigmaルールをまとめてインポートします（YAMLファイル形式）。',
        parameters: [],
        requestBody: JSON.stringify({
          format: 'sigma',
          rules: ['title: PowerShell Encoded Command\nstatus: stable\n...']
        }, null, 2),
        response: JSON.stringify({
          id: '5b8e2f14-7c03-4a6d-9218-3f0c7d5a1e46',
          message: 'ルールをインポートしました。有効化する前に内容を確認してください。',
          rule: { id: '5b8e2f14-7c03-4a6d-9218-3f0c7d5a1e46', name: 'PowerShell Encoded Command', enabled: false }
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/rules/:id/test',
        description: '指定したルールを 1 件のサンプルイベントに対して評価します。過去イベントへの遡及実行ではありません。sample_event を省略すると最小のダミーイベント（event_type=test）で評価されます。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'ルールのUUID' },
        ],
        requestBody: JSON.stringify({
          sample_event: {
            event_type: 'process',
            process_name: 'powershell.exe',
            command_line: 'powershell -enc SQBFAFgA'
          }
        }, null, 2),
        response: JSON.stringify({
          rule_id: '5b8e2f14-7c03-4a6d-9218-3f0c7d5a1e46',
          rule_name: 'Suspicious PowerShell Encoded Command',
          rule_type: 'sigma',
          matched: true,
          matched_terms: ['powershell', '-enc'],
          note: '',
          tested_at: '2026-03-18T10:00:00Z'
        }, null, 2),
      },
    ],
  },
  {
    id: 'reports',
    label: 'Reports',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/reports',
        description: '生成済みレポートの一覧を取得します。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数' },
          { name: 'type',     type: 'string',  required: false, description: 'レポートタイプフィルタ' },
        ],
        response: JSON.stringify({
          reports: [
            {
              id: 'b93c5e21-0a74-4d68-91f5-2c7e8b4a0d13',
              type: 'weekly_summary',
              status: 'completed',
              requested_at: '2026-03-15T06:00:00Z',
              completed_at: '2026-03-15T06:00:31Z'
            }
          ],
          total: 28
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/reports',
        description: '新しいレポートを生成します。非同期処理のため 202 Accepted とジョブ ID を返し、本体は後から埋まります。期間を省略すると直近7日が対象です。レート制限あり。',
        parameters: [],
        requestBody: JSON.stringify({
          type: 'incident_summary',
          from: '2026-03-01T00:00:00Z',
          to: '2026-03-31T23:59:59Z'
        }, null, 2),
        response: JSON.stringify({
          id: 'b93c5e21-0a74-4d68-91f5-2c7e8b4a0d13',
          type: 'incident_summary',
          status: 'pending',
          requested_by: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
          requested_at: '2026-03-18T10:00:00Z'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/reports/:id',
        description: '生成済みレポートの本文を JSON で取得します。まだ生成中の場合は 202 と status を返します。PDF が必要な場合は GET /api/v1/reports/:id/pdf、ジョブの進行状況だけを見る場合は GET /api/v1/reports/jobs/:id を使います。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'レポートジョブのUUID' },
        ],
        response: JSON.stringify({
          id: 'b93c5e21-0a74-4d68-91f5-2c7e8b4a0d13',
          type: 'incident_summary',
          status: 'completed',
          requested_at: '2026-03-18T10:00:00Z',
          completed_at: '2026-03-18T10:00:28Z',
          content: { summary: '...', sections: [] }
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/reports/schedules',
        description: '定期レポートスケジュールを作成します。',
        parameters: [],
        requestBody: JSON.stringify({
          name: '毎週月曜日のセキュリティサマリー',
          type: 'weekly_summary',
          cron: '0 9 * * 1',
          format: 'pdf',
          recipients: ['soc@example.com', 'ciso@example.com']
        }, null, 2),
        response: JSON.stringify({
          message: 'スケジュールを作成しました',
          id: 'a58f3d92-4e17-4b60-9c8a-2f7b1e6d0453'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/reports/schedules',
        description: '定期レポートスケジュールの一覧を取得します。',
        parameters: [],
        response: JSON.stringify({
          data: [
            {
              id: '01HXSCHED001',
              name: '毎週月曜日のセキュリティサマリー',
              type: 'weekly_summary',
              cron: '0 9 * * 1',
              enabled: true,
              next_run: '2026-03-23T09:00:00Z'
            }
          ],
          total: 3
        }, null, 2),
      },
    ],
  },
  {
    id: 'threat-intel',
    label: 'Threat Intel',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/ioc',
        description: 'IOC（脅威インジケーター）の一覧を取得します。統計は GET /api/v1/ioc/stats、単一値の照合は GET /api/v1/ioc/check、一括取込は POST /api/v1/ioc/import です。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号 (デフォルト: 1)' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数 (デフォルト: 50, 最大: 200)' },
          { name: 'type',     type: 'string',  required: false, description: 'IOC種別フィルタ: ip | domain | hash | url' },
          { name: 'search',   type: 'string',  required: false, description: 'キーワード検索' },
          { name: 'active',   type: 'string',  required: false, description: '"true" を指定すると有効な IOC のみ返す' },
        ],
        response: JSON.stringify({
          data: [
            {
              id: 'e7d4a1b8-2c95-4f36-8a70-1b3e5d9c6f42',
              type: 'ip',
              value: '185.220.101.45',
              description: 'Tor出口ノード',
              severity: 7,
              is_active: true,
              added_by_name: '管理者',
              created_at: '2026-03-10T00:00:00Z',
              updated_at: '2026-03-10T00:00:00Z'
            }
          ],
          total: 12500,
          page: 1,
          per_page: 50,
          has_more: true
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/ioc',
        description: '新しいIOCをシステムに追加します。受け付けるのは type / value / description / severity のみで、severity が 1〜10 の範囲外だと 7 に丸められます。',
        parameters: [],
        requestBody: JSON.stringify({
          type: 'hash',
          value: 'd41d8cd98f00b204e9800998ecf8427e',
          description: '既知のランサムウェアハッシュ',
          severity: 10
        }, null, 2),
        response: JSON.stringify({
          message: 'IOCを追加しました'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/threat-intel/feeds',
        description: '設定済みの脅威インテリジェンスフィードの一覧を取得します。',
        parameters: [],
        response: JSON.stringify({
          data: [
            {
              id: '2c7f5a08-9b31-4e62-8d04-6a1e3c9b7d25',
              name: 'Abuse.ch URLhaus',
              url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
              type: 'urlhaus',
              enabled: true,
              last_sync: '2026-03-18T06:00:00Z',
              ioc_count: 45000
            }
          ],
          total: 1
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/threat-intel/search',
        description: '脅威インテリジェンスの IOC を部分一致で検索します（最大20件）。クエリパラメータ q が必須で、省略すると 400 になります。値の単発照合には GET /api/v1/ioc/check、外部ソースでの補強には POST /api/v1/threat-intel/enrich を使います。',
        parameters: [
          { name: 'q', type: 'string', required: true, description: 'IOC 値の部分一致キーワード' },
        ],
        response: JSON.stringify({
          results: [
            {
              value: '185.220.101.45',
              ioc_type: 'ip',
              threat_level: 7,
              tags: ['tor', 'c2'],
              description: 'Tor出口ノード',
              first_seen: '2026-03-10T00:00:00Z',
              last_seen: '2026-03-17T22:00:00Z',
              source_feed: 'abuse.ch'
            }
          ],
          query: '185.220.101',
          count: 1
        }, null, 2),
      },
      {
        method: 'DELETE',
        path: '/api/v1/ioc/:id',
        description: '指定したIOCをシステムから削除します。無効化のみ行う場合は PUT /api/v1/ioc/:id/toggle を使います。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'IOCのUUID' },
        ],
        response: JSON.stringify({
          message: 'IOCを削除しました',
          id: 'e7d4a1b8-2c95-4f36-8a70-1b3e5d9c6f42'
        }, null, 2),
      },
    ],
  },
  {
    id: 'export',
    label: 'Export',
    endpoints: [
      {
        method: 'POST',
        path: '/api/v1/export',
        description: 'データをエクスポートします。**ジョブキューではなく同期的に処理され、レスポンスはファイル本体**（Content-Disposition: attachment）です。ジョブIDや後追いのダウンロードURLはありません。format は csv / json / ndjson（既定 json）、limit は最大 50000（範囲外は 10000 に丸め）。',
        parameters: [],
        requestBody: JSON.stringify({
          type: 'alerts',
          format: 'csv',
          columns: ['id', 'title', 'severity', 'status', 'created_at'],
          from: '2026-03-01T00:00:00Z',
          to: '2026-03-18T23:59:59Z',
          filters: { status: 'open' },
          limit: 10000
        }, null, 2),
        response: '// Content-Type: text/csv (format に応じて application/json / application/x-ndjson)\n// Content-Disposition: attachment; filename=...\n// (エクスポートデータ本体)',
      },
      {
        method: 'GET',
        path: '/api/v1/export/status',
        description: 'エクスポート可能な種別と各テーブルの件数、上限・対応フォーマットを返します。**ジョブの進行状況ではありません**（ジョブという概念自体が無い）。',
        parameters: [],
        response: JSON.stringify({
          export_types: [
            { type: 'alerts', table: 'alerts', available: true, record_count: 12843 },
            { type: 'events', table: 'events', available: true, record_count: 9482013 }
          ],
          max_limit: 50000,
          formats: ['csv', 'json', 'ndjson'],
          checked_at: '2026-03-18T14:00:00Z'
        }, null, 2),
      },
    ],
  },
  {
    id: 'search',
    label: 'Search',
    endpoints: [
      {
        method: 'POST',
        path: '/api/v1/search',
        description: 'グローバル検索エンドポイント。エージェント、アラート、イベント、IOC等を横断的に検索します。',
        parameters: [],
        requestBody: JSON.stringify({
          query: 'powershell -enc',
          types: ['alerts', 'events', 'agents'],
          filters: {
            date_from: '2026-03-01T00:00:00Z',
            date_to: '2026-03-18T23:59:59Z',
            severity_min: 3
          },
          page: 1,
          per_page: 20
        }, null, 2),
        response: JSON.stringify({
          results: {
            alerts: {
              total: 5,
              data: [{ id: '01HX2222ALT1', title: '不審なPowerShellの実行', score: 0.98 }]
            },
            events: {
              total: 42,
              data: [{ id: '01HX8888EVT1', event_type: 'process_create', score: 0.85 }]
            },
            agents: {
              total: 0,
              data: []
            }
          },
          total: 47,
          took_ms: 45
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/events/search',
        description: 'イベントログを検索します。**KQL / Lucene 構文には対応していません** — query は raw_data に対する部分一致で、他の条件は agent_id / event_type / 期間の単純フィルタです。per_page は最大 200（範囲外は 50）。保存した検索条件は /api/v1/search/saved 配下で管理します。',
        parameters: [],
        requestBody: JSON.stringify({
          agent_id: '2df91291-9178-4d3c-8dcd-4ea4ea21289d',
          event_type: 'process',
          query: 'powershell',
          from: '2026-03-17T00:00:00Z',
          to: '2026-03-18T23:59:59Z',
          page: 1,
          per_page: 50
        }, null, 2),
        response: JSON.stringify({
          data: [
            {
              event_id: '0c9a7f31-6d24-4e58-b1a0-8f5c2e7b3d90',
              event_type: 'process',
              agent_id: '2df91291-9178-4d3c-8dcd-4ea4ea21289d',
              time: '2026-03-18T09:28:00Z',
              raw_data: { process_name: 'powershell.exe', command_line: 'powershell.exe -enc SQBFAFgA' }
            }
          ],
          total: 12,
          page: 1,
          per_page: 50,
          has_more: false,
          total_capped: false
        }, null, 2),
      },
    ],
  },
  {
    id: 'admin',
    label: 'Admin',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/admin/users',
        description: 'システムユーザーの一覧を取得します（管理者のみ）。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数' },
          { name: 'role',     type: 'string',  required: false, description: 'ロールフィルタ: admin | analyst | viewer' },
        ],
        response: JSON.stringify({
          users: [
            {
              id: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
              username: 'admin',
              email: 'admin@example.com',
              full_name: '管理者',
              role: 'admin',
              enabled: true,
              mfa_enabled: false,
              last_login: '2026-03-18T09:00:00Z',
              created_at: '2026-01-01T00:00:00Z',
              login_count: 142,
              failed_login_count: 0
            }
          ],
          total: 12
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/admin/users',
        description: '新しいユーザーアカウントを作成します。レスポンスは作成されたユーザー全体で、一覧 (GET /api/v1/admin/users) の users 要素と同じ形です。',
        parameters: [],
        requestBody: JSON.stringify({
          email: 'analyst@example.com',
          full_name: '新規アナリスト',
          role: 'analyst',
          password: 'SecurePassword123!'
        }, null, 2),
        response: JSON.stringify({
          id: 'b7e04c19-3a62-4f85-9d13-6c8a2e5b70f4',
          username: 'analyst',
          email: 'analyst@example.com',
          full_name: '新規アナリスト',
          role: 'analyst',
          enabled: true,
          mfa_enabled: false,
          created_at: '2026-03-18T15:00:00Z',
          login_count: 0,
          failed_login_count: 0
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/audit',
        description: '監査ログの一覧を取得します（admin 限定）。配列のキーは data ではなく **logs** です。絞り込みはユーザーのメールアドレス・HTTPメソッド・エラーのみの3種で、user_id / action / since は受け付けません。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号 (デフォルト: 1)' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数 (デフォルト: 50)' },
          { name: 'user',     type: 'string',  required: false, description: 'ユーザーのメールアドレスで絞り込み' },
          { name: 'method',   type: 'string',  required: false, description: 'HTTPメソッドで絞り込み (GET / POST 等)' },
          { name: 'errors',   type: 'string',  required: false, description: '"1" を指定するとエラー応答のみ返す' },
        ],
        response: JSON.stringify({
          logs: [
            {
              id: 'f4b8e0a7-3c61-4d92-a805-7e1f9b2c6d34',
              user_email: 'admin@example.com',
              method: 'PUT',
              path: '/api/v1/alerts/c1f0a8d2-4b6e-4a91-9f33-2e5b7c81d004',
              status_code: 200,
              ip_address: '192.168.1.50',
              created_at: '2026-03-18T10:00:00Z'
            }
          ],
          total: 5420,
          page: 1,
          per_page: 50,
          has_more: true
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/health',
        description: 'ヘルスチェック（**認証不要・`/api/v1` 配下ではない**）。DB へ ping し、失敗時は 503 と status="degraded" を返します。より詳細な情報は /api/v1/health/detailed、依存関係は /api/v1/health/dependencies、k8s 用プローブは /healthz です。',
        parameters: [],
        response: JSON.stringify({
          status: 'ok',
          time: '2026-03-18T15:00:00Z',
          db: 'ok'
        }, null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/api-keys',
        description: 'APIキーを生成します。外部システム連携用（API アクセス機能を含むプランが必要）。スコープは **read / write / admin の3値のみ**で、それ以外を指定すると 400 になります。レスポンスは生成されたキー文字列のみで、**この1回しか表示されません**。一覧は GET /api/v1/api-keys、失効は DELETE /api/v1/api-keys/:id です。',
        parameters: [],
        requestBody: JSON.stringify({
          name: 'SIEM連携キー',
          scopes: ['read'],
          expires_at: '2027-03-18T00:00:00Z'
        }, null, 2),
        response: JSON.stringify({
          key: 'edr_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
          message: 'このキーは一度しか表示されません。安全な場所に保存してください。'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/admin/tenants',
        description: 'マルチテナント環境のテナント一覧を取得します。',
        parameters: [
          { name: 'page',     type: 'integer', required: false, description: 'ページ番号' },
          { name: 'per_page', type: 'integer', required: false, description: '1ページあたりの件数' },
        ],
        response: JSON.stringify({
          data: [
            {
              id: '01HX0000TENANT',
              name: 'デフォルトテナント',
              agent_count: 142,
              user_count: 12,
              plan: 'enterprise',
              created_at: '2026-01-01T00:00:00Z'
            }
          ],
          total: 5
        }, null, 2),
      },
    ],
  },
  {
    id: 'support',
    label: 'Support Tickets',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/support/tickets',
        description: 'サポートチケット一覧を取得します。管理者は全件、一般ユーザーは自分のチケットのみ返します。',
        parameters: [
          { name: 'status',   type: 'string',  required: false, description: 'open | in_progress | waiting_customer | resolved | closed' },
          { name: 'priority', type: 'string',  required: false, description: 'low | medium | high | critical' },
          { name: 'category', type: 'string',  required: false, description: 'billing | technical | feature_request | bug_report | installation | configuration | security | other' },
          { name: 'search',   type: 'string',  required: false, description: 'タイトル・説明のキーワード検索' },
        ],
        response: JSON.stringify([
          {
            id: 'uuid-xxxx',
            title: 'エージェントが接続されない',
            category: 'technical',
            priority: 'high',
            status: 'open',
            comment_count: 2,
            created_at: '2026-03-21T09:00:00Z',
            updated_at: '2026-03-21T09:30:00Z'
          }
        ], null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/support/tickets',
        description: '新しいサポートチケットを作成します。レスポンスは作成されたチケット全体です。',
        parameters: [],
        requestBody: JSON.stringify({
          title: 'エージェントのインストールに失敗する',
          description: 'Linuxサーバーでインストールスクリプトを実行すると exit code 1 で失敗します。',
          category: 'installation',
          priority: 'high'
        }, null, 2),
        response: JSON.stringify({
          id: '4f7a2b93-8c15-4e06-b3d9-1a5e8c0f7b62',
          created_by: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
          created_by_name: '管理者',
          title: 'エージェントのインストールに失敗する',
          description: 'Linuxサーバーでインストールスクリプトを実行すると exit code 1 で失敗します。',
          category: 'installation',
          priority: 'high',
          status: 'open',
          comment_count: 0,
          created_at: '2026-03-21T09:00:00Z',
          updated_at: '2026-03-21T09:00:00Z'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/support/tickets/:id',
        description: '指定したチケットの詳細を取得します。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'チケットのUUID' },
        ],
        response: JSON.stringify({
          id: 'uuid-xxxx',
          title: 'エージェントのインストールに失敗する',
          description: '...',
          category: 'installation',
          priority: 'high',
          status: 'in_progress',
          assigned_to_name: 'サポート担当者',
          comment_count: 3,
          created_at: '2026-03-21T09:00:00Z',
          updated_at: '2026-03-21T10:00:00Z'
        }, null, 2),
      },
      {
        method: 'PATCH',
        path: '/api/v1/support/tickets/:id',
        description: 'チケットのステータス・優先度・担当者を更新します。管理者はすべて変更可。一般ユーザーはステータスの一部のみ変更可。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'チケットのUUID' },
        ],
        requestBody: JSON.stringify({
          status: 'resolved',
          priority: 'medium',
          assigned_to: 'user-uuid'
        }, null, 2),
        response: JSON.stringify({
          id: '4f7a2b93-8c15-4e06-b3d9-1a5e8c0f7b62',
          created_by_name: '管理者',
          assigned_to: '3e9c1a75-2b48-4d0f-8615-7c2a9e4b0d38',
          assigned_to_name: 'サポート担当者',
          title: 'エージェントのインストールに失敗する',
          description: '...',
          category: 'installation',
          priority: 'medium',
          status: 'resolved',
          comment_count: 3,
          resolved_at: '2026-03-21T11:00:00Z',
          created_at: '2026-03-21T09:00:00Z',
          updated_at: '2026-03-21T11:00:00Z'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/support/tickets/:id/comments',
        description: 'チケットのコメント一覧を取得します。管理者は内部メモを含む全コメントを取得できます。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'チケットのUUID' },
        ],
        response: JSON.stringify([
          {
            id: 'comment-uuid',
            ticket_id: 'uuid-xxxx',
            author_name: 'サポート担当者',
            body: 'ご報告ありがとうございます。確認中です。',
            is_internal: false,
            created_at: '2026-03-21T10:00:00Z'
          }
        ], null, 2),
      },
      {
        method: 'POST',
        path: '/api/v1/support/tickets/:id/comments',
        description: 'チケットにコメントを追加します。管理者は is_internal: true で内部メモを作成できます。',
        parameters: [
          { name: 'id', type: 'string', required: true, description: 'チケットのUUID' },
        ],
        requestBody: JSON.stringify({
          body: 'ご確認ありがとうございます。詳細なログを添付します。',
          is_internal: false
        }, null, 2),
        response: JSON.stringify({
          id: '1d6b8e04-7a29-4c53-9f80-3b5c2d7a6e91',
          ticket_id: '4f7a2b93-8c15-4e06-b3d9-1a5e8c0f7b62',
          author_id: '9f2b1c40-5a3d-4f18-b7e2-0c8a6d1e4b93',
          author_name: '管理者',
          body: 'ご確認ありがとうございます。',
          is_internal: false,
          created_at: '2026-03-21T11:00:00Z'
        }, null, 2),
      },
      {
        method: 'GET',
        path: '/api/v1/admin/support/stats',
        description: 'サポートチケットの統計情報を返します（管理者のみ）。',
        parameters: [],
        response: JSON.stringify({
          open: 12,
          in_progress: 5,
          resolved: 89,
          closed: 203,
          critical: 1,
          high: 4,
          avg_resolve_hours: 6.3
        }, null, 2),
      },
    ],
  },
]

// ─── CopyButton ─────────────────────────────────────────────────────────────

function CopyButton({ text, label = 'コピー' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs bg-[#1e2d42] hover:bg-[#253650] border border-[#2a3f5f] text-[#7d92b0] hover:text-[#e2e8f4] transition-all duration-150"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'コピー済み' : label}
    </button>
  )
}

// ─── Generate curl command ───────────────────────────────────────────────────

function buildCurl(method: string, path: string, body?: string): string {
  const url = `${BASE_URL}${path}`
  const bodyFlag = body && method !== 'GET' && !body.startsWith('//')
    ? ` \\\n  -d '${body}'`
    : ''
  return `curl -X ${method} '${url}' \\
  -H 'Authorization: Bearer YOUR_TOKEN' \\
  -H 'Content-Type: application/json'${bodyFlag}`
}

// ─── TryItOut ────────────────────────────────────────────────────────────────

function TryItOut({ ep }: { ep: Endpoint }) {
  const [token, setToken] = useState('')
  const [body, setBody] = useState(ep.requestBody ?? '')
  const [response, setResponse] = useState('')
  const [status, setStatus] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    setLoading(true)
    setResponse('')
    setStatus(null)
    try {
      const path = ep.path.replace(/:(\w+)/g, 'EXAMPLE_ID')
      const res = await fetch(`${BASE_URL}${path}`, {
        method: ep.method,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        ...(ep.method !== 'GET' && body && !body.startsWith('//') ? { body } : {}),
      })
      setStatus(res.status)
      const text = await res.text()
      try {
        setResponse(JSON.stringify(JSON.parse(text), null, 2))
      } catch {
        setResponse(text)
      }
    } catch (e) {
      setResponse(String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="mt-4 space-y-3">
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={token}
          onChange={e => setToken(e.target.value)}
          placeholder="Bearer トークンを入力 (省略可)"
          className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-xs text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#2a3f5a] font-mono"
        />
        <button
          onClick={run}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d]/20 hover:bg-[#e8002d]/30 border border-[#e8002d]/40 text-[#e8002d] text-xs rounded-sm transition-colors disabled:opacity-50"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          実行
        </button>
      </div>

      {ep.method !== 'GET' && (
        <div>
          <p className="text-[10px] text-[#3d5068] uppercase tracking-wider mb-1">リクエストボディ</p>
          <textarea
            value={body}
            onChange={e => setBody(e.target.value)}
            rows={4}
            className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm p-2 text-xs text-[#e2e8f4] font-mono focus:outline-hidden focus:border-[#2a3f5a] resize-none"
          />
        </div>
      )}

      {response && (
        <div>
          <div className="flex items-center gap-2 mb-1">
            <p className="text-[10px] text-[#3d5068] uppercase tracking-wider">レスポンス</p>
            {status !== null && (
              <span className={`text-[10px] px-1.5 py-0.5 rounded-sm font-mono ${status < 300 ? 'bg-[#22c55e]/20 text-[#22c55e]' : 'bg-[#e8002d]/20 text-[#e8002d]'}`}>
                {status}
              </span>
            )}
          </div>
          <pre className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 text-xs font-mono text-[#e2e8f4] overflow-x-auto max-h-48 overflow-y-auto">
            {response}
          </pre>
        </div>
      )}
    </div>
  )
}

// ─── EndpointCard ────────────────────────────────────────────────────────────

function EndpointCard({ ep }: { ep: Endpoint }) {
  const [open, setOpen] = useState(false)
  const [tryIt, setTryIt] = useState(false)
  const curl = buildCurl(ep.method, ep.path, ep.requestBody)

  return (
    <div className="border border-[#1e2d42] rounded-lg overflow-hidden bg-[#0d1220]">
      {/* Header row */}
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[#111b2e] transition-colors"
      >
        <span className={`text-[11px] font-bold px-2 py-0.5 rounded-sm font-mono w-16 text-center shrink-0 ${METHOD_COLORS[ep.method] ?? ''}`}>
          {ep.method}
        </span>
        <code className="text-[#e2e8f4] text-sm font-mono flex-1 text-left">{ep.path}</code>
        <span className="text-[#7d92b0] text-xs hidden sm:block text-right max-w-xs truncate">{ep.description}</span>
        <ChevronRight className={`w-4 h-4 text-[#3d5068] shrink-0 transition-transform ${open ? 'rotate-90' : ''}`} />
      </button>

      {/* Expanded detail */}
      {open && (
        <div className="border-t border-[#1e2d42] px-4 py-4 space-y-5">
          <p className="text-[#7d92b0] text-sm">{ep.description}</p>

          {/* Parameters */}
          {ep.parameters && ep.parameters.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#3d5068] mb-2">パラメーター</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-sm border-collapse">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      <th className="text-left py-2 pr-4 text-[#7d92b0] font-medium text-xs">名前</th>
                      <th className="text-left py-2 pr-4 text-[#7d92b0] font-medium text-xs">型</th>
                      <th className="text-left py-2 pr-4 text-[#7d92b0] font-medium text-xs">必須</th>
                      <th className="text-left py-2 text-[#7d92b0] font-medium text-xs">説明</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ep.parameters.map(p => (
                      <tr key={p.name} className="border-b border-[#1e2d42]/50">
                        <td className="py-2 pr-4">
                          <code className="text-[#e8002d] text-xs font-mono">{p.name}</code>
                        </td>
                        <td className="py-2 pr-4">
                          <span className="text-[#7d92b0] text-xs font-mono">{p.type}</span>
                        </td>
                        <td className="py-2 pr-4">
                          {p.required
                            ? <span className="text-xs px-1.5 py-0.5 rounded-sm bg-[#e8002d]/20 text-[#e8002d] border border-[#e8002d]/30">必須</span>
                            : <span className="text-xs text-[#3d5068]">任意</span>
                          }
                        </td>
                        <td className="py-2 text-[#7d92b0] text-xs">{p.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Request Body */}
          {ep.requestBody && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[#3d5068]">リクエストボディ</h4>
                <CopyButton text={ep.requestBody} />
              </div>
              <pre className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 text-[#e2e8f4] text-xs font-mono overflow-x-auto leading-relaxed">
                {ep.requestBody}
              </pre>
            </div>
          )}

          {/* Response */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#3d5068]">レスポンス例</h4>
              <CopyButton text={ep.response} />
            </div>
            <pre className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 text-[#e2e8f4] text-xs font-mono overflow-x-auto leading-relaxed">
              {ep.response}
            </pre>
          </div>

          {/* curl */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#3d5068]">curl コマンド</h4>
              <CopyButton text={curl} label="curlコピー" />
            </div>
            <pre className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 text-[#7d92b0] text-xs font-mono overflow-x-auto leading-relaxed">
              {curl}
            </pre>
          </div>

          {/* Try it out */}
          <div className="border-t border-[#1e2d42] pt-4">
            <button
              onClick={() => setTryIt(v => !v)}
              className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-sm border transition-colors ${
                tryIt
                  ? 'bg-[#1e2d42] border-[#2a3f5a] text-[#e2e8f4]'
                  : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#2a3f5a] hover:text-[#e2e8f4]'
              }`}
            >
              {tryIt ? <X className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              {tryIt ? '閉じる' : 'Try it out'}
            </button>
            {tryIt && <TryItOut ep={ep} />}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function ApiDocsPage() {
  const [activeSection, setActiveSection] = useState('authentication')
  const [searchQuery, setSearchQuery] = useState('')
  const sectionRefs = useRef<Record<string, HTMLElement | null>>({})

  const scrollTo = (id: string) => {
    setActiveSection(id)
    setSearchQuery('')
    const el = sectionRefs.current[id]
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  // 検索フィルタリング
  const filteredGroups = useMemo(() => {
    if (!searchQuery.trim()) return endpointGroups
    const q = searchQuery.toLowerCase()
    return endpointGroups
      .map(group => ({
        ...group,
        endpoints: group.endpoints.filter(ep =>
          ep.path.toLowerCase().includes(q) ||
          ep.description.toLowerCase().includes(q) ||
          ep.method.toLowerCase().includes(q)
        ),
      }))
      .filter(g => g.endpoints.length > 0)
  }, [searchQuery])

  return (
    <div className="flex h-full bg-[#070d19] text-[#e2e8f4]">

      {/* ── Left Sidebar ─────────────────────────────────────────── */}
      <div className="w-52 shrink-0 border-r border-[#1e2d42] flex flex-col sticky top-0 h-screen overflow-y-auto">
        <div className="p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-[#e8002d]" />
            <span className="text-sm font-semibold">API ドキュメント</span>
          </div>
          <p className="text-[10px] text-[#3d5068] mt-1 font-mono truncate">{BASE_URL}</p>
        </div>
        <nav className="p-3 space-y-0.5">
          {endpointGroups.map(group => (
            <button
              key={group.id}
              onClick={() => scrollTo(group.id)}
              className={`w-full text-left px-3 py-2 rounded-sm text-xs transition-all duration-100 flex items-center justify-between
                ${activeSection === group.id
                  ? 'bg-[#1d2f4a] text-white'
                  : 'text-[#7d92b0] hover:bg-[#111b2e] hover:text-[#e2e8f4]'
                }`}
            >
              <span>{group.label}</span>
              <span className="text-[10px] text-[#3d5068]">{group.endpoints.length}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* ── Main Content ─────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">

        {/* Page Header */}
        <div className="border-b border-[#1e2d42] p-6 bg-[#0d1220]">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                API ドキュメント
                <span className="text-xs font-normal px-2 py-1 rounded-sm bg-[#e8002d]/20 text-[#e8002d] border border-[#e8002d]/30 font-mono">
                  v1.0
                </span>
              </h1>
              <p className="text-[#7d92b0] text-sm mt-1">
                Kizashi REST API リファレンス
              </p>
            </div>
            <div className="text-right">
              <p className="text-xs text-[#3d5068] uppercase tracking-wider">ベースURL</p>
              <code className="text-sm font-mono text-[#7d92b0]">{BASE_URL}</code>
            </div>
          </div>

          {/* Search */}
          <div className="mt-4 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="エンドポイントを検索... (例: /alerts, POST, チケット)"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg pl-9 pr-4 py-2 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#2a3f5a]"
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-[#3d5068] hover:text-[#7d92b0]">
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Authentication note */}
          <div className="mt-4 p-4 rounded-lg bg-[#070d19] border border-[#1e2d42]">
            <h3 className="text-sm font-semibold text-[#e2e8f4] mb-2">認証</h3>
            <p className="text-xs text-[#7d92b0] mb-3">
              すべてのAPIリクエストには、リクエストヘッダーにJWT Bearerトークンが必要です。
              <code className="text-[#e8002d] mx-1 font-mono">/api/v1/auth/login</code>
              でトークンを取得してください。
            </p>
            <div className="flex items-center gap-3">
              <pre className="flex-1 bg-[#0d1220] border border-[#1e2d42] rounded-sm p-2.5 text-xs font-mono text-[#7d92b0] overflow-x-auto">
                {`Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`}
              </pre>
              <CopyButton text="Authorization: Bearer YOUR_TOKEN" />
            </div>
          </div>
        </div>

        {/* Endpoint Groups */}
        <div className="p-6 space-y-10">
          {searchQuery && filteredGroups.length === 0 && (
            <div className="text-center py-16 text-[#3d5068] text-sm">
              <Search className="w-8 h-8 mx-auto mb-3 opacity-30" />
              <p>&quot;{searchQuery}&quot; に一致するエンドポイントはありません</p>
            </div>
          )}
          {filteredGroups.map(group => (
            <section
              key={group.id}
              ref={el => { sectionRefs.current[group.id] = el }}
            >
              <div className="flex items-center gap-3 mb-4">
                <h2 className="text-lg font-bold text-white">{group.label}</h2>
                <span className="text-xs text-[#3d5068] font-mono">
                  {group.endpoints.length} エンドポイント
                </span>
                <div className="flex-1 h-px bg-[#1e2d42]" />
              </div>
              <div className="space-y-3">
                {group.endpoints.map((ep, i) => (
                  <EndpointCard key={`${group.id}-${i}`} ep={ep} />
                ))}
              </div>
            </section>
          ))}
        </div>

        {/* Footer */}
        <div className="border-t border-[#1e2d42] p-6 text-center">
          <p className="text-xs text-[#3d5068]">
            Kizashi API v1.0 &mdash; すべてのリクエストはTLSが必要です。
            レート制限は認証ユーザーあたり 1000 req/min です。
          </p>
        </div>
      </div>
    </div>
  )
}
