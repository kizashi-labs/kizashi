# EDR Platform API Routes Audit

**Source files:** `server/internal/api/router.go`, `server/cmd/api/main.go`
**Audit date:** 2026-03-17
**Base path:** `/api/v1` (unless noted)

---

## 1. Total Route Count

| Method   | Count |
|----------|-------|
| GET      | 104   |
| POST     | 64    |
| PUT      | 36    |
| PATCH    | 14    |
| DELETE   | 35    |
| **Total**| **253** |

> Note: pprof endpoints and static file mounts (`/docs`, `/downloads`) are excluded from the count. Routes behind conditional `if s.handlers.X != nil` guards are included — all handlers are wired in `main.go`.

---

## 2. Routes by Category

### Authentication (`/auth`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| POST | `/api/v1/auth/login` | `AuthHandler.Login` | No |
| POST | `/api/v1/auth/refresh` | `AuthHandler.Refresh` | No |
| POST | `/api/v1/auth/logout` | `AuthHandler.Logout` | No |
| POST | `/api/v1/auth/mfa/verify` | `AuthHandler.VerifyMFA` | No |
| POST | `/api/v1/auth/password-policy/validate` | `PasswordPolicyHandler.ValidatePassword` | No |
| GET  | `/api/v1/auth/invite/info` | `InvitationHandler.Info` | No |
| POST | `/api/v1/auth/invite/accept` | `InvitationHandler.Accept` | No |
| POST | `/api/v1/auth/mfa/setup` | `AuthHandler.SetupMFA` | Yes |
| POST | `/api/v1/auth/mfa/confirm` | `AuthHandler.ConfirmMFA` | Yes |
| POST | `/api/v1/auth/mfa/disable` | `AuthHandler.DisableMFA` | Yes |
| POST | `/api/v1/auth/mfa/email/send` | `EmailMFAHandler.SendOTP` | No |
| POST | `/api/v1/auth/mfa/email/verify` | `EmailMFAHandler.VerifyOTP` | No |
| POST | `/api/v1/auth/mfa/email/enable` | `EmailMFAHandler.EnableEmailMFA` | Yes |
| POST | `/api/v1/auth/mfa/email/disable` | `EmailMFAHandler.DisableEmailMFA` | Yes |
| POST | `/api/v1/auth/password-reset/request` | `PasswordResetHandler.RequestReset` | No |
| POST | `/api/v1/auth/password-reset/confirm` | `PasswordResetHandler.ConfirmReset` | No |
| GET  | `/api/v1/auth/sso/providers` | `SSOHandler.ListProviders` | No |
| POST | `/api/v1/auth/sso/callback` | `SSOHandler.SSOCallback` | No |
| POST | `/api/v1/auth/email-verification/confirm` | `EmailVerificationHandler.ConfirmVerification` | No |
| POST | `/api/v1/auth/email-verification/send` | `EmailVerificationHandler.SendVerification` | Yes |
| GET  | `/api/v1/auth/email-verification/status` | `EmailVerificationHandler.GetStatus` | Yes |

### Agents (`/agents`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/agents` | `AgentHandler.List` | Yes |
| GET    | `/api/v1/agents/:id` | `AgentHandler.Get` | Yes |
| PUT    | `/api/v1/agents/:id` | `AgentHandler.Update` | Yes |
| DELETE | `/api/v1/agents/:id` | `AgentHandler.Delete` | Yes |
| POST   | `/api/v1/agents/:id/isolate` | `AgentHandler.Isolate` | Yes |
| POST   | `/api/v1/agents/:id/unisolate` | `AgentHandler.Unisolate` | Yes |
| GET    | `/api/v1/agents/:id/events` | `EventHandler.ListByAgent` | Yes |
| GET    | `/api/v1/agents/:id/processes` | `AgentHandler.GetProcesses` | Yes |
| POST   | `/api/v1/agents/:id/scan` | `AgentHandler.TriggerScan` | Yes |
| POST   | `/api/v1/agents/:id/kill-process` | `AgentHandler.KillProcess` | Yes |
| GET    | `/api/v1/agents/:id/response-history` | `AgentHandler.GetResponseHistory` | Yes |
| GET    | `/api/v1/agents/:id/risk-score` | `AgentHandler.RiskScore` | Yes |
| GET    | `/api/v1/agents/:id/process-tree` | `AgentHandler.ProcessTree` | Yes |
| GET    | `/api/v1/agents/:id/timeline` | `EventHandler.AgentTimeline` | Yes |
| GET    | `/api/v1/agents/:id/software` | `SoftwareInventoryHandler.ListByAgent` | Yes |
| POST   | `/api/v1/agents/:id/software` | `SoftwareInventoryHandler.Report` | Yes |
| GET    | `/api/v1/agents/:id/tags` | `AgentTagHandler.ListTags` | Yes |
| POST   | `/api/v1/agents/:id/tags` | `AgentTagHandler.AddTag` | Yes |
| DELETE | `/api/v1/agents/:id/tags/:tag` | `AgentTagHandler.RemoveTag` | Yes |
| GET    | `/api/v1/agents/:id/update-check` | `UpdateHandler.UpdateCheck` | Yes |
| GET    | `/api/v1/agents/:id/effective-config` | `AgentConfigHandler.GetEffective` | Yes |
| PUT    | `/api/v1/agents/:id/config-override` | `AgentConfigHandler.UpdateOverride` | Yes |
| POST   | `/api/v1/agents/:id/cert/enroll` | `CertHandler.Enroll` | Yes |
| GET    | `/api/v1/agents/:id/cert/ca` | `CertHandler.GetCA` | No |
| GET    | `/api/v1/agents/risk-scores` | `AgentHandler.RiskScores` | Yes |
| GET    | `/api/v1/agents-risk-scores` | `AgentHandler.RiskScores` | Yes |
| GET    | `/api/v1/agents/download` | `DownloadHandler.GetBinary` | Yes |
| GET    | `/api/v1/agents/download/checksum` | `DownloadHandler.GetChecksum` | Yes |
| POST   | `/api/v1/agents/update` | `UpdateHandler.TriggerUpdate` | Yes (Admin) |
| GET    | `/api/v1/agent-tags` | `AgentTagHandler.ListAllTags` | Yes |
| GET    | `/api/v1/agent-tags/:tag/agents` | `AgentTagHandler.ListByTag` | Yes |
| GET    | `/api/v1/agent-config/schema` | `AgentConfigHandler.GetSchema` | Yes |

### Agent Groups (`/groups`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/groups` | `AgentHandler.ListGroups` | Yes |
| POST   | `/api/v1/groups` | `AgentHandler.CreateGroup` | Yes |
| PUT    | `/api/v1/groups/:id` | `AgentHandler.UpdateGroup` | Yes |
| DELETE | `/api/v1/groups/:id` | `AgentHandler.DeleteGroup` | Yes |
| PUT    | `/api/v1/groups/:id/policy` | `AgentPolicyHandler.Assign` | Yes (Admin) |

### Alerts (`/alerts`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/alerts` | `AlertHandler.List` | Yes |
| GET    | `/api/v1/alerts/stats` | `AlertHandler.Stats` | Yes |
| GET    | `/api/v1/alerts/export` | `AlertHandler.Export` | Yes |
| GET    | `/api/v1/alerts/mitre-stats` | `AlertHandler.MITREStats` | Yes |
| GET    | `/api/v1/alerts/:id` | `AlertHandler.Get` | Yes |
| PUT    | `/api/v1/alerts/:id` | `AlertHandler.Update` | Yes |
| PUT    | `/api/v1/alerts/:id/assign` | `AlertHandler.Assign` | Yes |
| GET    | `/api/v1/alerts/:id/related` | `AlertHandler.Related` | Yes |
| GET    | `/api/v1/alerts/:id/history` | `AlertHandler.StatusHistory` | Yes |
| GET    | `/api/v1/alerts/:id/graph` | `AlertHandler.Graph` | Yes |
| GET    | `/api/v1/alerts/:id/comments` | `AlertHandler.ListComments` | Yes |
| POST   | `/api/v1/alerts/:id/comments` | `AlertHandler.AddComment` | Yes |
| DELETE | `/api/v1/alerts/:id/comments/:comment_id` | `AlertCommentsHandler.Delete` | Yes |
| POST   | `/api/v1/alerts/bulk-update` | `AlertHandler.BulkUpdate` | Yes |
| POST   | `/api/v1/alerts/bulk-status` | `AlertBulkHandler.BulkStatus` | Yes |
| POST   | `/api/v1/alerts/bulk-delete` | `AlertBulkHandler.BulkDelete` | Yes |
| POST   | `/api/v1/alerts/bulk-tag` | `AlertBulkHandler.BulkTag` | Yes |
| POST   | `/api/v1/alerts/bulk-assign` | `AlertBulkHandler.BulkAssign` | Yes |
| POST   | `/api/v1/alerts/:id/status` | `AlertActionHandler.UpdateStatus` | Yes |
| POST   | `/api/v1/alerts/:id/enrich` | `AlertActionHandler.Enrich` | Yes |
| POST   | `/api/v1/alerts/:id/analyze` | `AIHandler.ReanalyzeAlert` | Yes |
| POST   | `/api/v1/alerts/:id/chat` | `AIHandler.ChatAboutAlert` | Yes |

### Events (`/events`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/events` | `EventHandler.List` | Yes |
| GET    | `/api/v1/events/dns` | `EventHandler.ListDNS` | Yes |
| GET    | `/api/v1/events/network-stats` | `EventHandler.NetworkStats` | Yes |
| GET    | `/api/v1/events/file-stats` | `EventHandler.FileStats` | Yes |
| GET    | `/api/v1/events/auth-stats` | `EventHandler.AuthStats` | Yes |
| GET    | `/api/v1/events/:id` | `EventHandler.Get` | Yes |
| POST   | `/api/v1/events/search` | `EventHandler.Search` | Yes |
| GET    | `/api/v1/events/timeline` | `EventHandler.Timeline` | Yes |

### Detection Rules (`/rules`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/rules` | `RuleHandler.List` | Yes |
| GET    | `/api/v1/rules/:id` | `RuleHandler.Get` | Yes |
| POST   | `/api/v1/rules` | `RuleHandler.Create` | Yes |
| PUT    | `/api/v1/rules/:id` | `RuleHandler.Update` | Yes |
| DELETE | `/api/v1/rules/:id` | `RuleHandler.Delete` | Yes |
| POST   | `/api/v1/rules/:id/test` | `RuleHandler.Test` | Yes |
| PUT    | `/api/v1/rules/:id/toggle` | `RuleHandler.Toggle` | Yes |
| POST   | `/api/v1/rules/import` | `RuleHandler.Import` | Yes |
| POST   | `/api/v1/rules/sync` | `RuleHandler.SyncCommunity` | Yes |
| GET    | `/api/v1/rules/sync/status` | `RuleHandler.SyncStatus` | Yes |
| POST   | `/api/v1/rules/ai-generate` | `AIHandler.GenerateRule` | Yes |
| POST   | `/api/v1/rules/import/sigma` | `SigmaHandler.ImportSigma` | Yes |
| POST   | `/api/v1/rules/import/sigma/preview` | `SigmaHandler.ParsePreview` | Yes |
| GET    | `/api/v1/rules/export` | `RulesIEHandler.Export` | Yes |
| GET    | `/api/v1/rules/counts` | `RulesIEHandler.Counts` | Yes |
| POST   | `/api/v1/rules/import/bulk` | `RulesIEHandler.Import` | Yes |
| POST   | `/api/v1/rules/import/dry-run` | `RulesIEHandler.ImportDryRun` | Yes |
| POST   | `/api/v1/rules/test` | `RuleTestHandler.Test` | Yes |

### Reports (`/reports`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/reports` | `ReportHandler.List` | Yes |
| POST   | `/api/v1/reports` | `ReportHandler.Generate` | Yes |
| GET    | `/api/v1/reports/:id` | `ReportHandler.Download` | Yes |
| GET    | `/api/v1/reports/:id/pdf` | `ReportHandler.DownloadPDF` | Yes |
| DELETE | `/api/v1/reports/:id` | `ReportHandler.Delete` | Yes |
| GET    | `/api/v1/reports/jobs/:id` | `ReportHandler.JobStatus` | Yes |
| GET    | `/api/v1/reports/schedules` | `ReportScheduleHandler.List` | Yes |
| POST   | `/api/v1/reports/schedules` | `ReportScheduleHandler.Create` | Yes |
| PUT    | `/api/v1/reports/schedules/:id` | `ReportScheduleHandler.Update` | Yes |
| DELETE | `/api/v1/reports/schedules/:id` | `ReportScheduleHandler.Delete` | Yes |
| PUT    | `/api/v1/reports/schedules/:id/toggle` | `ReportScheduleHandler.Toggle` | Yes |
| GET    | `/api/v1/reports/export/alerts` | `ReportExportHandler.ExportAlerts` | Yes |
| GET    | `/api/v1/reports/export/compliance` | `ReportExportHandler.ExportCompliance` | Yes |
| GET    | `/api/v1/reports/html` | `PDFReportHandler.GenerateHTML` | Yes |

### Quarantine (`/quarantine`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/quarantine` | `QuarantineHandler.List` | Yes |
| POST   | `/api/v1/quarantine` | `QuarantineHandler.Record` | Yes |
| POST   | `/api/v1/quarantine/:id/restore` | `QuarantineHandler.Restore` | Yes |
| DELETE | `/api/v1/quarantine/:id` | `QuarantineHandler.Delete` | Yes |

### IOC — Indicators of Compromise (`/ioc`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/ioc` | `IOCHandler.List` | Yes |
| POST   | `/api/v1/ioc` | `IOCHandler.Create` | Yes |
| POST   | `/api/v1/ioc/import` | `IOCHandler.BulkImport` | Yes |
| GET    | `/api/v1/ioc/stats` | `IOCHandler.Stats` | Yes |
| DELETE | `/api/v1/ioc/:id` | `IOCHandler.Delete` | Yes |
| PUT    | `/api/v1/ioc/:id/toggle` | `IOCHandler.Toggle` | Yes |
| GET    | `/api/v1/ioc/check` | `IOCHandler.Check` | Yes |
| GET    | `/api/v1/ioc/ip-block` | `IPBlockHandler.List` | Yes |
| POST   | `/api/v1/ioc/ip-block` | `IPBlockHandler.Create` | Yes |
| DELETE | `/api/v1/ioc/ip-block/:id` | `IPBlockHandler.Delete` | Yes |

> `ip-block` の3ルートは 2026-07-25 追加（`/admin/ip-blocklist` のバックエンド実装、PR #538、migration 340）。本監査の他の行は 2026-03-17 時点のスナップショットのまま更新していない。

### Suppression Rules (`/suppressions`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/suppressions` | `SuppressionHandler.List` | Yes |
| POST   | `/api/v1/suppressions` | `SuppressionHandler.Create` | Yes |
| DELETE | `/api/v1/suppressions/:id` | `SuppressionHandler.Delete` | Yes |
| PUT    | `/api/v1/suppressions/:id/toggle` | `SuppressionHandler.Toggle` | Yes |

### Incidents (`/incidents`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/incidents` | `IncidentHandler.List` | Yes |
| POST   | `/api/v1/incidents` | `IncidentHandler.Create` | Yes |
| GET    | `/api/v1/incidents/:id` | `IncidentHandler.Get` | Yes |
| PUT    | `/api/v1/incidents/:id` | `IncidentHandler.Update` | Yes |
| DELETE | `/api/v1/incidents/:id` | `IncidentHandler.Delete` | Yes |
| POST   | `/api/v1/incidents/:id/alerts` | `IncidentHandler.LinkAlert` | Yes |
| DELETE | `/api/v1/incidents/:id/alerts/:alert_id` | `IncidentHandler.UnlinkAlert` | Yes |
| GET    | `/api/v1/incidents/:id/notes` | `IncidentHandler.ListNotes` | Yes |
| POST   | `/api/v1/incidents/:id/notes` | `IncidentHandler.AddNote` | Yes |
| PATCH  | `/api/v1/incidents/:id/assign` | `IncidentHandler.Assign` | Yes |
| PATCH  | `/api/v1/incidents/:id/status` | `IncidentHandler.Transition` | Yes |
| GET    | `/api/v1/incidents/:id/timeline` | `IncidentHandler.Timeline` | Yes |
| GET    | `/api/v1/incidents/:id/comments` | `IncidentCommentHandler.List` | Yes |
| POST   | `/api/v1/incidents/:id/comments` | `IncidentCommentHandler.Add` | Yes |
| DELETE | `/api/v1/incidents/:id/comments/:comment_id` | `IncidentCommentHandler.Delete` | Yes |
| POST   | `/api/v1/incidents/:id/ticket` | `SOARHandler.CreateTicket` | Yes |

### Playbooks (`/playbooks`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/playbooks` | `PlaybookHandler.List` | Yes |
| POST   | `/api/v1/playbooks` | `PlaybookHandler.Create` | Yes |
| GET    | `/api/v1/playbooks/:id` | `PlaybookHandler.Get` | Yes |
| PUT    | `/api/v1/playbooks/:id` | `PlaybookHandler.Update` | Yes |
| DELETE | `/api/v1/playbooks/:id` | `PlaybookHandler.Delete` | Yes |
| PUT    | `/api/v1/playbooks/:id/toggle` | `PlaybookHandler.Toggle` | Yes |
| GET    | `/api/v1/playbooks/:id/runs` | `PlaybookHandler.Runs` | Yes |

### Vulnerabilities (`/vulnerabilities`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/vulnerabilities` | `VulnHandler.List` | Yes |
| GET    | `/api/v1/vulnerabilities/stats` | `VulnHandler.Stats` | Yes |
| POST   | `/api/v1/vulnerabilities` | `VulnHandler.Create` | Yes |
| GET    | `/api/v1/vulnerabilities/:id` | `VulnHandler.Get` | Yes |
| PUT    | `/api/v1/vulnerabilities/:id/status` | `VulnHandler.UpdateStatus` | Yes |
| DELETE | `/api/v1/vulnerabilities/:id` | `VulnHandler.Delete` | Yes |

### Notifications (`/notifications`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/notifications/channels` | `SettingsHandler.ListChannels` | Yes |
| POST   | `/api/v1/notifications/channels` | `SettingsHandler.CreateChannel` | Yes |
| PUT    | `/api/v1/notifications/channels/:id` | `SettingsHandler.UpdateChannel` | Yes |
| DELETE | `/api/v1/notifications/channels/:id` | `SettingsHandler.DeleteChannel` | Yes |
| POST   | `/api/v1/notifications/channels/:id/test` | `SettingsHandler.TestChannel` | Yes |
| GET    | `/api/v1/notifications/preferences` | `NotificationPrefsHandler.GetPreferences` | Yes |
| PUT    | `/api/v1/notifications/preferences` | `NotificationPrefsHandler.UpsertPreferences` | Yes |

### Settings (`/settings`) — Admin Only

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/settings` | `SettingsHandler.Get` | Yes (Admin) |
| PUT    | `/api/v1/settings` | `SettingsHandler.Update` | Yes (Admin) |
| POST   | `/api/v1/settings/enrollment-token` | `SettingsHandler.RegenerateToken` | Yes (Admin) |

### Users (`/users`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/users/me` | `UsersHandler.Me` | Yes |
| PATCH  | `/api/v1/users/me` | `UsersHandler.UpdateMe` | Yes |
| PUT    | `/api/v1/users/:id/password` | `UsersHandler.UpdatePassword` | Yes |
| GET    | `/api/v1/users` | `UsersHandler.List` | Yes |
| POST   | `/api/v1/users` | `UsersHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/users/:id` | `UsersHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/users/:id` | `UsersHandler.Deactivate` | Yes (Admin) |

### Threat Intelligence Feeds (`/threat-feeds`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/threat-feeds` | `ThreatFeedHandler.List` | Yes |
| POST   | `/api/v1/threat-feeds` | `ThreatFeedHandler.Create` | Yes |
| PUT    | `/api/v1/threat-feeds/:id` | `ThreatFeedHandler.Update` | Yes |
| DELETE | `/api/v1/threat-feeds/:id` | `ThreatFeedHandler.Delete` | Yes |
| PUT    | `/api/v1/threat-feeds/:id/toggle` | `ThreatFeedHandler.Toggle` | Yes |
| POST   | `/api/v1/threat-feeds/:id/sync` | `ThreatFeedHandler.Sync` | Yes |
| GET    | `/api/v1/threat-feeds/stats` | `TIFeedSyncHandler.GetStats` | Yes |
| GET    | `/api/v1/threat-feeds/:id/history` | `TIFeedSyncHandler.GetHistory` | Yes |

### Software Inventory (`/software`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/software` | `SoftwareInventoryHandler.Search` | Yes |
| DELETE | `/api/v1/software/:id` | `SoftwareInventoryHandler.DeleteEntry` | Yes |

### Compliance (`/compliance`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/compliance/summary` | `ComplianceHandler.Summary` | Yes |
| GET    | `/api/v1/compliance/frameworks` | `ComplianceReportHandler.ListFrameworks` | Yes |
| GET    | `/api/v1/compliance/score/:framework_id` | `ComplianceReportHandler.GetScore` | Yes |
| POST   | `/api/v1/compliance/evidence` | `ComplianceReportHandler.AddEvidence` | Yes |
| GET    | `/api/v1/compliance/evidence/:control_id` | `ComplianceReportHandler.GetEvidence` | Yes |
| GET    | `/api/v1/compliance/export` | `ComplianceExportHandler.Export` | Yes |
| GET    | `/api/v1/compliance/export/summary` | `ComplianceExportHandler.ExportSummary` | Yes |
| GET    | `/api/v1/compliance/scores` | `ComplianceScoreHandler.ListScores` | Yes |
| GET    | `/api/v1/compliance/scores/:agent_id` | `ComplianceScoreHandler.GetScore` | Yes |
| POST   | `/api/v1/compliance/scores/:agent_id/compute` | `ComplianceScoreHandler.ComputeScore` | Yes |

### UEBA / SOC Metrics / Campaigns

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/ueba/summary` | `UEBAHandler.Summary` | Yes |
| GET    | `/api/v1/soc-metrics/summary` | `SOCMetricsHandler.Summary` | Yes |
| GET    | `/api/v1/soc-metrics/handover` | `SOCMetricsHandler.ShiftHandover` | Yes |
| GET    | `/api/v1/campaigns` | `CampaignsHandler.List` | Yes |
| GET    | `/api/v1/notification-history` | `NotificationHistoryHandler.List` | Yes |
| GET    | `/api/v1/notification-history/stats` | `NotificationHistoryHandler.Stats` | Yes |
| GET    | `/api/v1/search` | `SearchHandler.Search` | Yes |

### Live Response (`/agents/:id/live-response`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| POST   | `/api/v1/agents/:id/live-response/sessions` | `LiveResponseHandler.CreateSession` | Yes |
| GET    | `/api/v1/agents/:id/live-response/sessions` | `LiveResponseHandler.ListSessions` | Yes |
| DELETE | `/api/v1/agents/:id/live-response/sessions/:sid` | `LiveResponseHandler.CloseSession` | Yes |
| POST   | `/api/v1/agents/:id/live-response/sessions/:sid/exec` | `LiveResponseHandler.ExecCommand` | Yes |
| GET    | `/api/v1/agents/:id/live-response/sessions/:sid/stream` | `LiveResponseHandler.StreamOutput` | Yes (SSE) |
| GET    | `/api/v1/live-response/poll` | `LiveResponseHandler.AgentPoll` | No (token-auth) |
| POST   | `/api/v1/live-response/output` | `LiveResponseHandler.AgentOutput` | No (token-auth) |

### Live Response Command Queue (`/agents/:agent_id/commands`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/agents/:agent_id/commands` | `LiveResponseCmdHandler.ListCommands` | Yes |
| POST   | `/api/v1/agents/:agent_id/commands` | `LiveResponseCmdHandler.CreateCommand` | Yes |
| GET    | `/api/v1/agents/:agent_id/commands/:cmd_id` | `LiveResponseCmdHandler.GetCommand` | Yes |
| DELETE | `/api/v1/agents/:agent_id/commands/:cmd_id` | `LiveResponseCmdHandler.CancelCommand` | Yes |
| GET    | `/api/v1/agent/commands/poll` | `LiveResponseCmdHandler.PollCommands` | Yes |
| POST   | `/api/v1/agent/commands/:cmd_id/result` | `LiveResponseCmdHandler.SubmitResult` | Yes |

### SIEM Targets (`/siem/targets`) — Admin Only

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/siem/targets` | `SIEMHandler.List` | Yes (Admin) |
| POST   | `/api/v1/siem/targets` | `SIEMHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/siem/targets/:id` | `SIEMHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/siem/targets/:id` | `SIEMHandler.Delete` | Yes (Admin) |
| POST   | `/api/v1/siem/targets/:id/test` | `SIEMHandler.TestForward` | Yes (Admin) |

### Threat Hunting (`/threat-hunting`, `/hunt/saved`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/threat-hunting/search` | `HuntHandler.Search` | Yes |
| GET    | `/api/v1/threat-hunting/saved` | `HuntHandler.ListSavedHunts` | Yes |
| POST   | `/api/v1/threat-hunting/saved` | `HuntHandler.CreateSavedHunt` | Yes |
| DELETE | `/api/v1/threat-hunting/saved/:id` | `HuntHandler.DeleteSavedHunt` | Yes |
| POST   | `/api/v1/threat-hunting/saved/:id/run` | `HuntHandler.RecordRun` | Yes |
| GET    | `/api/v1/hunt/saved` | `SavedHuntHandler.List` | Yes |
| POST   | `/api/v1/hunt/saved` | `SavedHuntHandler.Create` | Yes |
| PUT    | `/api/v1/hunt/saved/:id` | `SavedHuntHandler.Update` | Yes |
| DELETE | `/api/v1/hunt/saved/:id` | `SavedHuntHandler.Delete` | Yes |

### Forensics (`/forensics`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| POST   | `/api/v1/forensics/jobs` | `ForensicsHandler.CreateJob` | Yes |
| GET    | `/api/v1/forensics/jobs` | `ForensicsHandler.ListJobs` | Yes |
| GET    | `/api/v1/forensics/jobs/:id` | `ForensicsHandler.GetJob` | Yes |
| GET    | `/api/v1/forensics/jobs/:id/download` | `ForensicsHandler.DownloadArtifact` | Yes |
| POST   | `/api/v1/forensics/jobs/:id/result` | `ForensicsHandler.SubmitResult` | Yes |

### Session Management (`/sessions`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/sessions` | `SessionHandler.ListSessions` | Yes |
| DELETE | `/api/v1/sessions` | `SessionHandler.RevokeAllSessions` | Yes |
| DELETE | `/api/v1/sessions/:id` | `SessionHandler.RevokeSession` | Yes |

### Agent Policies (`/agent-policies`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/agent-policies` | `AgentPolicyHandler.List` | Yes |
| GET    | `/api/v1/agent-policies/:id` | `AgentPolicyHandler.Get` | Yes |
| POST   | `/api/v1/agent-policies` | `AgentPolicyHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/agent-policies/:id` | `AgentPolicyHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/agent-policies/:id` | `AgentPolicyHandler.Delete` | Yes (Admin) |

### YARA Rules (`/yara-rules`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/yara-rules` | `YARAHandler.List` | Yes |
| GET    | `/api/v1/yara-rules/enabled` | `YARAHandler.ListEnabled` | Yes |
| GET    | `/api/v1/yara-rules/:id` | `YARAHandler.Get` | Yes |
| POST   | `/api/v1/yara-rules/:id/match` | `YARAHandler.RecordMatch` | Yes |
| POST   | `/api/v1/yara-rules` | `YARAHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/yara-rules/:id` | `YARAHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/yara-rules/:id` | `YARAHandler.Delete` | Yes (Admin) |
| PATCH  | `/api/v1/yara-rules/:id/toggle` | `YARAHandler.Toggle` | Yes (Admin) |

### FIM Rules (`/fim-rules`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/fim-rules` | `FIMHandler.List` | Yes |
| POST   | `/api/v1/fim-rules` | `FIMHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/fim-rules/:id` | `FIMHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/fim-rules/:id` | `FIMHandler.Delete` | Yes (Admin) |
| PATCH  | `/api/v1/fim-rules/:id/toggle` | `FIMHandler.Toggle` | Yes (Admin) |

### Process Block Rules (`/process-rules`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/process-rules` | `ProcessBlockHandler.List` | Yes |
| GET    | `/api/v1/process-rules/agent/:agent_id` | `ProcessBlockHandler.ListForAgent` | Yes |
| POST   | `/api/v1/process-rules` | `ProcessBlockHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/process-rules/:id` | `ProcessBlockHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/process-rules/:id` | `ProcessBlockHandler.Delete` | Yes (Admin) |
| PATCH  | `/api/v1/process-rules/:id/toggle` | `ProcessBlockHandler.Toggle` | Yes (Admin) |

### Device Events (`/device-events`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/device-events` | `DeviceHandler.List` | Yes |
| GET    | `/api/v1/device-events/stats` | `DeviceHandler.Stats` | Yes |

### API Keys (`/api-keys`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/api-keys` | `APIKeyHandler.List` | Yes |
| POST   | `/api/v1/api-keys` | `APIKeyHandler.Create` | Yes |
| DELETE | `/api/v1/api-keys/:id` | `APIKeyHandler.Revoke` | Yes |

### Cloud Workload Monitoring (`/cloud`)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/cloud/integrations` | `CloudMonitorHandler.ListIntegrations` | Yes |
| POST   | `/api/v1/cloud/integrations` | `CloudMonitorHandler.CreateIntegration` | Yes |
| PATCH  | `/api/v1/cloud/integrations/:id` | `CloudMonitorHandler.UpdateIntegration` | Yes |
| DELETE | `/api/v1/cloud/integrations/:id` | `CloudMonitorHandler.DeleteIntegration` | Yes |
| POST   | `/api/v1/cloud/integrations/:id/test` | `CloudMonitorHandler.TestConnection` | Yes |
| GET    | `/api/v1/cloud/events` | `CloudMonitorHandler.ListEvents` | Yes |

### Tenants (`/tenants`) — Admin Only

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/tenants` | `TenantHandler.List` | Yes (Admin) |
| POST   | `/api/v1/tenants` | `TenantHandler.Create` | Yes (Admin) |
| GET    | `/api/v1/tenants/:id` | `TenantHandler.Get` | Yes (Admin) |
| PATCH  | `/api/v1/tenants/:id` | `TenantHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/tenants/:id` | `TenantHandler.Delete` | Yes (Admin) |
| GET    | `/api/v1/tenants/:id/roles` | `TenantRolesHandler.List` | Yes (Admin or TenantAdmin) |
| GET    | `/api/v1/tenants/:id/roles/:user_id` | `TenantRolesHandler.Get` | Yes (Admin or TenantAdmin) |
| PUT    | `/api/v1/tenants/:id/roles/:user_id` | `TenantRolesHandler.Upsert` | Yes (Admin or TenantAdmin) |
| DELETE | `/api/v1/tenants/:id/roles/:user_id` | `TenantRolesHandler.Delete` | Yes (Admin or TenantAdmin) |

### Dashboard

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/dashboard` | `AlertHandler.Dashboard` | Yes |
| GET    | `/api/v1/preferences/dashboard` | `DashboardPrefsHandler.GetPrefs` | Yes |
| PUT    | `/api/v1/preferences/dashboard` | `DashboardPrefsHandler.UpsertPrefs` | Yes |
| GET    | `/api/v1/dashboard/layout` | `DashboardHandler.GetLayout` | Yes |
| PUT    | `/api/v1/dashboard/layout` | `DashboardHandler.SaveLayout` | Yes |
| GET    | `/api/v1/dashboard/alert-trend` | `DashboardStatsHandler.AlertTrend` | Yes |
| GET    | `/api/v1/dashboard/top-endpoints` | `DashboardStatsHandler.TopEndpoints` | Yes |
| GET    | `/api/v1/dashboard/detection-rate` | `DashboardStatsHandler.DetectionRate` | Yes |
| GET    | `/api/v1/dashboard/summary` | `DashboardStatsHandler.Summary` | Yes |

### Admin — Miscellaneous

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/audit` | `auditListHandler` | Yes (Admin) |
| GET    | `/api/v1/admin/password-policy` | `PasswordPolicyHandler.GetPolicy` | Yes (Admin) |
| PUT    | `/api/v1/admin/password-policy` | `PasswordPolicyHandler.UpdatePolicy` | Yes (Admin) |
| POST   | `/api/v1/admin/invitations` | `InvitationHandler.Create` | Yes (Admin) |
| GET    | `/api/v1/admin/invitations` | `InvitationHandler.List` | Yes (Admin) |
| DELETE | `/api/v1/admin/invitations/:id` | `InvitationHandler.Delete` | Yes (Admin) |
| GET    | `/api/v1/admin/ldap` | `LDAPHandler.GetConfig` | Yes (Admin) |
| PUT    | `/api/v1/admin/ldap` | `LDAPHandler.SaveConfig` | Yes (Admin) |
| POST   | `/api/v1/admin/ldap/test` | `LDAPHandler.TestConnection` | Yes (Admin) |
| POST   | `/api/v1/admin/ldap/sync` | `LDAPHandler.SyncUsers` | Yes (Admin) |
| GET    | `/api/v1/admin/sso` | `SSOHandler.ListConfigs` | Yes (Admin) |
| POST   | `/api/v1/admin/sso` | `SSOHandler.CreateConfig` | Yes (Admin) |
| PUT    | `/api/v1/admin/sso/:id` | `SSOHandler.UpdateConfig` | Yes (Admin) |
| DELETE | `/api/v1/admin/sso/:id` | `SSOHandler.DeleteConfig` | Yes (Admin) |
| POST   | `/api/v1/admin/sso/:id/test` | `SSOHandler.TestConfig` | Yes (Admin) |
| POST   | `/api/v1/admin/elasticsearch/test` | `ESHandler.Test` | Yes (Admin) |
| POST   | `/api/v1/admin/elasticsearch/flush` | `ESHandler.Flush` | Yes (Admin) |
| GET    | `/api/v1/admin/notification-templates` | `NotificationTemplateHandler.List` | Yes (Admin) |
| POST   | `/api/v1/admin/notification-templates` | `NotificationTemplateHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/admin/notification-templates/:id` | `NotificationTemplateHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/admin/notification-templates/:id` | `NotificationTemplateHandler.Delete` | Yes (Admin) |
| GET    | `/api/v1/admin/notifications` | `NotificationHandler.List` | Yes (Admin) |
| POST   | `/api/v1/admin/notifications` | `NotificationHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/admin/notifications/:id` | `NotificationHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/admin/notifications/:id` | `NotificationHandler.Delete` | Yes (Admin) |
| POST   | `/api/v1/admin/notifications/:id/test` | `NotificationHandler.Test` | Yes (Admin) |
| GET    | `/api/v1/admin/backups` | `BackupHandler.List` | Yes (Admin) |
| POST   | `/api/v1/admin/backups` | `BackupHandler.Create` | Yes (Admin) |
| DELETE | `/api/v1/admin/backups/:name` | `BackupHandler.Delete` | Yes (Admin) |
| GET    | `/api/v1/admin/backups/:name/download` | `BackupHandler.Download` | Yes (Admin) |

### Correlation / Escalation / Assignment Rules

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/correlation-rules` | `CorrelationHandler.List` | Yes (Admin) |
| POST   | `/api/v1/correlation-rules` | `CorrelationHandler.Create` | Yes (Admin) |
| GET    | `/api/v1/correlation-rules/:id` | `CorrelationHandler.Get` | Yes (Admin) |
| PUT    | `/api/v1/correlation-rules/:id` | `CorrelationHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/correlation-rules/:id` | `CorrelationHandler.Delete` | Yes (Admin) |
| PUT    | `/api/v1/correlation-rules/:id/toggle` | `CorrelationHandler.Toggle` | Yes (Admin) |
| GET    | `/api/v1/escalation-rules` | `EscalationRuleHandler.List` | Yes (Admin) |
| POST   | `/api/v1/escalation-rules` | `EscalationRuleHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/escalation-rules/:id` | `EscalationRuleHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/escalation-rules/:id` | `EscalationRuleHandler.Delete` | Yes (Admin) |
| PATCH  | `/api/v1/escalation-rules/:id/toggle` | `EscalationRuleHandler.Toggle` | Yes (Admin) |
| GET    | `/api/v1/alert-assign-rules` | `AlertAssignHandler.List` | Yes |
| POST   | `/api/v1/alert-assign-rules` | `AlertAssignHandler.Create` | Yes |
| PUT    | `/api/v1/alert-assign-rules/:id` | `AlertAssignHandler.Update` | Yes |
| DELETE | `/api/v1/alert-assign-rules/:id` | `AlertAssignHandler.Delete` | Yes |

### Webhooks (`/webhooks`) — Admin Only

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/webhooks` | `WebhookHandler.List` | Yes (Admin) |
| POST   | `/api/v1/webhooks` | `WebhookHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/webhooks/:id` | `WebhookHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/webhooks/:id` | `WebhookHandler.Delete` | Yes (Admin) |
| PATCH  | `/api/v1/webhooks/:id/toggle` | `WebhookHandler.Toggle` | Yes (Admin) |
| POST   | `/api/v1/webhooks/:id/test` | `WebhookHandler.Test` | Yes (Admin) |

### Risk Action Rules (`/risk-actions`) — Admin Only

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/risk-actions` | `RiskActionHandler.List` | Yes (Admin) |
| POST   | `/api/v1/risk-actions` | `RiskActionHandler.Create` | Yes (Admin) |
| PUT    | `/api/v1/risk-actions/:id` | `RiskActionHandler.Update` | Yes (Admin) |
| DELETE | `/api/v1/risk-actions/:id` | `RiskActionHandler.Delete` | Yes (Admin) |
| PATCH  | `/api/v1/risk-actions/:id/toggle` | `RiskActionHandler.Toggle` | Yes (Admin) |

### SOAR (`/soar`) — Admin Only (configs)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/soar/configs` | `SOARHandler.ListConfigs` | Yes (Admin) |
| POST   | `/api/v1/soar/configs` | `SOARHandler.CreateConfig` | Yes (Admin) |
| PATCH  | `/api/v1/soar/configs/:id` | `SOARHandler.UpdateConfig` | Yes (Admin) |
| DELETE | `/api/v1/soar/configs/:id` | `SOARHandler.DeleteConfig` | Yes (Admin) |
| POST   | `/api/v1/soar/configs/:id/test` | `SOARHandler.TestConfig` | Yes (Admin) |

### Threat Intel — VirusTotal

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| POST   | `/api/v1/intel/vt/lookup` | `VirusTotalHandler.Lookup` | Yes |

### User Preferences

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/user/preferences` | `UserPreferencesHandler.Get` | Yes |
| PUT    | `/api/v1/user/preferences` | `UserPreferencesHandler.Update` | Yes |

### Ingest (Wazuh — token auth, no JWT)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| POST   | `/api/v1/ingest/wazuh` | `IngestHandler.WazuhAlert` | No (token-auth) |
| GET    | `/api/v1/ingest/wazuh/status` | `IngestHandler.WazuhStatus` | No (token-auth) |

### Audit Log Export

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/audit-logs/export` | `AuditExportHandler.Export` | Yes |

### Agent Installer Scripts (no auth)

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/api/v1/installer/linux/:arch` | `InstallerHandler.LinuxInstaller` | No |
| GET    | `/api/v1/installer/windows/:arch` | `InstallerHandler.WindowsInstaller` | No |
| GET    | `/api/v1/installer/download/:os/:arch` | `InstallerHandler.Download` | No |

### System / Infrastructure

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET    | `/health` | inline handler | No |
| GET    | `/api/v1/health/detailed` | `DetailedHealthHandler.DetailedHealth` | No |
| GET    | `/metrics` | Prometheus `promhttp.Handler` | No |
| GET    | `/api/v1/openapi.yaml` | inline file serve | No |
| GET    | `/api/v1/docs` | `DocsHandler.ServeUI` | No |
| GET    | `/api/v1/docs/openapi.yaml` | `DocsHandler.ServeSpec` | No |
| GET    | `/debug/pprof/*` | `net/http/pprof` handlers | No (conditional on `ENABLE_PPROF=true`) |

---

## 3. Stub / TODO Endpoints

The following endpoints return `501 Not Implemented` or contain prominent TODO/stub comments indicating they are not fully implemented for production use:

| Method | Path | Handler | Issue |
|--------|------|---------|-------|
| POST | `/api/v1/rules/import/bulk` | `RulesIEHandler.Import` | Returns `501 Not Implemented` explicitly; comment: "stub - returns 501 for now with helpful message" |
| POST | `/api/v1/rules/import/dry-run` | `RulesIEHandler.ImportDryRun` | Returns `501 Not Implemented` explicitly; comment: "stub" |
| GET  | `/api/v1/installer/download/:os/:arch` | `InstallerHandler.Download` | Returns `501 Not Implemented`; comment: "In production this would serve the actual binary. For now returns a stub response." |
| POST | `/api/v1/auth/sso/callback` | `SSOHandler.SSOCallback` | TODO comment: "Replace this entire stub with real SAML/OIDC assertion processing." Issues a demo JWT instead of real SSO validation. |
| GET  | `/api/v1/admin/ldap` | `LDAPHandler.GetConfig` | TODO comment: "load from DB/config store" — config is not persisted. |
| POST | `/api/v1/admin/ldap/test` | `LDAPHandler.TestConnection` | TODO comment: "actual LDAP bind test" — not performing real LDAP bind. |
| POST | `/api/v1/auth/mfa/email/send` | `EmailMFAHandler.SendOTP` | Uses `stubEmailSender` when no real SMTP sender is configured — OTP is logged rather than emailed. |

---

## 4. Public Endpoints (No Authentication Required)

These endpoints are reachable without a JWT or API key:

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/v1/auth/login` | Rate-limited (10/5 min per IP) |
| POST | `/api/v1/auth/refresh` | Rate-limited |
| POST | `/api/v1/auth/logout` | Rate-limited |
| POST | `/api/v1/auth/mfa/verify` | Rate-limited |
| POST | `/api/v1/auth/password-policy/validate` | Rate-limited |
| GET  | `/api/v1/auth/invite/info` | Rate-limited |
| POST | `/api/v1/auth/invite/accept` | Rate-limited |
| POST | `/api/v1/auth/mfa/email/send` | Rate-limited |
| POST | `/api/v1/auth/mfa/email/verify` | Rate-limited |
| POST | `/api/v1/auth/password-reset/request` | Rate-limited |
| POST | `/api/v1/auth/password-reset/confirm` | Rate-limited |
| GET  | `/api/v1/auth/sso/providers` | Lists enabled SSO providers |
| POST | `/api/v1/auth/sso/callback` | SSO assertion endpoint (stub) |
| POST | `/api/v1/auth/email-verification/confirm` | Token from email link |
| GET  | `/api/v1/agents/:id/cert/ca` | Agent bootstraps mTLS trust |
| POST | `/api/v1/ingest/wazuh` | Token-auth (separate from JWT) |
| GET  | `/api/v1/ingest/wazuh/status` | Token-auth |
| GET  | `/api/v1/live-response/poll` | Token-auth (agent-facing) |
| POST | `/api/v1/live-response/output` | Token-auth (agent-facing) |
| GET  | `/api/v1/installer/linux/:arch` | No auth — installer script |
| GET  | `/api/v1/installer/windows/:arch` | No auth — installer script |
| GET  | `/api/v1/installer/download/:os/:arch` | No auth — binary download (501 stub) |
| GET  | `/health` | Health check |
| GET  | `/api/v1/health/detailed` | Includes DB latency, goroutines |
| GET  | `/metrics` | Prometheus metrics |
| GET  | `/api/v1/openapi.yaml` | OpenAPI spec |
| GET  | `/api/v1/docs` | Swagger UI |
| GET  | `/api/v1/docs/openapi.yaml` | OpenAPI spec (docs handler) |
| GET  | `/downloads/*` | Static agent binary files |
| GET  | `/docs/*` | Static documentation files |

---

## 5. Admin-Only Endpoints

These require `role = "admin"` in the JWT (enforced by `adminMiddleware()`), or `tenant_admin` for the tenant-scoped role endpoints:

| Category | Paths |
|----------|-------|
| Settings | `GET/PUT /settings`, `POST /settings/enrollment-token` |
| Audit log | `GET /audit` |
| Password policy | `GET/PUT /admin/password-policy` |
| Invitations | `POST/GET/DELETE /admin/invitations` |
| LDAP | `GET/PUT /admin/ldap`, `POST /admin/ldap/test`, `POST /admin/ldap/sync` |
| SSO | `GET/POST/PUT/DELETE/POST /admin/sso` |
| Elasticsearch | `POST /admin/elasticsearch/test`, `POST /admin/elasticsearch/flush` |
| Notification templates | `GET/POST/PUT/DELETE /admin/notification-templates` |
| Alert notifications | `GET/POST/PUT/DELETE/POST /admin/notifications` |
| Backups | `GET/POST/DELETE/GET /admin/backups` |
| SIEM targets | `GET/POST/PUT/DELETE/POST /siem/targets` |
| Tenants | `GET/POST/GET/PATCH/DELETE /tenants` |
| Tenant roles | `GET/GET/PUT/DELETE /tenants/:id/roles` (Admin or TenantAdmin) |
| Agent update trigger | `POST /agents/update` |
| Group policy assign | `PUT /groups/:id/policy` |
| Agent policies (write) | `POST/PUT/DELETE /agent-policies` |
| YARA rules (write) | `POST/PUT/DELETE/PATCH /yara-rules` |
| FIM rules (write) | `POST/PUT/DELETE/PATCH /fim-rules` |
| Process rules (write) | `POST/PUT/DELETE/PATCH /process-rules` |
| Webhooks | `GET/POST/PUT/DELETE/PATCH/POST /webhooks` |
| Risk action rules | `GET/POST/PUT/DELETE/PATCH /risk-actions` |
| SOAR configs | `GET/POST/PATCH/DELETE/POST /soar/configs` |
| Correlation rules | `GET/POST/GET/PUT/DELETE/PUT /correlation-rules` |
| Escalation rules | `GET/POST/PUT/DELETE/PATCH /escalation-rules` |
| Users (write) | `POST/PUT/DELETE /users` |

---

## 6. WebSocket / SSE Endpoints

| Protocol | Path | Handler | Auth Required | Notes |
|----------|------|---------|---------------|-------|
| WebSocket | `/ws/alerts` | `WebSocketHub.HandleAlerts` | Yes (JWT via `?token=` or `Authorization` header) | Real-time alert stream |
| WebSocket | `/ws/agents/:id/events` | `WebSocketHub.HandleAgentEvents` | Yes (JWT via `?token=`) | Per-agent event stream |
| WebSocket | `/ws/cloud` | `WebSocketHub.HandleCloudEvents` | Yes (JWT via `?token=`) | Cloud workload event stream |
| SSE | `/api/v1/agents/:id/live-response/sessions/:sid/stream` | `LiveResponseHandler.StreamOutput` | Yes | Live response output stream; uses SSE pattern |

> All WebSocket endpoints accept JWT tokens via the `?token=` query parameter to support browser `EventSource` clients where custom `Authorization` headers are not available.

---

## 7. 追補（2026-06-12 更新）

本書の初回監査（2026-03-17、253ルート）以降、ルートは大幅に増加している。
2026-06-11〜12 に**フロントエンドが参照する静的568エンドポイントを検証環境へ実プローブする方式**で再監査を実施した
（手順・結果・修正内容は `docs/フロントエンド監査と実データ化.md` を参照）。

### 7.1 実プローブ結果サマリ

| HTTP | 件数 | 意味 |
|------|------|------|
| 200 | 314 | 正常稼働 |
| 402 | 31 | プランゲート（Lite制限・正常） |
| 400 | 3 | 要パラメータ（正常） |
| 500 | 2 | サーバーバグ → 修正済み（forensics-automation #102） |
| 404 | 218 | バックエンド未実装（→ 約70ページに「準備中」バナー掲示 #103） |

### 7.2 本期間に追加された主なルート（PR #94〜#108）

| 機能 | ルート（`/api/v1` 配下） | Migration |
|------|--------------------------|-----------|
| 敵対的エミュレーション | `GET/POST /admin/adversary-emulation`, `DELETE /:id`, `GET/POST /admin/adversary-emulation/executions` | 254 |
| ネットワーク分離 | `GET/POST /admin/network-segments`, `DELETE /:id`, `POST /policies`, `DELETE /policies/:id`, `POST /compliance-check` | 255 |
| パッチ自動化（実データ化） | `GET/POST /admin/patch-automation(/policies)`, `POST /policies/:id/toggle`, `GET/POST /jobs`, `POST /jobs/:id/approve`, `GET /missing-patches`, `GET /stats` | 144/256 |
| MFA バックアップコード | `GET /auth/mfa/backup-codes`, `POST /auth/mfa/backup-codes/regenerate` | 257 |
| 配信ダイジェスト | `PUT /admin/digest/config`, `GET /admin/digest/history`, `GET /admin/digest/stats`（既存: `POST /trigger`, `GET /config`） | 258 |
| データ保持 | `GET /admin/data-retention`, `PUT /:type`, `POST /purge-preview`, `POST /purge` | 259 |
| エンドポイントグループ | `GET/POST /admin/endpoint-groups`, `PUT/DELETE /:id` | 260 |
| セキュリティKPI（拡張） | `GET /admin/kpi`（current_value/achievement_pct/status/trend を計算返却） | 119 |

> 注意: フロントエンド向けに配列を返す際、ラッパーキーは `frontend/lib/api.ts` の `ARRAY_KEYS` に
> 登録されているものを使うこと（本期間に `kpis` / `jobs` / `patches` を追加）。未登録キーは
> `apiFetchList` が剥がせず一覧が常に空になる。

### 7.3 ライブレスポンスのコマンド経路（#110/#111 で判明）

- **セッション**: `POST /agents/:id/live-response/sessions`（作成）/ `GET`（一覧）/ `DELETE /sessions/:sid`（終了）
- **コマンド投入は `POST /agents/:id/live-response/sessions/:sid/exec`**。`GET /sessions/:sid/commands` は**取得専用**（POST すると 404）。
- 配送経路: API が NATS `commands.<agentID>.live_response_start` を発行 → **ingestion の NATSブリッジ**（`server/cmd/ingestion/main.go` の `startNATSCommandBridge`）が gRPC `ServerCommand_CollectArtifact(LOGS)` に変換しエージェントの gRPC ストリームへ配送 → エージェントが `GET /live-response/poll?token=` で取得・実行し `POST /live-response/output` で結果返却。
- **教訓**: 「サーバーは正常だがエージェントがコマンドを実行しない」系は、**NATSブリッジの `switch cmdType` に当該 command type の case があるか**を最初に確認する（case 漏れだと黙って破棄される）。
