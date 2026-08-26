#!/usr/bin/env python3
"""保管時暗号化の読み出し側が、黙って空を返すようにされたら気づけること。

対象:
  server/internal/store/alerts.go
  server/internal/api/handlers/export_handler.go

守っている検査:
  server/internal/store/raw_event_decode_test.go
  server/internal/store/raw_event_note_test.go
  server/internal/api/handlers/export_raw_event_test.go

この経路の失敗は、どれも**「生イベントが無いアラート」と同じ姿**になります。
鍵の設定を間違えたまま何週間も気づかない、という壊れ方をするので、
「復号できなかった」が応答とエクスポートに残ることを変異で確かめます。

書き込み側（prepareRawEvent）は既に有効です。読み出し側を緩めると、
書けるが読めないデータが増えます。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

ALERTS = 'server/internal/store/alerts.go'
EXPORT = 'server/internal/api/handlers/export_handler.go'

CASES = [
    # ── 読み出しそのもの ───────────────────────────────────────────────────
    (ALERTS,
     '\tif !strings.HasPrefix(*stored, encryptedRawEventPrefix) {\n'
     '\t\treturn json.RawMessage(*stored), nil\n\t}',
     '\tif true {\n\t\treturn json.RawMessage(*stored), nil\n\t}',
     '暗号文をそのまま JSON として返す（復号しなくなる）'),
    (ALERTS,
     '\t\treturn nil, fmt.Errorf("復号できません: %w", err)',
     '\t\treturn nil, nil',
     '復号の失敗を「生イベントが無い」として返す'),
    (ALERTS,
     '\t\treturn nil, fmt.Errorf("暗号化された raw_event ですが、encryptor が設定されていません")',
     '\t\treturn nil, nil',
     'encryptor が無いのを「生イベントが無い」として返す'),
    (ALERTS,
     '\t\treturn nil, fmt.Errorf("暗号化された raw_event ですが、テナントが分かりません")',
     '\t\treturn nil, nil',
     'テナントが分からないのを「生イベントが無い」として返す'),

    # ── 出せなかったことが応答に載ること ───────────────────────────────────
    (ALERTS,
     '\t\treturn nil, rawEventNote(alertID, "生イベントを読み出せませんでした", readErr)',
     '\t\treturn nil, nil',
     'DB から読めなかったことを、応答に載せなくなる'),
    (ALERTS,
     '\t\treturn nil, rawEventNote(alertID, "生イベントを復号できませんでした", err)',
     '\t\treturn nil, nil',
     '復号できなかったことを、応答に載せなくなる'),
    (ALERTS,
     '\treturn raw, nil\n}\n\n// rawEventNote records the failure',
     '\treturn raw, rawEventNote(alertID, "生イベントを復号できませんでした", nil)\n}\n\n'
     '// rawEventNote records the failure',
     '読めているのに、毎回「出せなかった」と付ける'),

    # ── エクスポート ───────────────────────────────────────────────────────
    (EXPORT,
     '\tif !store.IsEncryptedRawEvent(v) {\n\t\treturn v\n\t}',
     '\tif true {\n\t\treturn v\n\t}',
     'エクスポートが暗号文をそのまま CSV に書く'),
    (EXPORT,
     '\t\treturn "[復号できませんでした]"',
     '\t\treturn ""',
     '復号できなかったセルを空欄で出す'),
    (EXPORT,
     '\th.encryptor = enc',
     '\t_ = enc',
     'WithEncryptor が encryptor を取り付けなくなる'),

    # ── 前置きの判定 ───────────────────────────────────────────────────────
    (ALERTS,
     '\treturn strings.HasPrefix(stored, encryptedRawEventPrefix)',
     '\treturn false',
     'IsEncryptedRawEvent が何も暗号文と見なさなくなる'),
    (ALERTS,
     '\treturn strings.HasPrefix(stored, encryptedRawEventPrefix)',
     '\treturn true',
     'IsEncryptedRawEvent が平文まで暗号文と見なす'),
]

RUN = ('TestPlaintextRawEventStillReads|TestEncryptedRawEventIsDecrypted|'
       'TestUndecryptableRawEventIsAnError|TestEmptyRawEventIsNotAnError|'
       'TestWriteAndReadAgreeOnThePrefix|TestUnreadableRawEventSaysSoInTheResponse|'
       'TestUndecryptableRawEventSaysSoInTheResponse|TestReadableRawEventCarriesNoNote|'
       'TestAbsentRawEventIsNotAFailure|TestExportDecryptsRawEvent|'
       'TestExportSaysWhenItCannotDecrypt|TestExportLeavesPlainCellsAlone|'
       'TestExportUsesTheSharedPrefixTest')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/store/', './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
