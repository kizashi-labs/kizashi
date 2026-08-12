/*
   EDR Platform - ランサムウェア検知YARAルール
   対象: 一般的なランサムウェアの行動パターン
*/

rule Ransomware_FileExtension_Mass_Change {
    meta:
        description = "ランサムウェアによる大量ファイル拡張子変更の検知"
        severity    = 9
        author      = "EDR Platform"
        mitre       = "T1486"

    strings:
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypt" nocase
        $ext4 = ".ransom" nocase
        $ext5 = ".wncry" nocase      // WannaCry
        $ext6 = ".ryuk" nocase       // Ryuk
        $ext7 = ".conti" nocase      // Conti
        $ext8 = ".lockbit" nocase    // LockBit
        $ext9 = ".blackcat" nocase   // BlackCat/ALPHV

    condition:
        any of them
}

rule Ransomware_Ransom_Note {
    meta:
        description = "ランサムノート（身代金要求ファイル）の検知"
        severity    = 10
        mitre       = "T1486"

    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "All your files are encrypted" nocase
        $note3 = "ファイルが暗号化されました" nocase
        $note4 = "bitcoin" nocase
        $note5 = "decrypt" nocase
        $note6 = "HOW_TO_DECRYPT" nocase
        $note7 = "RECOVERY_FILES" nocase
        $note8 = "README_FOR_DECRYPT" nocase
        $note9 = ".onion" nocase     // Tor hidden service
        $wallet = /[13][a-km-zA-HJ-NP-Z0-9]{25,34}/ // Bitcoin address

    condition:
        (2 of ($note1, $note2, $note3, $note6, $note7, $note8))
        and ($note4 or $note5 or $note9 or $wallet)
}

rule Ransomware_Shadow_Copy_Deletion {
    meta:
        description = "シャドウコピー削除コマンドの検知（ランサムウェアの典型的手法）"
        severity    = 9
        mitre       = "T1490"

    strings:
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wmic shadowcopy delete" nocase
        $cmd3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $cmd4 = "bcdedit /set {default} recoveryenabled no" nocase
        $cmd5 = "wbadmin delete" nocase
        $cmd6 = "DisableAntiSpyware" nocase

    condition:
        any of them
}

rule Ransomware_Crypto_API_Usage {
    meta:
        description = "暗号化APIの大量使用（ランサムウェアの暗号化処理）"
        severity    = 7
        mitre       = "T1486"

    strings:
        $api1 = "CryptEncrypt" fullword
        $api2 = "CryptGenRandom" fullword
        $api3 = "CryptAcquireContext" fullword
        $api4 = "BCryptEncrypt" fullword
        $api5 = "BCryptGenRandom" fullword
        $aes  = { 63 7C 77 7B F2 6B 6F C5 }   // AES S-box

    condition:
        uint16(0) == 0x5A4D   // PE file
        and (2 of ($api1, $api2, $api3, $api4, $api5))
        and $aes
}
