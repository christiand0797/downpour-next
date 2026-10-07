/*
    YARA Rules for Ransomware Detection
    Downpour v29 Titanium - Threat Intelligence
*/

rule ransomware_extension_change
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "ransomware"
        severity = "critical"
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
        $ext4 = ".locked" nocase
    condition:
        any of them
}

rule ransomware_ransom_note
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "ransomware"
        severity = "critical"
    strings:
        $note1 = "ALL YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "ransom" nocase
        $note3 = "payment" nocase
        $note4 = "bitcoin" nocase
        $note5 = "decrypt" nocase
        $note6 = "restore files" nocase
    condition:
        3 of them
}

rule ransomware_encryption_api
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "ransomware"
        severity = "critical"
    strings:
        $api1 = "CryptEncrypt"
        $api2 = "CryptGenKey"
        $api3 = "RtlEncryptMemory"
    condition:
        any of them
}