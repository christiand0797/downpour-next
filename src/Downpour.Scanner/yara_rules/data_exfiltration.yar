rule Data_Exfiltration_Tools
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "exfiltration"
        severity = "critical"
        mitre = "T1048,T1567"
        description = "Detects data exfiltration tools and staging behavior"

    strings:
        $rclone1 = "rclone" ascii nocase
        $rclone2 = "rclone copy" ascii nocase
        $rclone3 = "rclone sync" ascii nocase
        $mega1 = "megacmd" ascii nocase
        $mega2 = "mega-put" ascii nocase
        $mega3 = "MEGAclient" ascii nocase
        $ftp1 = "ftp -s:" ascii nocase
        $ftp2 = "open ftp" ascii nocase
        $curl_upload = "curl -T" ascii nocase
        $curl_post = "curl -X POST" ascii nocase
        $scp1 = "scp.exe" ascii nocase
        $sftp1 = "sftp.exe" ascii nocase
        $transfer_sh = "transfer.sh" ascii nocase
        $file_io = "file.io" ascii nocase
        $gofile = "gofile.io" ascii nocase
        $anonfiles = "anonfiles" ascii nocase
        $bitsadmin1 = "bitsadmin /transfer" ascii nocase
        $exfil1 = "Invoke-Exfiltration" ascii nocase
        $exfil2 = "data-exfil" ascii nocase
        $dns_exfil1 = "dnscat" ascii nocase
        $dns_exfil2 = "iodine" ascii nocase
        $dns_exfil3 = "dns2tcp" ascii nocase

    condition:
        any of them
}

rule Archive_Staging_Exfil
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "exfiltration"
        severity = "high"
        mitre = "T1560.001"
        description = "Detects archive creation for exfiltration staging"

    strings:
        $7z_cmd = "7z.exe a" ascii nocase
        $7z_pwd = "7z.exe a -p" ascii nocase
        $rar_cmd = "rar.exe a" ascii nocase
        $rar_pwd = "rar.exe a -hp" ascii nocase
        $zip_cmd = "makecab" ascii nocase
        $compact1 = "compact /c" ascii nocase
        $tar_cmd = "tar -czf" ascii nocase

    condition:
        any of them
}
