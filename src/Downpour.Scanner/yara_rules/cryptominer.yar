/*
    YARA Rules for Cryptominer Detection
    Downpour v29 Titanium - Threat Intelligence
*/

rule cryptominer_pool_connection
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "cryptominer"
        severity = "high"
    strings:
        $pool1 = "pool.minexmr.com"
        $pool2 = "mine.xmrpool.net"
        $pool3 = "xmr.pool.minergate.com"
        $pool4 = "stratum+tcp://"
        $pool5 = "stratum.slushpool.com"
    condition:
        any of them
}

rule cryptominer_binary_signature
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "cryptominer"
        severity = "high"
    strings:
        $sig1 = "xmrig"
        $sig2 = "nicehash"
        $sig3 = " Claymore"
        $sig4 = "Ethminer"
        $sig5 = "Phoenix"
    condition:
        any of them
}

rule cryptominer_api
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "cryptominer"
        severity = "medium"
    strings:
        $api1 = "GetWork"
        $api2 = "SubmitHashrate"
        $api3 = "stratum_get_transport"
    condition:
        any of them
}