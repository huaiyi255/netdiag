@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
title netdiag - 网站打不开 / 网络连通性 排查工具

if /i "%~1"=="-h"     goto :usage
if /i "%~1"=="--help" goto :usage
if /i "%~1"=="/?"     goto :usage

set "TARGET=%~1"
if not defined TARGET (
    echo.
    echo   请输入要排查的目标（IP / 域名 / URL）：
    echo     例: www.example.com
    echo     例: https://www.example.com/path
    echo     例: 1.2.3.4
    echo.
    set /p "TARGET=> "
)
if not defined TARGET (
    echo 未输入，退出。
    pause
    exit /b 1
)

set "NETDIAG_TARGET=%TARGET%"
set "PSFILE=%TEMP%\netdiag_%RANDOM%%RANDOM%.ps1"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$c=@(Get-Content -LiteralPath '%~f0' -Encoding UTF8); $m=($c | Select-String -Pattern '^#PSSTART$' | Select-Object -First 1); if(-not $m){Write-Host '[internal] PSSTART not found'; exit 2}; $c[($m.LineNumber)..($c.Count-1)] | Set-Content -LiteralPath '%PSFILE%' -Encoding UTF8"

if not exist "%PSFILE%" (
    echo 生成临时脚本失败。
    pause
    exit /b 2
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PSFILE%"
set "RC=%ERRORLEVEL%"
del "%PSFILE%" >nul 2>&1

if "%~1"=="" pause
exit /b %RC%

:usage
echo.
echo   用法: netdiag.bat ^<目标^>
echo.
echo   目标可以是:  域名 / IP / 带协议的 URL
echo   例:  netdiag.bat www.example.com
echo        netdiag.bat https://www.example.com/path
echo        netdiag.bat 1.2.3.4
echo        netdiag.bat example.com:8443
echo.
echo   不带参数运行则进入交互输入模式。
echo   退出码: 0=未发现异常  3=发现问题  1=输入错误  2=内部错误
echo.
exit /b 0

#PSSTART
param(
    [string]$Target = $env:NETDIAG_TARGET,
    [int]$TimeoutSec = 8,
    [switch]$NoTrace
)

[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$script:StartTime = Get-Date

$script:Log      = New-Object System.Collections.ArrayList
$script:Findings = New-Object System.Collections.ArrayList
$script:Advices  = New-Object System.Collections.ArrayList
$script:Rca      = New-Object System.Collections.ArrayList
$script:NeedMtu  = $false
$script:NeedTrace= $false
$script:TlsBlocked= $false

# ================= 输出辅助 =================
function Write-Both {
    param([string]$Text = '', [string]$Color = '')
    [void]$script:Log.Add($Text)
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Section { param([string]$T)
    Write-Both ''
    Write-Both ('=' * 74) 'DarkGray'
    Write-Both " $T" 'Cyan'
    Write-Both ('=' * 74) 'DarkGray'
}
function OK   { param([string]$M) Write-Both "  [OK]   $M" 'Green' }
function WARN { param([string]$M) Write-Both "  [WARN] $M" 'Yellow' }
function BAD  { param([string]$M) Write-Both "  [FAIL] $M" 'Red' }
function INFO { param([string]$M) Write-Both "  [INFO] $M" 'Gray' }
function NOTE { param([string]$M) Write-Both "         $M" 'DarkGray' }

function Add-Finding {
    param([string]$S)
    foreach ($f in $script:Findings) { if ($f -eq $S) { return } }
    [void]$script:Findings.Add($S)
}

function Add-Advice {
    param([string]$Priority = 'P2', [string]$Layer = '通用', [string]$Text)
    foreach ($a in $script:Advices) { if ($a.Text -eq $Text) { return } }
    [void]$script:Advices.Add([pscustomobject]@{ Priority = $Priority; Layer = $Layer; Text = $Text; Idx = $script:Advices.Count })
}
function Add-Rca {
    param([int]$Level = 3, [string]$Text)
    foreach ($r in $script:Rca) { if ($r.Text -eq $Text) { return } }
    [void]$script:Rca.Add([pscustomobject]@{ Level = $Level; Text = $Text })
}
function Show-Advices {
    if ($script:Advices.Count -eq 0) { return }
    Section '修复建议（按优先级）'
    $sorted = @($script:Advices | Sort-Object -Property Priority, Idx)
    $i = 1
    foreach ($a in $sorted) {
        $color = 'Gray'
        if ($a.Priority -eq 'P0') { $color = 'Red' } elseif ($a.Priority -eq 'P1') { $color = 'Yellow' }
        Write-Both ("  {0,2}. [{1}][{2}] {3}" -f $i, $a.Priority, $a.Layer, $a.Text) $color
        $i++
    }
    Write-Both ''
    Write-Both '  说明: P0=立即处理 / P1=重要 / P2=参考' 'DarkGray'
}

# ================= 基础探测函数 =================
function Test-IcmpPing {
    param([string]$HostName, [int]$TimeoutMs = 1500, [int]$Count = 2)
    $rtts = @(); $ok = 0
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $r = $p.Send($HostName, $TimeoutMs)
                if ($r -and $r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $ok++; $rtts += [int]$r.RoundtripTime
                }
            } catch {}
        }
    } catch { return [pscustomobject]@{ Ok = $false; Ms = $null; Loss = 100; Err = 'ICMP 不可用' } }
    $ms = $null
    if ($rtts.Count -gt 0) { $ms = [int](($rtts | Measure-Object -Average).Average) }
    $loss = 100
    if ($Count -gt 0) { $loss = [int](100 * ($Count - $ok) / $Count) }
    return [pscustomobject]@{ Ok = ($ok -gt 0); Ms = $ms; Loss = $loss; Err = '' }
}

function Invoke-TcpSample {
    param([string]$Ip, [int]$Port, [int]$TimeoutMs = 4000)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $cli = $null
    try {
        $addr = [System.Net.IPAddress]::Parse($Ip)
        $cli = [System.Net.Sockets.TcpClient]::new($addr.AddressFamily)
        $iar = $cli.BeginConnect($addr, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $sw.Stop()
            return [pscustomobject]@{ Ok = $false; Kind = 'timeout'; Ms = $sw.ElapsedMilliseconds; Err = 'SYN 无响应（防火墙 drop 或端口未监听）' }
        }
        $cli.EndConnect($iar)
        $sw.Stop()
        return [pscustomobject]@{ Ok = $true; Kind = 'open'; Ms = $sw.ElapsedMilliseconds; Err = '' }
    } catch {
        $sw.Stop()
        $inner = $_.Exception.InnerException
        $msg = $_.Exception.Message
        if ($inner) { $msg = $inner.Message }
        $kind = 'error'
        if ($msg -match 'refused|拒绝|actively refused|Reset') { $kind = 'refused' }
        if ($msg -match '(?i)unreachable|no route|没有到主机的路由|无法访问网络|address family') { $kind = 'unreachable' }
        return [pscustomobject]@{ Ok = $false; Kind = $kind; Ms = $sw.ElapsedMilliseconds; Err = $msg }
    } finally {
        if ($cli) { try { $cli.Close() } catch {} }
    }
}

function Invoke-TcpStat {
    param([string]$Ip, [int]$Port, [int]$TimeoutMs = 4000)
    $samples = New-Object System.Collections.ArrayList
    $first = Invoke-TcpSample -Ip $Ip -Port $Port -TimeoutMs $TimeoutMs
    [void]$samples.Add($first)
    # 成功或快速失败(RST)时才追加采样：SYN 超时再采样只会让等待翻倍
    if ($first.Ok -or $first.Kind -eq 'refused') {
        for ($i = 0; $i -lt 2; $i++) {
            [void]$samples.Add((Invoke-TcpSample -Ip $Ip -Port $Port -TimeoutMs $TimeoutMs))
        }
    }
    $okSamples = @($samples | Where-Object { $_.Ok })
    $rtts = @($okSamples | ForEach-Object { [int]$_.Ms })
    $loss = $null
    if ($samples.Count -gt 1) { $loss = [int](100 * ($samples.Count - $okSamples.Count) / $samples.Count) }
    $min = $null; $avg = $null; $max = $null; $jit = $null
    if ($rtts.Count -gt 0) {
        $min = ($rtts | Measure-Object -Minimum).Minimum
        $max = ($rtts | Measure-Object -Maximum).Maximum
        $avg = [int](($rtts | Measure-Object -Average).Average)
        $jit = $max - $min
    }
    return [pscustomobject]@{
        Ip = $Ip; Port = $Port; Ok = $first.Ok; Kind = $first.Kind; Err = $first.Err; Ms = $first.Ms
        Attempts = $samples.Count; Successes = $okSamples.Count; Loss = $loss
        MinMs = $min; AvgMs = $avg; MaxMs = $max; Jitter = $jit
    }
}

function Get-FileSha16 {
    param([string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs = [System.IO.File]::OpenRead($Path)
        $h = [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '')
        $fs.Close(); $sha.Dispose()
        if ($h.Length -ge 16) { return $h.Substring(0, 16) }
        return $h
    } catch { return $null }
}

function Test-TlsEnvBlocked {
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match '(?i)NO_CREDENTIALS|AcquireCredentialsHandle|schannel|credential|SEC_E_')
}

function Test-TlsProbe {
    param([string]$Ip, [string]$Sni, [int]$Port = 443, [int]$TimeoutMs = 8000,
          [string]$Protocols = 'Tls12, Tls11, Tls')
    $tcp = $null; $ssl = $null
    try {
        $addr = [System.Net.IPAddress]::Parse($Ip)
        $tcp = [System.Net.Sockets.TcpClient]::new($addr.AddressFamily)
        $iar = $tcp.BeginConnect($addr, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw 'connect timeout' }
        $tcp.EndConnect($iar)
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
        $proto = [System.Security.Authentication.SslProtocols]$Protocols
        $ssl.AuthenticateAsClient($Sni, $null, $proto, $false)
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)

        $chainOk = $null; $chainMsg = ''
        try {
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chainOk = $chain.Build($x509)
            $msgs = @()
            foreach ($st in $chain.ChainStatus) {
                if ($st.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError) {
                    $msgs += ($st.StatusInformation.Trim())
                }
            }
            $chainMsg = ($msgs -join '; ')
        } catch {}

        $sanList = @()
        try {
            $ext = $x509.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
            if ($ext) {
                $fmt = $ext.Format($false)
                foreach ($ln in ($fmt -split "`n")) {
                    if ($ln -match 'DNS') {
                        $v = ($ln -replace '.*?=', '').Trim()
                        if ($v) { $sanList += $v }
                    }
                }
            }
        } catch {}

        return [pscustomobject]@{
            Ok = $true; Protocol = [string]$ssl.SslProtocol; Cipher = [string]$ssl.CipherAlgorithm
            Subject = $x509.Subject; Issuer = $x509.Issuer; NotAfter = $x509.NotAfter
            NotBefore = $x509.NotBefore; San = $sanList; ChainOk = $chainOk; ChainMsg = $chainMsg
            Err = ''; X509 = $x509
        }
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        return [pscustomobject]@{ Ok = $false; Err = $msg; NotAfter = $null; San = @(); ChainOk = $null; ChainMsg = '' }
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch {} }
        if ($tcp) { try { $tcp.Close() } catch {} }
    }
}

function Invoke-HttpProbe {
    param([string]$CurlExe, [string]$Scheme, [string]$TargetHost, [int]$Port, [string]$UrlPath, [string]$Ip)
    $tmpBody = [System.IO.Path]::GetTempFileName()
    $tmpHdr  = [System.IO.Path]::GetTempFileName()
    $defaultPort = 80
    if ($Scheme -eq 'https') { $defaultPort = 443 }
    $hostPart = $TargetHost
    if ($Port -ne $defaultPort) { $hostPart = "${TargetHost}:${Port}" }
    if ($TargetHost -match ':') { $hostPart = "[${TargetHost}]" }
    if ($TargetHost -match ':' -and $Port -ne $defaultPort) { $hostPart = "[${TargetHost}]:${Port}" }
    $url = "${Scheme}://${hostPart}${UrlPath}"
    $ipForResolve = $Ip
    if ($Ip -match ':') { $ipForResolve = "[$Ip]" }
    $resolveArg = "${TargetHost}:${Port}:${ipForResolve}"
    $fmt = '%{http_code}|%{time_total}|%{time_connect}|%{time_appconnect}|%{size_download}|%{remote_ip}|%{url_effective}|%{http_version}'
    $curlArgs = @('-sS', '-k', '-L', '--max-redirs', '5', '--max-time', '12', '--connect-timeout', '6',
                  '-A', 'netdiag/2.0', '-o', $tmpBody, '-D', $tmpHdr, '-w', $fmt, '--resolve', $resolveArg, $url)
    $rawOut = & $CurlExe @curlArgs 2>&1
    $rc = $LASTEXITCODE
    $stdout = ($rawOut | Out-String)
    $errText = ''
    foreach ($o in $rawOut) {
        $s = $o.ToString()
        $k = $s.IndexOf('curl: (')
        if ($k -ge 0) { $errText = $s.Substring($k).Trim(); break }
        if ($s -match '(?i)SEC_E_|schannel|credential') { $errText = $s.Trim(); break }
    }
    $parsed = $null
    $line = ($stdout -split "`n" | Where-Object { $_ -match '\|' } | Select-Object -Last 1)
    if ($line -and $line -match '^(\d{3})\|([\d.]+)\|([\d.]+)\|([\d.]+)\|(\d+)\|([^|]*)\|([^|]*)\|(.*)$') {
        $parsed = [pscustomobject]@{
            Code = [int]$matches[1]; Time = [double]$matches[2]; Connect = [double]$matches[3]
            AppConnect = [double]$matches[4]; Size = [long]$matches[5]; RemoteIp = $matches[6]
            EffectiveUrl = $matches[7].Trim(); HttpVersion = $matches[8].Trim()
        }
    }
    $bytes = 0; $title = ''; $hash = $null
    if (Test-Path -LiteralPath $tmpBody) {
        $bytes = (Get-Item -LiteralPath $tmpBody).Length
        if ($bytes -gt 0 -and $bytes -lt 2097152) {
            $hash = Get-FileSha16 -Path $tmpBody
            try {
                $txt = Get-Content -LiteralPath $tmpBody -Raw -Encoding UTF8 -ErrorAction Stop
                if ($txt -match '(?is)<title[^>]*>(.*?)</title>') { $title = ($matches[1] -replace '\s+', ' ').Trim() }
            } catch {}
        }
    }
    $server = ''; $dateHdr = ''
    if (Test-Path -LiteralPath $tmpHdr) {
        $hl = @(Get-Content -LiteralPath $tmpHdr -ErrorAction SilentlyContinue)
        foreach ($h in $hl) {
            if ($h -match '^(?i)server:\s*(.+)$') { $server = $matches[1].Trim() }
            if ($h -match '^(?i)date:\s*(.+)$')   { $dateHdr = $matches[1].Trim() }
        }
    }
    return [pscustomobject]@{
        Url = $url; Ip = $Ip; Scheme = $Scheme; Port = $Port; ExitCode = $rc; Stdout = $stdout.Trim()
        Parsed = $parsed; Bytes = $bytes; Title = $title; Hash = $hash; Server = $server
        DateHdr = $dateHdr; BodyFile = $tmpBody; HdrFile = $tmpHdr; ErrText = $errText
    }
}

function Invoke-DohQuery {
    param([string]$CurlExe, [string]$Name, [string]$Endpoint)
    try {
        $u = "${Endpoint}?name=${Name}&type=A"
        $r = & $CurlExe -sS --max-time 6 -H 'accept: application/dns-json' $u 2>$null
        $t = ($r | Out-String)
        $ips = @([regex]::Matches($t, '"data"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"') | ForEach-Object { $_.Groups[1].Value })
        return @($ips | Sort-Object -Unique)
    } catch { return @() }
}

# ================= 0. 输入解析 =================
$raw = ''
if ($null -ne $Target) { $raw = $Target.Trim() }

function Test-TargetSafe {
    param([string]$S)
    if (-not $S) { return $false }
    if ($S.Length -gt 2048) { return $false }
    if ($S -match '[\s"`&|<>^%]') { return $false }
    return $true
}

Section '0. 输入解析'
if (-not $raw) {
    BAD '输入为空'
    Add-Advice 'P0' '输入' '请输入 IP / 域名 / URL，例如: netdiag.bat www.example.com'
    Show-Advices
    exit 1
}
if (-not (Test-TargetSafe -S $raw)) {
    BAD '目标包含非法字符（空白、" & | < > ^ %）'
    Add-Advice 'P0' '输入' '请只输入域名 / IP / URL，不要包含引号或管道符'
    Show-Advices
    exit 1
}

$scheme = $null; $port = $null; $UrlPath = '/'
$cleanRaw = $raw.Trim('[', ']')
$ipTmp = $null
$isIPInput = [System.Net.IPAddress]::TryParse($cleanRaw, [ref]$ipTmp)
$TargetHost = ''
$explicitPort = $false

if ($raw -match '^[A-Za-z][A-Za-z0-9+.\-]*://') {
    try {
        $u = [Uri]$raw
        $scheme = $u.Scheme.ToLower()
        $TargetHost = $u.Host.Trim('[', ']')
        $port = $u.Port
        $explicitPort = $true
    } catch {
        BAD "URL 解析失败: $($_.Exception.Message)"
        Show-Advices
        exit 1
    }
    if ($u.PathAndQuery) { $UrlPath = $u.PathAndQuery }
} elseif ($isIPInput) {
    $TargetHost = $cleanRaw
} elseif ($raw -match '[:/]') {
    try {
        $u = [Uri]('http://' + $raw)
        $TargetHost = $u.Host.Trim('[', ']')
        $port = $u.Port
        $explicitPort = -not $u.IsDefaultPort
        if ($u.PathAndQuery) { $UrlPath = $u.PathAndQuery }
    } catch { $TargetHost = $raw }
} else { $TargetHost = $raw }

if (-not $scheme -and $explicitPort) {
    if ($port -eq 80) { $scheme = 'http' }
    elseif ($port -eq 443) { $scheme = 'https' }
}
INFO "目标主机: $TargetHost"
if ($scheme) { INFO "协议: $scheme" } else { INFO '协议: 未指定（将同时测试 https/http）' }
if ($explicitPort) { INFO "端口: $port" }
INFO "路径: $UrlPath"

if (-not $isIPInput) {
    $ipTmp2 = $null
    if ([System.Net.IPAddress]::TryParse($TargetHost, [ref]$ipTmp2)) { $isIPInput = $true }
}

# ================= 1. 本机环境 =================
Section '1. 本机环境'
$localAdapters = @()
$localGateway  = @()
$localDns      = @()
try {
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
        if ($nic.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) { continue }
        try {
            $props = $nic.GetIPProperties()
            $addrs = @()
            foreach ($ua in $props.UnicastAddresses) {
                $a = $ua.Address.ToString()
                if ($a -match '^169\.254\.') { continue }
                $addrs += $a
            }
            $gws = @()
            foreach ($g in $props.GatewayAddresses) {
                if ($g.Address -and $g.Address.ToString() -ne '0.0.0.0' -and $g.Address.ToString() -ne '::') { $gws += $g.Address.ToString() }
            }
            $dns = @()
            foreach ($d in $props.DnsAddresses) { $dns += $d.ToString() }
            $localAdapters += [pscustomobject]@{ Name = $nic.Name; Type = [string]$nic.NetworkInterfaceType; Addrs = $addrs }
            $localGateway += $gws
            $localDns += $dns
        } catch {}
    }
} catch {}

$localGateway = @($localGateway | Sort-Object -Unique)
$localDns     = @($localDns | Sort-Object -Unique)

if ($localAdapters.Count -eq 0) {
    BAD '没有处于已连接状态的网卡'
    Add-Finding '本机无已连接网卡'
    Add-Rca 1 '本机网络未连接（网卡断开或未获取到 IP）'
    Add-Advice 'P0' '本机' '检查网线 / Wi-Fi 是否已连接；运行 ipconfig /all 确认是否拿到有效 IP'
} else {
    foreach ($a in $localAdapters) {
        OK ("网卡 {0} [{1}] {2}" -f $a.Name, $a.Type, ($a.Addrs -join ', '))
    }
}

$gwIp = $null
foreach ($g in $localGateway) { if ($g -notmatch ':') { $gwIp = $g; break } }
if ($gwIp) {
    INFO "默认网关: $gwIp"
    $gwPing = Test-IcmpPing -HostName $gwIp -TimeoutMs 1200 -Count 2
    if ($gwPing.Ok) {
        OK ("网关可达  {0}ms  丢包 {1}%" -f $gwPing.Ms, $gwPing.Loss)
        if ($gwPing.Loss -gt 0) {
            WARN ("网关丢包 {0}% —— 本地链路/Wi-Fi 质量可疑" -f $gwPing.Loss)
            Add-Finding ("网关 {0} 丢包 {1}%" -f $gwIp, $gwPing.Loss)
            Add-Rca 2 '本地链路不稳定（网关丢包）'
            Add-Advice 'P1' '本机' '网关丢包：换有线/换 Wi-Fi 信道排查，或检查路由器负载'
        }
    } else {
        INFO "网关不响应 ICMP（很多路由器/手机热点默认禁 ping，不代表故障）"
    }
} elseif ($localAdapters.Count -gt 0) {
    WARN '未取到默认网关（可能是静态配置缺失或仅 IPv6）'
}

if ($localDns.Count -gt 0) { INFO ("本机 DNS: " + ($localDns -join ', ')) }
elseif (-not $isIPInput) { WARN '本机未配置 DNS 服务器，域名解析必然失败'; Add-Rca 1 '本机未配置 DNS' }

# --- 代理检测（最容易被忽略的"只有浏览器打不开"原因）---
$proxyHits = @()
try {
    $k = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    if ($k.ProxyEnable -eq 1 -and $k.ProxyServer) { $proxyHits += "系统/IE 代理: $($k.ProxyServer)" }
    if ($k.AutoConfigURL) { $proxyHits += "PAC 自动配置: $($k.AutoConfigURL)" }
} catch {}
try {
    $wh = & netsh winhttp show proxy 2>&1 | Out-String
    if ($wh -match '(?i)Proxy Server\(s\)\s*:\s*(\S+)|代理服务器\s*:\s*(\S+)') {
        $ps = $matches[1]; if (-not $ps) { $ps = $matches[2] }
        if ($ps -and $ps -notmatch '(?i)direct|直接') { $proxyHits += "WinHTTP 代理: $ps" }
    }
} catch {}
foreach ($v in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy')) {
    $val = [Environment]::GetEnvironmentVariable($v)
    if ($val) { $proxyHits += "环境变量 $v=$val" }
}
$proxyHits = @($proxyHits | Sort-Object -Unique)
if ($proxyHits.Count -gt 0) {
    WARN '检测到代理配置'
    foreach ($p in $proxyHits) { NOTE $p }
    Add-Finding '本机存在代理配置'
    Add-Rca 2 '代理配置可能导致部分应用连不上'
    Add-Advice 'P1' '本机' '确认代理是否应该开启：设置了已失效的代理会出现"浏览器打不开但能 ping 通"'
    Add-Advice 'P2' '本机' '关闭路径: Win+R → inetcpl.cpl → 连接 → 局域网设置 → 取消代理；以及 netsh winhttp reset proxy'
}

# --- hosts 覆盖检测 ---
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsHits = @()
try {
    if (Test-Path -LiteralPath $hostsPath) {
        $esc = [regex]::Escape($TargetHost)
        foreach ($ln in (Get-Content -LiteralPath $hostsPath -ErrorAction Stop)) {
            if ($ln -match '^\s*#') { continue }
            if (-not $ln.Trim()) { continue }
            if ($ln -match "(?i)(^|\s)$esc(\s|$)") { $hostsHits += $ln.Trim() }
        }
    }
} catch {}
if ($hostsHits.Count -gt 0) {
    WARN 'hosts 文件里存在该域名的记录（会覆盖 DNS 结果）'
    foreach ($h in $hostsHits) { NOTE $h }
    Add-Finding 'hosts 中存在目标域名记录'
    Add-Rca 1 'hosts 文件覆盖了域名解析'
    Add-Advice 'P0' '本机' ("hosts 路径 {0}，若其中的记录已失效请删除后再测" -f $hostsPath)
}

# ================= 2. DNS 解析 =================
Section '2. DNS 解析'
$addresses = @()
if ($isIPInput) {
    $addresses = @($TargetHost)
    INFO '输入为 IP，跳过 DNS 解析'
} else {
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($TargetHost)
        $addresses = @($addrs | ForEach-Object { $_.IPAddressToString } | Sort-Object -Unique)
        if ($addresses.Count -gt 0) { OK ("系统解析 -> " + ($addresses -join ', ')) }
        else { BAD '系统解析无结果' }
    } catch {
        $dnsMsg = $_.Exception.Message
        if ($_.Exception.InnerException) { $dnsMsg = $_.Exception.InnerException.Message }
        if ($dnsMsg -match '(?i)no such host|not known|does not exist') { $dnsMsg = '域名不存在或本地 DNS 无记录' }
        BAD ("系统解析失败: {0}" -f $dnsMsg)
    }
}

$curlExe = $null
$c = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $c) { $c = Get-Command curl -ErrorAction SilentlyContinue }
if ($c -and $c.CommandType -ne 'Alias') { $curlExe = $c.Source }
if (-not $curlExe) { WARN '未找到 curl，HTTP 层与 DoH 探测受限（建议升级到 Win10 1803+）' }

$hasRDN = $null -ne (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
$isCDN = $false
$cnameChain = @()
if ($hasRDN -and -not $isIPInput) {
    try {
        $cn = @(Resolve-DnsName -Name $TargetHost -Type CNAME -ErrorAction Stop | Where-Object { $_.Type -eq 'CNAME' } | ForEach-Object { $_.NameHost })
        if ($cn.Count -gt 0) {
            $cnameChain = $cn
            INFO ("CNAME 链: {0} -> {1}" -f $TargetHost, ($cn -join ' -> '))
            if (($cn -join ' ') -match 'jiasule|kunlun|aliyun|alicdn|cdn|cloudfront|akamai|fastly|wscdns|chinacache|wangsu|yunjiasu|azureedge|azurefd|edge') {
                $isCDN = $true
                WARN '检测到 CDN —— 解析结果取决于客户端位置/线路（这正解释"换个网络就通/不通"）'
                Add-Finding '解析到 CDN，结果随客户端位置/线路变化'
            }
        }
    } catch {}
}

$hasV6 = @($addresses | Where-Object { $_ -match ':' })
if ($hasV6.Count -gt 0) {
    WARN ("解析到 IPv6: " + ($hasV6 -join ', ') + "（若本地 IPv6 不通，浏览器会先卡 IPv6 再回落，表现为「时快时慢」）")
}

$seen = @{}
$dnsRows = @()
if ($hasRDN -and -not $isIPInput) {
    foreach ($s in @('223.5.5.5', '119.29.29.29', '180.76.76.76')) {
        try {
            $r = Resolve-DnsName -Name $TargetHost -Type A -Server $s -DnsOnly -ErrorAction Stop
            $ips = @($r | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
            if ($ips.Count -eq 0) { $ips = @('<无A记录>') }
            $joined = $ips -join ','
            $dnsRows += [pscustomobject]@{ Server = $s; Ips = $ips; Ok = $true }
            $seen[$joined] = 1
            INFO ("DNS {0,-15} -> {1}" -f $s, ($ips -join ', '))
        } catch {
            $dnsRows += [pscustomobject]@{ Server = $s; Ips = @(); Ok = $false }
            WARN ("DNS {0,-15} 查询失败: {1}" -f $s, $_.Exception.Message)
        }
    }
}

# 系统解析失败时用 DoH 交叉验证，区分"域名没了"和"本地 DNS 坏了"
if ($addresses.Count -eq 0 -and -not $isIPInput -and $curlExe) {
    $doh1 = Invoke-DohQuery -CurlExe $curlExe -Name $TargetHost -Endpoint 'https://223.5.5.5/resolve'
    $doh2 = Invoke-DohQuery -CurlExe $curlExe -Name $TargetHost -Endpoint 'https://1.1.1.1/dns-query'
    if ($doh1.Count -gt 0 -or $doh2.Count -gt 0) {
        WARN ("DoH 可解析 -> " + ((@($doh1 + $doh2) | Sort-Object -Unique) -join ', '))
        Add-Finding 'DoH 能解析但系统解析失败'
        Add-Rca 1 '本地 DNS 故障（DoH 可解析，说明域名本身正常）'
        Add-Advice 'P0' 'DNS' '本地 DNS 异常：ipconfig /flushdns 后仍失败则把网卡 DNS 改为 223.5.5.5 / 119.29.29.29'
        $addresses = @(@($doh1 + $doh2) | Sort-Object -Unique)
        INFO '后续探测改用 DoH 解析到的 IP'
    } else {
        Add-Rca 2 '域名在各 DNS 与 DoH 下均无法解析（域名不存在或已下线）'
    }
}

if ($seen.Keys.Count -gt 1) {
    WARN '不同 DNS 给出不同 IP —— 调度(CDN) 或 DNS 污染/劫持'
    Add-Finding '不同 DNS 返回不同结果'
    Add-Rca 2 '不同 DNS 返回不同 IP（CDN 调度或 DNS 劫持）'
}

# ---- 层 2 修复建议 ----
if ($addresses.Count -eq 0 -and -not $isIPInput) {
    Add-Advice 'P0' 'DNS' '系统无法解析目标域名，按顺序处理：'
    Add-Advice 'P0' 'DNS' '  1) ipconfig /flushdns 清 DNS 缓存'
    Add-Advice 'P0' 'DNS' '  2) 网络适配器 DNS 改为 223.5.5.5 / 119.29.29.29'
    Add-Advice 'P0' 'DNS' '  3) 打开 C:\Windows\System32\drivers\etc\hosts 检查是否被错误条目覆盖'
    Add-Advice 'P1' 'DNS' '  4) 若所有 DNS 都不行，域名可能已下线，用 DoH 交叉验证'
}
if ($seen.Keys.Count -gt 1) {
    Add-Advice 'P1' 'DNS' '不同 DNS 结果不一致：可能是 CDN 调度或 DNS 劫持'
    Add-Advice 'P2' 'DNS' '  可用 DoH+ECS 验证：curl -s "https://223.5.5.5/resolve?name=域名&type=A&edns_client_subnet=你的公网IP/24"'
}
if ($isCDN) {
    Add-Advice 'P1' 'DNS' '检测到 CDN："换个网络就通"通常是 CDN 按客户端网段调度造成的'
    Add-Advice 'P1' 'DNS' '  处理路径不是折腾 DNS，而是在 hosts 钉住一个健康节点 IP（见末尾建议）'
}

# ================= 3. TCP 端口探测 =================
Section '3. TCP 端口探测（不用 ping）'
$portsToTest = @()
if ($explicitPort -and $port) {
    $portsToTest = @($port)   # 指定端口时只测该端口
} else {
    $portsToTest = @(80, 443)
}
$portsToTest = @($portsToTest | Sort-Object -Unique)

# IPv4 优先，限制总数避免超长等待
$probeIps = @($addresses | Where-Object { $_ -notmatch ':' })
$probeIps += @($addresses | Where-Object { $_ -match ':' })
$probeIps = @($probeIps | Sort-Object -Unique)
if ($probeIps.Count -gt 8) {
    WARN ("解析到 {0} 个 IP，仅探测前 8 个（其余跳过）" -f $probeIps.Count)
    $probeIps = $probeIps[0..7]
}

$tcpResults = @()
if ($probeIps.Count -eq 0) {
    WARN '无可用 IP，跳过端口探测'
    Add-Finding '没有可探测的目标 IP（DNS 未返回地址）'
    Add-Rca 1 '没有可探测的目标 IP'
} else {
    foreach ($ip in $probeIps) {
        foreach ($p in $portsToTest) {
            $r = Invoke-TcpStat -Ip $ip -Port $p -TimeoutMs 4000
            $tcpResults += $r
            $key = '{0}:{1}' -f $ip, $p
            if ($r.Ok) {
                $extra = ''
                if ($null -ne $r.Loss -and $r.Loss -gt 0) { $extra += ("  丢包 {0}%" -f $r.Loss) }
                if ($null -ne $r.Jitter -and $r.Jitter -ge 50) { $extra += ("  抖动 {0}ms" -f $r.Jitter) }
                if ($null -eq $r.Loss) { $extra += '  丢包 未采样' }
                OK ("{0,-22} open   min/avg/max {1}/{2}/{3}ms{4}" -f $key, $r.MinMs, $r.AvgMs, $r.MaxMs, $extra)
                if ($null -ne $r.Loss -and $r.Loss -ge 30) {
                    WARN ("{0} 丢包率高 {1}% —— 链路质量差，不一定是被封" -f $key, $r.Loss)
                    Add-Rca 2 ("{0} 连接丢包 {1}%" -f $key, $r.Loss)
                }
            } else {
                $hint = ''
                if ($r.Kind -eq 'timeout') { $hint = 'SYN 无响应（防火墙 drop 或未监听）' }
                if ($r.Kind -eq 'refused') { $hint = '连接被拒（RST，主机活着但端口无服务）' }
                if ($r.Kind -eq 'unreachable') { $hint = '本机没有可用的该协议出口（网络不可达）' }
                BAD ("{0,-22} {1}    {2}ms  {3}" -f $key, $r.Kind, $r.Ms, $hint)
                if (-not $hint) { NOTE $r.Err }
            }
        }
    }
}

# 同一 IP 的 80/443 交叉判断
foreach ($ip in $probeIps) {
    $r80 = $tcpResults | Where-Object { $_.Ip -eq $ip -and $_.Port -eq 80 } | Select-Object -First 1
    $r443 = $tcpResults | Where-Object { $_.Ip -eq $ip -and $_.Port -eq 443 } | Select-Object -First 1
    if ($r80 -and $r443) {
        if ($r80.Ok -and -not $r443.Ok) {
            WARN ("{0} : 80 通但 443 不通 → 排除整机被封，是该节点 443 服务/策略问题" -f $ip)
            Add-Finding ("{0} 80 通 443 不通（节点 443 服务问题）" -f $ip)
            Add-Rca 1 ("节点 {0} 的 443 不可用（80 正常）" -f $ip)
        }
        if (-not $r80.Ok -and -not $r443.Ok -and $r80.Kind -eq 'timeout' -and $r443.Kind -eq 'timeout') {
            Add-Rca 2 ("节点 {0} 的 80/443 均 SYN 超时（整机不可达或被丢包）" -f $ip)
        }
    }
}

$v4ok = $false; $v6bad = $false
foreach ($r in $tcpResults) {
    if ($r.Ok -and $r.Ip -notmatch ':') { $v4ok = $true }
    if (-not $r.Ok -and $r.Ip -match ':') { $v6bad = $true }
}
if ($v4ok -and $v6bad) {
    WARN 'IPv4 可通但 IPv6 不可达 —— 浏览器会优先尝试 IPv6，表现为"转圈后变慢"'
    Add-Finding 'IPv4 通、IPv6 不通'
    Add-Rca 2 '本机/运营商 IPv6 不可用（浏览器优先 IPv6 导致变慢）'
    Add-Advice 'P2' 'IPv6' 'IPv6 不可达：在网卡属性里关闭 IPv6，或调整系统优先使用 IPv4'
}

$allFail = $false
if ($tcpResults.Count -gt 0) {
    $allFail = $true
    foreach ($r in $tcpResults) { if ($r.Ok) { $allFail = $false; break } }
}
if ($allFail) {
    Add-Rca 1 '所有端口均不可达（本地出口/代理/防火墙 或 整机被封）'
    Add-Advice 'P0' 'TCP' '所有端口全部失败：优先怀疑本地出口/代理/防火墙拦截，或整机被封'
    Add-Advice 'P0' 'TCP' '  1) 手机热点访问同一目标做差分（能通 → 本地线路/代理问题）'
    Add-Advice 'P1' 'TCP' '  2) Win+R → inetcpl.cpl → 连接 → 局域网设置 → 检查代理是否被勾选'
    Add-Advice 'P1' 'TCP' '  3) 临时关闭本地安全软件/防火墙测试'
}

# ---- 层 3 修复建议 ----
foreach ($r in $tcpResults) {
    if ($r.Ok) { continue }
    $key = '{0}:{1}' -f $r.Ip, $r.Port
    switch ($r.Kind) {
        'refused' {
            Add-Advice 'P1' 'TCP' ("{0} 连接被拒(RST)：主机活着但端口没服务/被策略拒，查该机器服务或安全组" -f $key)
        }
        'timeout' {
            Add-Advice 'P1' 'TCP' ("{0} SYN 静默超时：防火墙 drop 或主机没监听，不要直接判'被封'" -f $key)
        }
        'unreachable' {
            Add-Advice 'P2' 'TCP' ("{0} 网络不可达：本机缺少该地址族出口（IPv6 常见）" -f $key)
        }
        default {
            Add-Advice 'P1' 'TCP' ("{0} 连接失败: {1}" -f $key, $r.Err)
        }
    }
}

# ================= 4. HTTP/HTTPS 应用层探测 =================
Section '4. HTTP/HTTPS 应用层探测（保 Host 换 IP）'
$httpResults = @()
$tmpFiles = @()
$goodIps = @(); $badIps = @(); $warnIps = @()
$clockSkew = $null

if ($curlExe -and $probeIps.Count -gt 0) {
    INFO "使用 curl: $curlExe"
    $combos = @()
    if ($scheme) {
        $combos += [pscustomobject]@{ Scheme = $scheme; Port = $port }
    } elseif ($explicitPort) {
        $combos += [pscustomobject]@{ Scheme = 'http'; Port = $port }
    } else {
        $combos += [pscustomobject]@{ Scheme = 'https'; Port = 443 }
        $combos += [pscustomobject]@{ Scheme = 'http'; Port = 80 }
    }
    foreach ($combo in $combos) {
        foreach ($ip in $probeIps) {
            # TCP 明确失败的组合直接跳过，省时间
            $t = $tcpResults | Where-Object { $_.Ip -eq $ip -and $_.Port -eq $combo.Port } | Select-Object -First 1
            if ($t -and -not $t.Ok) {
                INFO ("{0} IP {1}:{2} TCP 不通，跳过 HTTP" -f $combo.Scheme.ToUpper(), $ip, $combo.Port)
                continue
            }
            $res = Invoke-HttpProbe -CurlExe $curlExe -Scheme $combo.Scheme -TargetHost $TargetHost -Port $combo.Port -UrlPath $UrlPath -Ip $ip
            $httpResults += $res
            if ($res.BodyFile -and (Test-Path -LiteralPath $res.BodyFile)) { $tmpFiles += $res.BodyFile }
            if ($res.HdrFile -and (Test-Path -LiteralPath $res.HdrFile)) { $tmpFiles += $res.HdrFile }

            $codeStr = '???'
            $timeStr = '?'
            $connStr = '?'
            if ($res.Parsed) { $codeStr = $res.Parsed.Code; $timeStr = $res.Parsed.Time; $connStr = $res.Parsed.Connect }
            $line = "{0,-5} IP {1,-16} code={2} time={3}s conn={4}s bytes={5}" -f $combo.Scheme.ToUpper(), $ip, $codeStr, $timeStr, $connStr, $res.Bytes

            if ($res.Parsed) {
                $cd = [int]$res.Parsed.Code
                if ($res.DateHdr -and $null -eq $clockSkew) {
                    try {
                        $sd = [DateTime]::Parse($res.DateHdr, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
                        $clockSkew = [int]([DateTime]::UtcNow - $sd.ToUniversalTime()).TotalSeconds
                    } catch {}
                }
                if ($cd -ge 200 -and $cd -lt 300 -and ($res.Bytes -gt 0 -or $cd -eq 204)) {
                    OK $line
                    if ($res.Title) { INFO "      title: $($res.Title)" }
                    if ($res.Server) { INFO "      server: $($res.Server)  http: $($res.Parsed.HttpVersion)" }
                    if ($res.Parsed.EffectiveUrl -and $res.Parsed.EffectiveUrl -ne $res.Url) {
                        INFO "      final:  $($res.Parsed.EffectiveUrl)"
                    }
                    $goodIps += $ip
                    # 健康节点不进结论列表（列表只放异常）
                } elseif ($cd -ge 300 -and $cd -lt 400) {
                    WARN ($line + '  <-- 重定向')
                    $warnIps += $ip
                    Add-Advice 'P2' 'HTTP' ("{0} 返回 {1} 重定向（可能 Location 指向异常目标）" -f $ip, $cd)
                } elseif ($cd -eq 0) {
                    # curl 没拿到状态行：按退出码区分原因，避免把"本机 TLS 不可用"误判成"节点坏"
                    $ec = [int]$res.ExitCode
                    if ($ec -eq 52) {
                        BAD ($line + '  <-- 0 字节秒断（应用层拒绝，类似 nginx return 444）')
                        $badIps += $ip
                        Add-Finding ("{0} 应用层 0 字节断开（节点坏）" -f $ip)
                        Add-Rca 2 ("节点 {0} 应用层直接断开连接（0 字节）" -f $ip)
                    } elseif ($ec -eq 28) {
                        BAD ($line + '  <-- 超时（连接后无响应）')
                        $badIps += $ip
                        Add-Finding ("{0} 请求超时" -f $ip)
                        Add-Rca 2 ("节点 {0} 连接后无响应（超时）" -f $ip)
                        $script:NeedMtu = $true
                    } elseif ($ec -eq 35 -and (Test-TlsEnvBlocked -Text $res.ErrText)) {
                        INFO ($line + '  <-- 本机 TLS 组件不可用，跳过该 HTTPS 判定')
                    } elseif ($ec -eq 35) {
                        BAD ($line + '  <-- TLS 握手失败')
                        $badIps += $ip
                        Add-Finding ("{0} TLS 握手失败" -f $ip)
                        Add-Rca 2 ("节点 {0} TLS 握手失败" -f $ip)
                        Add-Advice 'P1' 'TLS' ("{0} TLS 握手失败: {1}" -f $ip, $res.ErrText)
                        $script:NeedMtu = $true
                    } else {
                        BAD ($line + '  <-- 请求失败')
                        $badIps += $ip
                        Add-Finding ("{0} {1} 请求失败(rc={2})" -f $ip, $combo.Scheme, $ec)
                        Add-Advice 'P1' 'HTTP' ("{0} {1} 请求失败: rc={2} {3}" -f $ip, $combo.Scheme, $ec, $res.ErrText)
                        $script:NeedMtu = $true
                    }
                } else {
                    WARN $line
                    $warnIps += $ip
                    switch ($cd) {
                        401 { Add-Advice 'P1' 'HTTP' ("{0} HTTP 401：需要认证，确认是否被要求登录" -f $ip) }
                        403 { Add-Advice 'P1' 'HTTP' ("{0} HTTP 403：权限拒绝，可能被 WAF 拦截或路径受限" -f $ip) }
                        404 { Add-Advice 'P2' 'HTTP' ("{0} HTTP 404：路径不存在，检查 URL" -f $ip) }
                        429 { Add-Advice 'P1' 'HTTP' ("{0} HTTP 429：被限流，稍后再试" -f $ip) }
                        default {
                            if ($cd -ge 500) {
                                Add-Advice 'P0' 'HTTP' ("{0} HTTP {1}：服务端错误（502/504 一般是上游挂），联系运维或换节点" -f $ip, $cd)
                                Add-Rca 1 ("节点 {0} 返回 {1}（源站/上游故障）" -f $ip, $cd)
                            }
                        }
                    }
                }
            } else {
                WARN ($line + '  <-- 未拿到状态行')
                $warnIps += $ip
                if ($res.Stdout) { INFO "      curl: $($res.Stdout)" }
                Add-Advice 'P1' 'HTTP' ("{0} {1} 请求异常：{2}" -f $ip, $combo.Scheme, ($res.Stdout -replace '\s+', ' '))
                $script:NeedMtu = $true
            }
        }
    }
} elseif (-not $curlExe) {
    Add-Advice 'P2' 'HTTP' '未找到 curl.exe，HTTP 层探测受限；升级 Windows 或手动安装 curl 后重跑'
} elseif ($probeIps.Count -eq 0) {
    INFO '无可用 IP，跳过 HTTP 探测'
}

$goodIps = @($goodIps | Sort-Object -Unique)
$badIps  = @($badIps  | Sort-Object -Unique)
$warnIps = @($warnIps | Sort-Object -Unique)

# 系统时间偏差（TLS 失败的最常见本机原因之一）
if ($null -ne $clockSkew) {
    if ([Math]::Abs($clockSkew) -gt 300) {
        WARN ("本机时间与服务器相差 {0} 秒 —— 会导致证书校验失败" -f $clockSkew)
        Add-Finding ("系统时间偏差 {0} 秒" -f $clockSkew)
        Add-Rca 1 '系统时间偏差过大（TLS 证书校验必失败）'
        Add-Advice 'P0' '本机' '校准系统时间：设置 → 时间和语言 → 立即同步；或 w32tm /resync'
    } else {
        INFO ("本机时间偏差 {0} 秒（正常）" -f $clockSkew)
    }
}

# 多节点内容一致性（发现 vhost 错配 / 劫持）
$okRes = @($httpResults | Where-Object { $_.Parsed -and $_.Parsed.Code -ge 200 -and $_.Parsed.Code -lt 300 -and $_.Bytes -gt 0 })
if ($okRes.Count -ge 2) {
    $hashes = @($okRes | ForEach-Object { $_.Hash } | Where-Object { $_ } | Sort-Object -Unique)
    if ($hashes.Count -gt 1) {
        $titles = @($okRes | ForEach-Object { $_.Title } | Where-Object { $_ } | Sort-Object -Unique)
        if ($titles.Count -gt 1) {
            WARN '不同节点返回的页面标题不同 —— 可能 vhost 错配 / 被劫持 / 灰度版本不一致'
            foreach ($t in $titles) { NOTE "title: $t" }
            Add-Rca 2 '不同节点返回不同内容（vhost 错配或被劫持）'
        } else {
            INFO '不同节点内容 hash 不同但标题一致（动态页面属正常）'
        }
    } else {
        OK '多个节点返回内容完全一致'
    }
}

# ---- 层 4 修复建议 ----
if ($goodIps.Count -gt 0 -and $badIps.Count -gt 0) {
    Add-Advice 'P0' 'HTTP' '好节点与坏节点并存 → 典型 CDN 单节点故障，直接钉健康 IP'
    Add-Advice 'P0' 'HTTP' ("  坏节点: {0}" -f ($badIps -join ', '))
    Add-Advice 'P0' 'HTTP' ("  好节点: {0}" -f ($goodIps -join ', '))
    foreach ($g in $goodIps) {
        Add-Advice 'P0' 'HTTP' ("  在 hosts 末尾追加: {0} {1}   #netdiag-fix" -f $g, $TargetHost)
    }
    Add-Advice 'P1' 'HTTP' '  hosts 路径: C:\Windows\System32\drivers\etc\hosts（改前先备份）'
    Add-Advice 'P2' 'HTTP' '  节点修复后记得删除 hosts 里的 #netdiag-fix 行，否则下次成为新的故障点'
} elseif ($badIps.Count -gt 0 -and $goodIps.Count -eq 0) {
    Add-Advice 'P0' 'HTTP' '所有节点均不可用：'
    Add-Advice 'P0' 'HTTP' '  1) 用手机热点/在线检测（如 ping.chinaz.com）访问同一 URL'
    Add-Advice 'P1' 'HTTP' '  2) 外部能开 → 本地 DNS/代理/线路问题；外部也打不开 → 站点故障，等运维'
}


# ================= 5. TLS / 证书 =================
Section '5. TLS / 证书'
$tlsPorts = @()
if ($scheme -eq 'https') { $tlsPorts = @($port) }
elseif (-not $scheme)    { $tlsPorts = @(443) }
$tlsAnyOk = $false
$tlsChecked = 0

foreach ($ip in $probeIps) {
    foreach ($p in $tlsPorts) {
        $t = $tcpResults | Where-Object { $_.Ip -eq $ip -and $_.Port -eq $p } | Select-Object -First 1
        if ($t -and -not $t.Ok) {
            INFO ('{0}:{1} TCP 不通，跳过 TLS' -f $ip, $p)
            continue
        }
        $tlsChecked++
        if ($script:TlsBlocked) {
            INFO ('{0}:{1} 跳过（本机 TLS 组件不可用）' -f $ip, $p)
            continue
        }
        $r = Test-TlsProbe -Ip $ip -Sni $TargetHost -Port $p
        if ($r.Ok) {
            $tlsAnyOk = $true
            OK ('{0}:{1}  {2}  {3}  证书 CN 见下' -f $ip, $p, $r.Protocol, $r.Cipher)
            INFO ('        Subject: {0}' -f $r.Subject)
            INFO ('        Issuer : {0}' -f $r.Issuer)
            INFO ('        到期   : {0:yyyy-MM-dd}' -f $r.NotAfter)

            # 到期
            try {
                $days = [int]((New-TimeSpan -Start (Get-Date) -End $r.NotAfter).TotalDays)
                if ($days -lt 0) {
                    BAD ("        证书已过期 {0} 天" -f [Math]::Abs($days))
                    Add-Finding ("{0} 证书已过期" -f $ip)
                    Add-Rca 1 '证书已过期（浏览器必报错）'
                    Add-Advice 'P0' 'TLS' ('{0} 证书已过期 {1} 天（到期 {2:yyyy-MM-dd}），联系运维更换' -f $ip, [Math]::Abs($days), $r.NotAfter)
                } elseif ($days -lt 7) {
                    WARN ("        证书 {0} 天后过期" -f $days)
                    Add-Advice 'P1' 'TLS' ('{0} 证书 {1} 天后过期（{2:yyyy-MM-dd}），联系运维更换' -f $ip, $days, $r.NotAfter)
                } else {
                    INFO ("        剩余 {0} 天" -f $days)
                }
            } catch {}

            # 证书链
            if ($r.ChainOk -eq $false) {
                WARN ("        证书链校验失败: {0}" -f $r.ChainMsg)
                Add-Finding ("{0} 证书链不受信任/不完整" -f $ip)
                Add-Rca 2 '证书链不完整或不受信任（部分客户端报错）'
                Add-Advice 'P1' 'TLS' ('{0} 证书链校验失败：{1}；通常需要在服务器补全中间证书' -f $ip, $r.ChainMsg)
            }

            # 域名匹配（CN + SAN）
            $matchHost = $false
            $cnValue = ''
            if ($r.Subject -match 'CN=([^,]+)') { $cnValue = $matches[1].Trim() }
            $names = @()
            if ($cnValue) { $names += $cnValue }
            foreach ($s in $r.San) { $names += $s }
            if ($TargetHost -eq $ip -or $isIPInput) {
                $matchHost = $true
            } else {
                foreach ($n in $names) {
                    if ($n -ieq $TargetHost) { $matchHost = $true; break }
                    if ($n -match '^\*\.') {
                        $base = $n.Substring(2)
                        if ($TargetHost.ToLower().EndsWith('.' + $base.ToLower())) { $matchHost = $true; break }
                    }
                }
            }
            if (-not $matchHost) {
                WARN ('        证书 Subject/SAN 与目标域名不匹配: {0}' -f ($names -join ', '))
                Add-Finding ("{0} 证书与域名不匹配" -f $ip)
                Add-Rca 1 '证书与访问域名不匹配（中间人代理或 vhost 错配）'
                Add-Advice 'P1' 'TLS' ('{0} 证书不含 {1}：可能被中间人代理，或服务器 vhost 配置错误' -f $ip, $TargetHost)
            }

            # 旧协议（安全提示，不是故障）
            if ($tlsChecked -eq 1) {
                $legacy = Test-TlsProbe -Ip $ip -Sni $TargetHost -Port $p -Protocols 'Ssl3, Tls'
                if ($legacy.Ok) {
                    WARN ("        仍接受旧协议 {0}" -f $legacy.Protocol)
                    Add-Finding ("{0} 支持已废弃的 {1}" -f $ip, $legacy.Protocol)
                    Add-Advice 'P2' 'TLS' ('{0} 仍启用 {1}：存在降级风险，建议服务端关闭' -f $ip, $legacy.Protocol)
                }
            }
        } elseif (Test-TlsEnvBlocked -Text $r.Err) {
            INFO ('{0}:{1} 本机 TLS 组件不可用（受限环境），无法做证书探测' -f $ip, $p)
            $script:TlsBlocked = $true
        } else {
            BAD ('{0}:{1} TLS 握手失败: {2}' -f $ip, $p, $r.Err)
            Add-Finding ('{0} TLS 握手失败' -f $ip)
            Add-Rca 2 ("节点 {0} TLS 握手失败" -f $ip)
            Add-Advice 'P1' 'TLS' ('{0}:{1} TLS 握手失败：{2}' -f $ip, $p, $r.Err)
            Add-Advice 'P2' 'TLS' '  常见原因: 协议版本不兼容 / SNI 未配置 / 系统时间偏差 / 证书链缺失 / 被中间人'
            Add-Advice 'P2' 'TLS' '  先检查系统时间，再用 testssl.sh 或 openssl s_client 单独验证'
            $script:NeedMtu = $true
        }
    }
}
if ($tlsChecked -eq 0 -and -not $script:TlsBlocked) {
    if ($probeIps.Count -eq 0) { INFO '无可用 IP，跳过 TLS 探测' }
    elseif ($scheme -eq 'http') { INFO '本次未做 TLS 探测（http 目标）' }
}
if ($script:TlsBlocked) {
    WARN '本机 TLS 组件不可用，HTTPS/TLS 相关结论不可信，请换环境重跑'
    Add-Advice 'P2' 'TLS' '本机无法建立 TLS（Schannel 凭据不可用）：用普通用户会话重跑，或用浏览器 / openssl s_client 单独验证证书'
}

# ================= 6. MTU 与路径（按需） =================
Section '6. 路径与 MTU（按需触发）'

function Test-PathMtu {
    param([string]$Name, [int]$TimeoutMs = 1200)
    # 先确认目标响应 ICMP，否则直接放弃（不代表故障）
    $base = & ping.exe -n 1 -w $TimeoutMs $Name 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return $null }
    $lo = 548; $hi = 1472; $best = 548
    for ($i = 0; $i -lt 9 -and $lo -le $hi; $i++) {
        $mid = [int](($lo + $hi) / 2)
        & ping.exe -n 1 -f -l $mid -w $TimeoutMs $Name 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $best = $mid; $lo = $mid + 1 } else { $hi = $mid - 1 }
    }
    return $best + 28
}

if ($script:NeedMtu -and $probeIps.Count -gt 0) {
    $mtuHost = $probeIps[0]
    $mtu = Test-PathMtu -Name $mtuHost
    if ($null -eq $mtu) {
        INFO '目标不响应 ICMP，无法测 PMTU（不代表故障）'
        Add-Advice 'P2' 'MTU' '无法测 PMTU（目标禁 ICMP）；如怀疑 MTU 问题可用 ping -f -l 1472 手动验证'
    } else {
        if ($mtu -ge 1500) {
            OK ("路径 MTU {0}（正常）" -f $mtu)
        } elseif ($mtu -lt 1400) {
            WARN ("路径 MTU 仅 {0} —— 存在 MTU 黑洞：大包被丢，表现为「能连上但页面加载卡死/TLS 握手失败」" -f $mtu)
            Add-Finding ("路径 MTU 偏小: {0}" -f $mtu)
            Add-Rca 1 '路径 MTU 异常（MTU 黑洞，大包被丢弃）'
            Add-Advice 'P0' 'MTU' ('实测路径 MTU {0}：典型原因是 PPPoE/隧道/VPN 导致 MSS 过大' -f $mtu)
            Add-Advice 'P1' 'MTU' '  临时验证: ping -f -l 1400 目标 (成功) 对比 ping -f -l 1472 (失败)'
            Add-Advice 'P1' 'MTU' '  解决: 路由器上把 WAN MTU 调到 1480 或开启 MSS Clamping；VPN 场景调低隧道 MTU'
        } else {
            INFO ("路径 MTU {0}（略小于 1500，一般可用）" -f $mtu)
        }
    }
} else {
    INFO '本次无需 MTU 探测'
}

# 路径追踪：只在明确失败时跑，节省时间
if (-not $NoTrace) {
    if ($allFail -or ($badIps.Count -gt 0 -and $goodIps.Count -eq 0)) {
        $script:NeedTrace = $true
    }
}
if ($script:NeedTrace) {
    INFO ("路径追踪（最多 12 跳）: {0}" -f $TargetHost)
    try {
        $tr = & tracert.exe -d -h 12 -w 800 -4 $TargetHost 2>&1
        $hops = @()
        foreach ($ln in $tr) {
            $s = ($ln | Out-String).Trim()
            if ($s -match '^\s*\d+\s' -and $s -match '(?i)\d+\s*ms|<\s*1\s*ms|\*') { $hops += ($s -replace '\s+', ' ') }
        }
        if ($hops.Count -gt 0) { foreach ($h in $hops) { NOTE $h } }
        else { INFO '未取到有效跳数（ICMP 被中间设备拦截或权限不足）' }
    } catch { INFO 'tracert 执行失败' }
}

# ================= 7. 诊断结论 =================
Section '7. 诊断结论'
if ($script:Findings.Count -eq 0 -and $script:Rca.Count -eq 0) { INFO '未发现明显异常' }
else {
    $i = 1
    foreach ($f in $script:Findings) { Write-Both ("  {0}. {1}" -f $i, $f); $i++ }
}

$script:Rca = @($script:Rca | Sort-Object -Property Level)
if ($script:Rca.Count -gt 0) {
    Write-Both ''
    Write-Both '  [根因判断]' 'Cyan'
    $i = 1
    foreach ($r in $script:Rca) {
        $tag = '可能'
        $color = 'Yellow'
        if ($r.Level -le 1) { $tag = '高置信'; $color = 'Red' }
        Write-Both ("  {0}. ({1}) {2}" -f $i, $tag, $r.Text) $color
        $i++
    }
}

# ================= 8. 浏览器层通用建议 =================
if ($goodIps.Count -gt 0 -and $badIps.Count -eq 0 -and $tlsAnyOk) {
    Add-Advice 'P2' '浏览器' '系统层全通但浏览器仍打不开时：'
    Add-Advice 'P2' '浏览器' '  1) chrome://net-internals/#dns 看域名解析，点 Clear host cache'
    Add-Advice 'P2' '浏览器' '  2) chrome://net-internals/#sockets → Flush socket pools'
    Add-Advice 'P2' '浏览器' '  3) chrome://settings/security 关闭"使用安全 DNS(DoH)"'
    Add-Advice 'P2' '浏览器' '  4) 任务管理器彻底结束所有 chrome.exe（含后台）再开'
    Add-Advice 'P2' '浏览器' '  5) Win+R → inetcpl.cpl → 连接 → 局域网设置 → 取消所有代理勾选'
}

if ($goodIps.Count -eq 0 -and $badIps.Count -eq 0 -and $warnIps.Count -eq 0 -and $tcpResults.Count -gt 0 -and -not $script:TlsBlocked) {
    $anyTcpOk = $false
    foreach ($r in $tcpResults) { if ($r.Ok) { $anyTcpOk = $true; break } }
    if ($anyTcpOk) {
        Add-Advice 'P1' 'HTTP' 'TCP 通但 HTTP 全无结果：优先怀疑 MTU/代理/中间设备拦截'
    }
}

Show-Advices

# ================= 收尾 =================
foreach ($f in $tmpFiles) {
    if ($f -and (Test-Path -LiteralPath $f)) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
}

$elapsed = [int]((Get-Date) - $script:StartTime).TotalSeconds
Write-Both ''
Write-Both (" 耗时 {0}s" -f $elapsed) 'DarkGray'

if ($script:Log.Count -gt 0) {
    try {
        $logPath = Join-Path $env:TEMP ('netdiag-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $script:Log | Set-Content -LiteralPath $logPath -Encoding UTF8
        Write-Both (" 日志已保存: {0}" -f $logPath) 'DarkGray'
    } catch {}
}

# 退出码: 0=正常  3=发现问题
$hasProblem = ($script:Findings.Count -gt 0)
foreach ($a in $script:Advices) { if ($a.Priority -eq 'P0' -or $a.Priority -eq 'P1') { $hasProblem = $true; break } }
if ($hasProblem) { exit 3 }
exit 0
