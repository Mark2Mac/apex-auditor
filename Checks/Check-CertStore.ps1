#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckCertStore
#  Certificate store hygiene.
#  CERT-NONMS   : Unexpected non-Microsoft root CAs in LocalMachine\Root (MEDIUM)
#  CERT-EXPIRED : Expired certificates in LocalMachine\My (LOW)
# =============================================================================
function Invoke-CheckCertStore {
    param()

    # Known-good Microsoft / trusted-infrastructure issuer patterns.
    # Checked against Subject CN/O and Issuer to classify root CAs as MS-origin.
    $msPatterns = @(
        'Microsoft',
        'VeriSign',
        'DigiCert',
        'Baltimore CyberTrust',
        'Thawte',
        'GlobalSign',
        'Entrust',
        'GeoTrust',
        'QuoVadis',
        'COMODO',
        'Sectigo',
        'Symantec',
        'GTE CyberTrust',
        'USERTrust',
        'Starfield',
        'Amazon',
        'Go Daddy'
    )

    # --- CERT-NONMS ---
    try {
        $rootCerts   = Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop
        $nonMsCerts  = $rootCerts | Where-Object {
            $subj  = $_.Subject + ' ' + $_.Issuer
            -not ($msPatterns | Where-Object { $subj -match [regex]::Escape($_) })
        }
        $nonMsV   = $nonMsCerts.Count -gt 0
        $nonMsSev = if ($nonMsV) { 'MEDIUM' } else { 'PASS' }
        $nonMsObs = if ($nonMsV) {
            $list = ($nonMsCerts | ForEach-Object {
                "[$($_.Thumbprint.Substring(0,8))...] $($_.Subject -replace 'CN=','' -split ',' | Select-Object -First 1)"
            }) -join '; '
            "Count=$($nonMsCerts.Count) Certs=[$list]"
        } else { "TrustedRootCount=$($rootCerts.Count) AllRecognized" }
        Add-Finding -Id 'CERT-NONMS' -Category 'Identity' -CheckName 'Unexpected Root CAs' `
            -Severity $nonMsSev -Vulnerable $nonMsV -Confidence (if ($nonMsV) { 'Medium' } else { 'High' }) `
            -Observed $nonMsObs -Expected 'Only recognized root CAs' `
            -Source 'Cert:\LocalMachine\Root' `
            -Fix 'Remove-Item -Path "Cert:\LocalMachine\Root\<Thumbprint>" -DeleteKey  # verify before removing' `
            -Note 'Unexpected root CAs can intercept TLS traffic (corporate MITM proxies are common; investigate each one). Use -ShowSignals to see full thumbprints.'
    } catch {
        Add-Finding -Id 'CERT-NONMS' -Category 'Identity' -CheckName 'Unexpected Root CAs' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'Only recognized root CAs' -Source 'Cert:\LocalMachine\Root'
    }

    # --- CERT-EXPIRED ---
    try {
        $personalCerts  = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop
        $expiredCerts   = $personalCerts | Where-Object { $_.NotAfter -lt (Get-Date) }
        $expiredV       = $expiredCerts.Count -gt 0
        $expiredSev     = if ($expiredV) { 'LOW' } else { 'PASS' }
        $expiredObs     = if ($expiredV) {
            $list = ($expiredCerts | ForEach-Object {
                "[$($_.Subject -replace 'CN=','' -split ',' | Select-Object -First 1) exp:$($_.NotAfter.ToString('yyyy-MM-dd'))]"
            }) -join '; '
            "Count=$($expiredCerts.Count) Certs=[$list]"
        } else { "PersonalCertCount=$($personalCerts.Count) NoneExpired" }
        Add-Finding -Id 'CERT-EXPIRED' -Category 'Identity' -CheckName 'Expired Certificates (Personal Store)' `
            -Severity $expiredSev -Vulnerable $expiredV -Confidence 'High' `
            -Observed $expiredObs -Expected 'No expired certificates' `
            -Source 'Cert:\LocalMachine\My' `
            -Fix 'Review and remove via certlm.msc > Personal > Certificates. Expired certs may be used for codesigning bypass on some legacy systems.' `
            -Note 'Expired certificates in the personal store can indicate stale credentials or abandoned service accounts.'
    } catch {
        Add-Finding -Id 'CERT-EXPIRED' -Category 'Identity' -CheckName 'Expired Certificates (Personal Store)' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'No expired certificates' -Source 'Cert:\LocalMachine\My'
    }
}
