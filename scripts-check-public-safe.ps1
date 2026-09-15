$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$blockedNames = @('.env','*.pem','*.key','*.pfx','*.p12','*.crt','*.msi','*.log','*.pyc')
$files = Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
  $_.FullName -notmatch '\\.git\\'
}
foreach ($file in $files) {
  if ($file.Name -eq 'scripts-check-public-safe.ps1') { continue }
  foreach ($pattern in $blockedNames) {
    if ($file.Name -like $pattern) {
      throw "Blocked file type present: $($file.FullName)"
    }
  }
  $lines = Get-Content -LiteralPath $file.FullName -ErrorAction Stop
  foreach ($line in $lines) {
    if ($line -match 'for marker in') { continue }
    if ($line -match '(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----') {
      throw "Private key material detected: $($file.FullName)"
    }
    if ($line -match '(?i)(gho_|github_pat_|xox[baprs]-|sk-[A-Za-z0-9]{20,})') {
      throw "Credential-shaped token detected: $($file.FullName)"
    }
    if ($line -match '(?i)(SPLUNK_PASSWORD|VERCEL_TOKEN|SUPABASE_KEY|FIREBASE_SERVICE_ACCOUNT)\s*(=|:)\s*(?<value>.+)$') {
      $value = $Matches['value'].Trim()
      if ($value -notmatch '^(\$|<|your-|placeholder|\(|\{)') {
        throw "Credential assignment detected: $($file.FullName)"
      }
    }
  }
}
Write-Output 'Public-safety scan passed.'


