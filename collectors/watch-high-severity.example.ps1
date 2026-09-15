param(
  [int]$WindowMinutes = 10,
  [string]$SecretPath = 'C:\SOC-Secrets\wazuh-readonly.json',
  [string]$StatePath = 'C:\SOC-Lab\state\wazuh-high-severity.json',
  [string]$OutputDirectory = 'C:\SOC-Lab\live'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path (Split-Path -Parent $StatePath) -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$cfg = Get-Content -LiteralPath $SecretPath -Raw | ConvertFrom-Json
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($cfg.username):$($cfg.password)"))
$headers = @{ Authorization = "Basic $basic" }

$body = @{
  size = 500
  sort = @(@{ timestamp = @{ order = 'desc' } })
  query = @{
    bool = @{
      must = @(
        @{ range = @{ timestamp = @{ gte = "now-${WindowMinutes}m" } } }
        @{ range = @{ 'rule.level' = @{ gte = 12 } } }
      )
    }
  }
  _source = @(
    '@timestamp', 'timestamp', 'agent.name', 'agent.id', 'rule.id', 'rule.level',
    'rule.description', 'data.source', 'data.event_id', 'data.event_type',
    'data.action', 'data.outcome', 'data.severity', 'data.message',
    'data.event_time', 'data.route', 'data.deployment_url', 'data.win'
  )
} | ConvertTo-Json -Depth 20

$response = Invoke-RestMethod -Method Post -SkipCertificateCheck `
  -Uri "$($cfg.base_url)/wazuh-alerts-*/_search" `
  -Headers $headers -ContentType 'application/json' -Body $body

$state = @{ seen = @(); last_run = $null }
if (Test-Path -LiteralPath $StatePath) {
  try { $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json } catch { }
}
$seen = @($state.seen | ForEach-Object { [string]$_ })
$newEvents = New-Object System.Collections.Generic.List[object]
$allKeys = New-Object System.Collections.Generic.List[string]

foreach ($hit in $response.hits.hits) {
  $s = $hit._source
  $key = [string]$hit._id
  if ([string]::IsNullOrWhiteSpace($key)) {
    $key = "{0}|{1}|{2}|{3}" -f $s.timestamp, $s.rule.id, $s.data.event_id, $s.agent.name
  }
  $allKeys.Add($key)
  if ($seen -contains $key) { continue }

  $win = $s.data.win
  $newEvents.Add([pscustomobject]@{
    alert_key = $key
    timestamp = if ($s.'@timestamp') { [string]$s.'@timestamp' } else { [string]$s.timestamp }
    agent = [string]$s.agent.name
    agent_id = [string]$s.agent.id
    rule_id = [string]$s.rule.id
    rule_level = [int]$s.rule.level
    rule_description = [string]$s.rule.description
    source = [string]$s.data.source
    event_id = [string]$s.data.event_id
    event_type = [string]$s.data.event_type
    action = [string]$s.data.action
    outcome = [string]$s.data.outcome
    severity = [string]$s.data.severity
    message = [string]$s.data.message
    producer_time = [string]$s.data.event_time
    route = [string]$s.data.route
    deployment_url = [string]$s.data.deployment_url
    image = [string]$win.eventdata.image
    target = [string]$win.eventdata.targetFilename
    script_block = [string]$win.eventdata.scriptBlockText
  })
}

$retained = @($seen + $allKeys | Select-Object -Unique | Select-Object -Last 2000)
@{ seen = $retained; last_run = [DateTimeOffset]::Now.ToString('o') } |
  ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $StatePath -Encoding UTF8

$latestJson = Join-Path $OutputDirectory 'latest-high-severity.json'
$latestNdjson = Join-Path $OutputDirectory 'high-severity.ndjson'
$latestMarkdown = Join-Path $OutputDirectory 'latest-high-severity.md'
$newEvents | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $latestJson -Encoding UTF8
foreach ($event in $newEvents) {
  $event | ConvertTo-Json -Compress -Depth 20 | Add-Content -LiteralPath $latestNdjson -Encoding UTF8
}

$checked = [DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
$md = New-Object System.Collections.Generic.List[string]
$md.Add('# New high-severity Wazuh alerts')
$md.Add('')
$md.Add("Checked: $checked")
$md.Add("Window: last $WindowMinutes minutes; rule level 12 or higher")
$md.Add('')
if ($newEvents.Count -eq 0) {
  $md.Add('No new high-severity alerts since the previous check.')
} else {
  $md.Add("New alerts: $($newEvents.Count)")
  $md.Add('')
  foreach ($event in $newEvents) {
    $label = if ($event.source) { $event.source } else { 'windows' }
    $detail = if ($event.message) { $event.message } elseif ($event.rule_description) { $event.rule_description } else { $event.event_type }
    $md.Add("- [$($event.timestamp)] level $($event.rule_level) rule $($event.rule_id) ($label/$($event.agent)): $detail")
  }
}
$md | Set-Content -LiteralPath $latestMarkdown -Encoding UTF8

Write-Output "NewHighSeverity=$($newEvents.Count) Output=$latestMarkdown"
