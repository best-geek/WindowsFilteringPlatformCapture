 
param ($CaptureSeconds)
if (-Not ($CaptureSeconds)) {
    $CaptureSeconds=10
}
# https://github.com/best-geek/WindowsFilteringPlatformCapture
#   Will enable auditing of packet filtering in Windows
#   Allows auditing to occur for 'x' seconds
#   Will scrape events from the Windows Event log
#   Will then enrich matching FilterIds against loaded firewall state
#   Will then enrich matching discovered local ports against net filter rules [see readme because this may yield false positives]
#   Script will suggest files to take a copy of that contain useful information
#   Note: This script will reset the packet filtering audit policy to none to save disk space


Write-Host "[-] Allowing Filtering Platform to run for $CaptureSeconds seconds"


$TempDir=$env:TEMP 
Set-Location -Path $TempDir
Write-Host "[-] Working From: $TempDir"


Write-Host "[-] Dumping Firewall Filters"
netsh wfp show filters


Write-Host "[-] Load Firewall Filters"
$xmlData = New-Object System.Xml.XmlDocument
$xmlPath= Join-Path $TempDir -ChildPath "filters.xml"
$xmlData.Load($xmlPath)

# get current audit pol config
Write-Host "[-] Enable audit of Packet Filtering"
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable  
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable  

Write-Host "[-] Allowing Packet Filtering events to occur for $CaptureSeconds seconds..."
Start-Sleep $CaptureSeconds

Write-Host "[-] Exporting matching Firewall logs from Windows Event Log. Will take time. "
Get-EventLog -LogName Security -Message "*Filtering Platform has*" | Select-Object -Property EntryType,TimeGenerated,Source,EventID,Category,Message | Export-CSV -Path "FilteringPlatformEvents.csv" 

Write-Host "[-] Enriching Data with Firewall State. This will take a while. "
$PlatformEvents = Import-Csv FilteringPlatformEvents.csv
foreach ($Log in $PlatformEvents)
{


  # Enrich by FilterId 
  $Log -match 'Filter Run-Time ID:\s(\d+)' > $null
  $RuleIdEventMatch =  $Matches.1

  $MatchedRuleName="Unknown"
  if ($RuleIdEventMatch) {

      $RuleName = $xmlData.SelectNodes("//filters/item[filterId=$RuleIdEventMatch]/displayData/name").'#text'

      if ($RuleName) {
      $MatchedRuleName = $RuleName
      }

  }
  # Write additional fields
  $Log | Add-Member -NotePropertyName "EnrichedFilterIdResult" -NotePropertyValue $RuleName

  

  # Enrich by NetFireWallPortFilter
  $PossibleNetPortFilter = ''
  # 14592 correlated with inbound during testing
  if ($Log.Message -match "Direction:		%%14592") {
        
        $Log -match 'Destination Port:\W\W(\d+)' > $null
        $DestinationPort =  $Matches.1
        $PossibleNetPortFilter = Get-NetFirewallPortFilter -All -PolicyStore ActiveStore | Where LocalPort -EQ $DestinationPort | Select InstanceID,Protocol | Out-String
  }


  # Write additional fields
  $Log | Add-Member -NotePropertyName "EnrichedNetFirewallPortFilter" -NotePropertyValue $PossibleNetPortFilter
}

$PlatformEvents | Export-Csv -Path 'FilteringPlatformEvents-Enriched.csv' -NoTypeInformation


Write-Host "[-] Disable audit of Packet Filtering"
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable  
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable  

Write-Host "[-] Current Config:"
auditpol /get /subcategory:"Filtering Platform Connection"
auditpol /get /subcategory:"Filtering Platform Connection"


Write-Host "[-] Complete. Obtain and review the following files:"
Join-Path -Path $TempDir -ChildPath "FilteringPlatformEvents.csv"
Join-Path -Path $TempDir -ChildPath "FilteringPlatformEvents-Enriched.csv"
Join-Path -Path $TempDir -ChildPath "filters.xml" 
