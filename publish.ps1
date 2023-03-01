
$modulePath = "$PSScriptRoot\PoshWUG"

Publish-Module -Path $modulePath -NuGetApiKey $Env:APIKEY
