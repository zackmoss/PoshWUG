
#region Core API Functions


function Get-WUGToken {

    param (

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential
    )

    $Script:urlVar = 'https://{0}' -f $WUGServer

    $uri = '{0}:9644/api/v1/token' -f $Script:urlVar

    $requestBody = @{

        username   = $Credential.UserName
        password   = $Credential.GetNetworkCredential().Password
        grant_type = 'password'
    }

    try {

        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $requestBody

        $wugRefreshToken = $response.refresh_token
        $wugTokenExpiry = (Get-Date).AddSeconds($response.expires_in)

        $Script:wugConnection = New-Object -TypeName psobject

        $Script:wugConnection | Add-Member -MemberType NoteProperty -Name wugTokenExpiry -Value $wugTokenExpiry
        $Script:wugConnection | Add-Member -MemberType NoteProperty -Name wugRefreshToken -Value $wugRefreshToken

        $Script:wugHeaders = @{

            'Content-Type'  = 'application/json'
            'Authorization' = '{0} {1}' -f $response.token_type, $response.access_token
        }
    }
    catch {

        Write-Error $_
    }
}

function Request-WUGAuthToken {

    [CmdletBinding()]
    param(

        [Parameter()]
        [int] $RefreshMinutes = 5
    )

    if ((Get-Date).AddMinutes($RefreshMinutes) -ge $Script:wugConnection.wugTokenExpiry) {

        $refreshTokenUri = '{0}:9644/api/v1/token' -f $Script:urlVar

        $refreshTokenHeaders = @{"Content-Type" = "application/json" }

        $refreshTokenBody = @{

            refresh_token = $Script:wugConnection.wugRefreshToken
            grant_type    = 'refresh_token'
        }

        try {

            $newToken = Invoke-RestMethod -Uri $refreshTokenUri -Method Post -Headers $refreshTokenHeaders -Body $refreshTokenBody
        }
        catch {

            Write-Error -Message ('Error: {0}' -f $_.Exception.Response.StatusDescription)
        }

        $Script:wugHeaders = @{

            "Content-Type"  = 'application/json'
            "Authorization" = '{0} {1}' -f $newToken.token_type, $newToken.access_token
        }

        $wugRefreshToken = $newToken.refresh_token

        $wugTokenExpiry = (Get-Date).AddSeconds($newToken.expires_in)

        $Global:wugConnection | Add-Member -MemberType NoteProperty -Name wugTokenExpiry -Value $wugTokenExpiry -Force
        $Global:wugConnection | Add-Member -MemberType NoteProperty -Name wugRefreshToken -Value $wugRefreshToken -Force
    }
    else {

        Write-Verbose -Message ('No need to refresh yet, token expires {0}' -f $Script:wugConnection.wugTokenExpiry)
    }
}


#endregion

#region Helper Functions


function Write-Log {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string] $Message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Info', 'Warn', 'Error')]
        [string] $Severty = 'Info',

        [switch] $Console,

        [switch] $LogToFile
    )

    $logTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    $logObject = [PSCustomObject]@{

        Time    = $logTimestamp
        Severty = $Severty
        Message = $Message
    }

    if ($LogToFile) {

        $logObject | Export-Csv -Path ('{0}\{1}_PSLog.csv' -f $env:TEMP, (Get-Date -Format 'MMddyyy')) -NoTypeInformation -Encoding ASCII
    }

    if ($Console) {

        switch ($Severty) {

            Warn {

                Write-Host -Object ('{0} [{1}]' -f $logObject.Time, $logObject.Severty) -ForegroundColor Gray
                Write-Host -Object ('{0}' -f $logObject.Message) -ForegroundColor Yellow
            }
            Error {

                Write-Host -Object ('{0} [{1}]' -f $logObject.Time, $logObject.Severty) -ForegroundColor Gray
                Write-Host -Object ('{0}' -f $logObject.Message) -ForegroundColor Red
            }
            Default {

                Write-Host -Object ('{0} [{1}]' -f $logObject.Time, $logObject.Severty) -ForegroundColor Gray
                Write-Host -Object ('{0}' -f $logObject.Message) -ForegroundColor Cyan
            }
        }
    }
}


#endregion

#region Device Functions


function Get-DeviceIDByName {

    param (

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $GroupID = '-1',

        [string] $DeviceName
    )

    begin {

        if (!$Script:wugHeaders) {

            Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

            Write-Warning -Message 'Token expired, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        else {

            Request-WUGAuthToken
        }
    }

    process {

        if ($DeviceName) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/devices?search={2}' -f $Script:urlVar, $GroupID, $DeviceName
        }
        else {

            $uri = '{0}:9644/api/v1/device-groups/{1}/devices/-' -f $Script:urlVar, $GroupID
        }

        try {

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            [string] $response.data.'devices'.'id'
        }
        catch {

            Write-Error $_
        }
    }
}

function Add-MonitoredDevice {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $GroupID = '0',

        [Parameter(Mandatory)]
        [string[]] $DeviceIPAddress,

        [switch] $ForceAdd,

        [string] $DisplayName
    )

    begin {

        if (!$Script:wugHeaders) {

            Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

            Write-Warning -Message 'Token expired, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        else {

            Request-WUGAuthToken
        }
    }

    process {

        foreach ($device in $DeviceIPAddress) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/newDevice?ipOrName={2}' -f $Script:urlVar, $GroupID, $device

            if ($ForceAdd) {

                $requestBody = @(
                    @{
                        forceAdd          = $true
                        useAllCredentials = $true
                    }
                )
            }
            else {

                $requestBody = @(
                    @{
                        useAllCredentials = $true
                    }
                )
            }

            $requestBody = $requestBody | ConvertTo-Json

            try {

                $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $Script:wugHeaders -Body $requestBody

                if ($response.data."success" -eq $true) {

                    Write-Log -Message ('[INFO] Successfully added device {0}' -f $device) -Severty Info -Console

                    $deviceId = Get-DeviceIDByName -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device

                    Write-Log -Message '[INFO] Waiting for device to be created to obtain device ID' -Severty Info -Console

                    while ($deviceId.Length -le 0) {

                        $deviceId = Get-DeviceIDByName -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device
                    }

                    Write-Log -Message ('[INFO] New device ID {0}' -f $deviceId) -Severty Info -Console

                    Update-DeviceProperty -WUGServer $WUGServer -Credential $Credential -DeviceID $deviceId -DisplayName $DisplayName
                }
            }
            catch {

                Write-Error $_
            }
        }
    }
}

function Update-DeviceProperty {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $DeviceID,

        [string] $DisplayName,

        [string] $Notes
    )

    begin {

        if (!$Script:wugHeaders) {

            Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

            Write-Warning -Message 'Token expired, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        else {

            Request-WUGAuthToken
        }
    }

    process {

        $uri = '{0}:9644/api/v1/devices/{1}/properties' -f $Script:urlVar, $DeviceID

        $requestBody = @(
            @{
                displayName = $DisplayName
                notes       = $Notes
            }
        )

        $requestBody = $requestBody | ConvertTo-Json

        try {

            $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $Script:wugHeaders -Body $requestBody

            if ($response.data."success" -eq $true) {

                Write-Log -Message ('[INFO] Successfully updated device {0}' -f $DisplayName) -Severty Info -Console
            }
        }
        catch {

            Write-Error $_
        }
    }
}


#endregion

#region Device Group Functions


function Add-DeviceGroup {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $ParentGroupID,

        [Parameter(Mandatory)]
        [string] $GroupName,

        [string] $GroupDescription
    )

    begin {

        if (!$Script:wugHeaders) {

            Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

            Write-Warning -Message 'Token expired, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        else {

            Request-WUGAuthToken
        }
    }

    process {

        $uri = '{0}:9644/api/v1/device-groups/{1}/child' -f $Script:urlVar, $ParentGroupID

        $requestBody = @(
            @{
                name        = $GroupName
                description = $GroupDescription
            }
        )

        $requestBody = $requestBody | ConvertTo-Json

        try {

            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $Script:wugHeaders -Body $requestBody

            Write-Log -Message ('[INFO] Successfully added group {0}' -f $GroupName) -Severty Info -Console
        }
        catch {

            Write-Error $_
        }
    }
}

function Get-DeviceGroupsSummary {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $Search
    )

    begin {

        if (!$Script:wugHeaders) {

            Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

            Write-Warning -Message 'Token expired, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        else {

            Request-WUGAuthToken
        }
    }

    process {

        $deviceGroups = Get-DeviceGroup -WUGServer $WUGServer -Credential $Credential -Search $Search

        foreach ($group in $deviceGroups) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/status' -f $Script:urlVar, $group.id

            try {

                $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

                [PSCustomObject]@{

                    GroupName          = $group.name
                    UpDevices          = $response.data.stateSummaries.deviceCount[0]
                    DownDevices        = $response.data.stateSummaries.deviceCount[1]
                    MaintenanceDevices = $response.data.stateSummaries.deviceCount[2]
                    UnknownDevices     = $response.data.stateSummaries.deviceCount[3]
                }
            }
            catch {

                Write-Error $_
            }
        }
    }
}

function Get-DeviceGroup {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $Search,

        [ValidateSet('static', 'dynamic', 'layer2')]
        [string] $GroupType
    )

    begin {

        if (!$Script:wugHeaders) {

            Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

            Write-Warning -Message 'Token expired, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        else {

            Request-WUGAuthToken
        }
    }

    process {

        if ($Search) {

            $uri = '{0}:9644/api/v1/device-groups/-?search={1}' -f $Script:urlVar, $Search
        }
        else {

            switch ($GroupType) {

                'static' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=static_group' -f $Script:urlVar }

                'dynamic' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=dynamic_group' -f $Script:urlVar }

                'layer2' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=layer2' -f $Script:urlVar }

                Default { $uri = '{0}:9644/api/v1/device-groups/-' -f $Script:urlVar }
            }
        }

        try {

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $response.data.groups
        }
        catch {

            Write-Error $_
        }
    }
}

function Invoke-DeviceGroupRefresh {

    [CmdletBinding()]
    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $GroupId,

        [string] $Search
    )

    begin {

        if (!$Script:wugHeaders) {

            Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

            Write-Warning -Message 'Token expired, running Connect-WUGServer'

            Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
        else {

            Request-WUGAuthToken
        }

        $updateNamesActiveMonitor = 'updateNamesForInterfaceActiveMonitor=true'
        $updateInterfaceActiveMonitor = 'updateEnableSettingsForInterfaceActiveMonitor=true'
    }

    process {

        if ($Search) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/refresh?search={2}&{3}&{4}' `
                -f $Script:urlVar, $GroupId, $Search, $updateNamesActiveMonitor, $updateInterfaceActiveMonitor
        }
        else {

            $uri = '{0}:9644/api/v1/device-groups/{1}/refresh?{3}&{4}' `
                -f $Script:urlVar, $GroupId, $updateNamesActiveMonitor, $updateInterfaceActiveMonitor
        }

        try {

            $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $Script:wugHeaders

            Write-Log -Message ('[INFO] Successfully refreshed device group {0}' -f $GroupId) -Severty Info -Console
        }
        catch {

            Write-Error $_
        }
    }

    end {

    }
}


#endregion

#region Monitor Functions


function Get-Monitor {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential
    )

    begin {

        $token = Get-WUGToken -WUGServer $WUGServer -Credential $Credential

        $headers = @{

            "Content-Type"  = "application/json"
            "Authorization" = 'bearer {0}' -f $token.access_token
        }
    }

    process {

        $uri = '{0}:9644/api/v1/monitors/-' -f $Script:urlVar

        try {

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

            $response
        }
        catch {

            $result = $_.Exception.Response.GetResponseStream()

            $reader = New-Object System.IO.StreamReader($result)

            $reader.BaseStream.Position = 0

            $reader.DiscardBufferedData()

            $responseBody = $reader.ReadToEnd() | ConvertFrom-Json

            Write-Log -Message $($responseBody.error) -Severty Error -Console
        }
    }
}


#endregion

#region Dev


<# TODO Fix Function for new auth token method
function Enable-DeviceMaintMode {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [bool] $Enable = $True,

        [int] $EnabledHours = 0,

        [string] $DeviceName,

        [string] $ReasonComment
    )

    if ($EnabledHours -gt 0) {

        $dateTimeUTC = Get-Date ([datetime]::UtcNow)
        $addedDateTime = $dateTimeUTC.AddHours($EnabledHours)
        $endTimeUTC = $addedDateTime.ToString("O")
    }

    $deviceID = Get-DeviceIDByName -DeviceName $DeviceName -WUGServer $WUGServer -Credential $Credential

    $uri = 'http://{0}:9644/api/v1/devices/{1}/config/maintenance' -f $WUGServer, $deviceID

    if ($Enable -eq $true) {

        $requestBody = @(
            @{
                enabled = $true
                endUtc  = $endTimeUTC
                reason  = $ReasonComment
            }
        )
    }
    else {

        $requestBody = @(
            @{
                enabled = $false
            }
        )
    }

    $requestBody = $requestBody | ConvertTo-Json

    try {

        $authToken = Get-WUGToken -ServerIPAddress $WUGServer -Credential $Credential

        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $headers.Add("Authorization", "Bearer $authToken")
        $headers.Add("Accept", "application/json")

        $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body $requestBody

        if ($response.data."success" -eq $true) {

            if (!$Enable) {

                Write-Host -Object ('[INFO] Successfully disabled maintenance mode on {0}' -f $DeviceName) -ForegroundColor 'Cyan'
            }
            else {

                Write-Host -Object ('[INFO] Successfully enabled maintenance mode on {0}' -f $DeviceName) -ForegroundColor 'Cyan'
            }
        }


    }
    catch {

        $result = $_.Exception.Response.GetResponseStream()

        $reader = New-Object System.IO.StreamReader($result)

        $reader.BaseStream.Position = 0

        $reader.DiscardBufferedData()

        $responseBody = $reader.ReadToEnd() | ConvertFrom-Json

        Write-Host -Object ('[ERROR] {0}' -f $responseBody.error) -ForegroundColor 'Red'
    }
}
#>


#endregion
