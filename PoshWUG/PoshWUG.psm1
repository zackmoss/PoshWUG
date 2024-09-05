
#region Core API Functions


function Get-WUGToken {

    param (

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential
    )

    $currentProtocol = [Net.ServicePointManager]::SecurityProtocol

    if ($currentProtocol.ToString().Split(',').Trim() -notcontains 'Tls12') {

        [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
    }

    Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;

public class InSecureWebPolicy : ICertificatePolicy
{
    public bool CheckValidationResult(ServicePoint sPoint, X509Certificate cert,WebRequest wRequest, int certProb)
    {
        return true;
    }
}
'@

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName InSecureWebPolicy

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

function Request-WUGRefreshToken {

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

        $Script:wugConnection | Add-Member -MemberType NoteProperty -Name wugTokenExpiry -Value $wugTokenExpiry -Force
        $Script:wugConnection | Add-Member -MemberType NoteProperty -Name wugRefreshToken -Value $wugRefreshToken -Force
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


function Get-WUGDevice {

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

            Request-WUGRefreshToken
        }

        if ($DeviceName) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/devices/-?search={2}&view=basic' -f $Script:urlVar, $GroupID, $DeviceName
        }
        else {

            $uri = '{0}:9644/api/v1/device-groups/{1}/devices/-?view=basic' -f $Script:urlVar, $GroupID
        }

        try {

            $initialResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $initialResponse.paging.nextPageId

            $returnObject = @()

            $returnObject += $initialResponse.data.devices
        }
        catch {

            Write-Error $_
        }
    }

    process {

        while ($nextPageId) {

            $uri += '&pageId={0}' -f $nextPageId

            $continuedResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $continuedResponse.paging.nextPageId

            $returnObject += $continuedResponse.data.devices
        }
    }

    end {

        $returnObject
    }
}

function Get-WUGDeviceGroupAssignment {

    param (

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $DeviceID,

        [string] $GroupName
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

            Request-WUGRefreshToken
        }

        if ($DeviceName) {

            $uri = '{0}:9644/api/v1/devices/{1}/group/-?search={2}&type=static_group' -f $Script:urlVar, $DeviceID, $DeviceName
        }
        else {

            $uri = '{0}:9644/api/v1/devices/{1}/group/-?type=static_group' -f $Script:urlVar, $DeviceID
        }

        try {

            $initialResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $initialResponse.paging.nextPageId

            $returnObject = @()

            $returnObject += $initialResponse.data
        }
        catch {

            Write-Error $_
        }
    }

    process {

        while ($nextPageId) {

            $uri += '&pageId={0}' -f $nextPageId

            $continuedResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $continuedResponse.paging.nextPageId

            $returnObject += $continuedResponse.data
        }
    }

    end {

        $returnObject
    }
}

function Get-WUGDeviceAttribute {

    param (

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $DeviceID,

        [string] $AttributeName
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

            Request-WUGRefreshToken
        }

        $uri = '{0}:9644/api/v1/devices/{1}/attributes/-?names={2}' -f $Script:urlVar, $DeviceID, $AttributeName

        try {

            $initialResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $initialResponse.paging.nextPageId

            $returnObject = @()

            $returnObject += $initialResponse.data
        }
        catch {

            Write-Error $_
        }
    }

    process {

        while ($nextPageId) {

            $uri += '&pageId={0}' -f $nextPageId

            $continuedResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $continuedResponse.paging.nextPageId

            $returnObject += $continuedResponse.data
        }
    }

    end {

        $returnObject
    }
}

function Add-WUGActiveMonitorToDevice {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $DeviceID,

        [Parameter(Mandatory)]
        [string] $ActiveMonitorID
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

            Request-WUGRefreshToken
        }
    }

    process {

        $uri = '{0}:9644/api/v1/devices/{1}/monitors/-' -f $Script:urlVar, $DeviceID

        $requestBody = @(
            @{
                type          = 'active'
                monitorTypeId = $ActiveMonitorID
                enabled       = $true
            }
        )

        $requestBody = $requestBody | ConvertTo-Json

        try {

            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $Script:wugHeaders -Body $requestBody

            if ($response.data."successful" -eq 1) {

                Write-Log -Message '[INFO] Successfully added monitor to device' -Severty Info -Console
            }
        }
        catch {

            Write-Error $_
        }
        
    }
}

function Add-WUGMonitoredDevice {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $GroupID = '0',

        [Parameter(Mandatory)]
        [string[]] $DeviceIPAddress,

        [switch] $ForceAdd,

        [string] $DisplayName,

        [string] $Role
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

            Request-WUGRefreshToken
        }
    }

    process {

        foreach ($device in $DeviceIPAddress) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/newDevice?ipOrName={2}' -f $Script:urlVar, $GroupID, $device

            if ($ForceAdd) {

                $requestBody = @(
                    @{
                        forceAdd = $true
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

                    $deviceId = Get-WUGDevice -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device | Where-Object {

                        $_.networkAddress -eq $device
                    } | Select-Object -ExpandProperty id

                    Write-Log -Message '[INFO] Waiting for device to be created to obtain device ID' -Severty Info -Console

                    while ($deviceId.Length -le 0) {

                        Start-Sleep -Seconds 10

                        $deviceId = Get-WUGDevice -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device | Where-Object {

                            $_.networkAddress -eq $device
                        } | Select-Object -ExpandProperty id
                    }

                    Write-Log -Message ('[INFO] New device ID {0}' -f $deviceId) -Severty Info -Console

                    Update-WUGDeviceProperty -WUGServer $WUGServer -Credential $Credential -DeviceID $deviceId -DisplayName $DisplayName
                }
            }
            catch {

                Write-Error $_
            }
        }
    }
}

function Update-WUGDeviceProperty {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $DeviceID,

        [string] $DisplayName,

        [string] $Notes,

        [string] $Role
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

            Request-WUGRefreshToken
        }
    }

    process {

        if ($Role) {

            $roleID = Get-WUGDeviceRole -WUGServer $WUGServer -Credential $Credential -Search $Role | Select-Object -ExpandProperty id

            $uri = '{0}:9644/api/v1/devices/{1}/roles/-?roleId={2}' -f $Script:urlVar, $DeviceID, $roleID
        }
        else {

            $uri = '{0}:9644/api/v1/devices/{1}/properties' -f $Script:urlVar, $DeviceID
        }

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

function Get-WUGDeviceRole {

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

            Request-WUGRefreshToken
        }
    }

    process {

        $uri = '{0}:9644/api/v1/device-role/-' -f $Script:urlVar

        if ($Search) {

            $uri += '?search={0}' -f $Search
        }

        try {

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $response.data
        }
        catch {

            Write-Error $_
        }
    }
}


#endregion

#region Device Group Functions


function Add-WUGDeviceGroup {

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

            Request-WUGRefreshToken
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

function Invoke-WUGDeviceMaintenanceMode {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $Enable,

        [int] $EnabledHours = 0,

        [string] $DeviceName,

        [string] $ReasonComment
    )

    if (!$Script:wugHeaders) {

        Write-Warning -Message 'Authorization header not set, running Connect-WUGServer'

        Get-WUGToken -WUGServer $WUGServer -Credential $Credential
    }
    elseif ((Get-Date) -ge $Script:wugConnection.wugTokenExpiry) {

        Write-Warning -Message 'Token expired, running Connect-WUGServer'

        Get-WUGToken -WUGServer $WUGServer -Credential $Credential
    }
    else {

        Request-WUGRefreshToken
    }

    if ($EnabledHours -gt 0) {

        $dateTimeUTC = Get-Date ([datetime]::UtcNow)
        $addedDateTime = $dateTimeUTC.AddHours($EnabledHours)
        $endTimeUTC = $addedDateTime.ToString("O")
    }

    $deviceID = Get-DeviceIDByName -DeviceName $DeviceName -WUGServer $WUGServer -Credential $Credential

    $uri = '{0}:9644/api/v1/devices/{1}/config/maintenance' -f $Script:urlVar, $deviceID

    if ($Enable) {

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

        $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $Script:wugHeaders -Body $requestBody

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

        Write-Error $_
    }
}

function Get-WUGDeviceGroupsSummary {

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

            Request-WUGRefreshToken
        }
    }

    process {

        $deviceGroups = Get-WUGDeviceGroup -WUGServer $WUGServer -Credential $Credential -Search $Search

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

function Get-WUGDeviceGroup {

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

            Request-WUGRefreshToken
        }

        switch ($GroupType) {

            'static' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=static_group' -f $Script:urlVar }

            'dynamic' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=dynamic_group' -f $Script:urlVar }

            'layer2' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=layer2' -f $Script:urlVar }

            Default { $uri = '{0}:9644/api/v1/device-groups/-' -f $Script:urlVar }
        }

        if ($Search) {

            if ($GroupType) {

                $uri += '&search={0}' -f $Search
            }
            else {

                $uri += '?search={0}' -f $Search
            }
        }

        try {

            $initialResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $initialResponse.paging.nextPageId

            $returnObject = @()

            $returnObject += $initialResponse.data.groups
        }
        catch {

            Write-Error $_
        }
    }

    process {

        while ($nextPageId) {

            if ($GroupType) {

                $uri += '&pageId={0}' -f $nextPageId
            }
            elseif ($Search) {

                $uri += '&pageId={0}' -f $nextPageId
            }
            else {

                $uri += '?pageId={0}' -f $nextPageId
            }

            $continuedResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $nextPageId = $continuedResponse.paging.nextPageId

            $returnObject += $continuedResponse.data.groups
        }
    }

    end {

        $returnObject
    }
}

function Invoke-WUGDeviceGroupRefresh {

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

            Request-WUGRefreshToken
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


function Add-WUGMonitor {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [ValidateSet('active', 'performance', 'passive')]
        [string] $MonitorType,

        [Parameter(Mandatory)]
        [string] $MonitorName,

        [Parameter(Mandatory)]
        [string] $MonitorDescription,

        [Parameter(Mandatory)]
        [string] $ClassID,

        [switch] $UseSNMP
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

            Request-WUGRefreshToken
        }
    }

    process {

        $uri = '{0}:9644/api/v1/monitors/-' -f $Script:urlVar

        if ($UseSNMP) {

            $snmp = '1'
        }
        else {

            $snmp = '0'
        }

        $requestBody = @(
            @{
                useInDiscovery  = $true
                name            = $MonitorName
                description     = $MonitorDescription
                monitorTypeInfo = @{
                    baseType = $MonitorType
                    classId  = $ClassID
                }
                propertyBags    = @(
                    @{
                        name  = 'NTSERVICE:ServiceDisplayName'
                        value = $ServiceDisplayName
                    }
                    @{
                        name  = 'NTSERVICE:ServiceInternalName'
                        value = ('Win32_Service.Name="{0}"' -f $ServiceInternalName)
                    }
                    @{
                        name  = 'NTSERVICE:RestartOnFailure'
                        value = '1'
                    }
                    @{
                        name  = 'NTSERVICE:SNMPRetries'
                        value = '1'
                    }
                    @{
                        name  = 'NTSERVICE:SNMPTimeout'
                        value = '3'
                    }
                    @{
                        name  = 'NTSERVICE:UseSNMP'
                        value = $snmp
                    }
                )
            }
        )

        $requestBody = $requestBody | ConvertTo-Json

        try {

            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $Script:wugHeaders -Body $requestBody

            $response
        }
        catch {

            Write-Error $_
        }
    }

    end {

    }

}

function Get-WUGMonitor {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $Search,

        [ValidateSet('active', 'passive', 'performance')]
        [string] $MonitorType = 'active'
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

            Request-WUGRefreshToken
        }
    }

    process {

        $uri = '{0}:9644/api/v1/monitors/-?includeCoreMonitors=true' -f $Script:urlVar

        if ($Search) {

            $uri += '&search={0}' -f $Search
        }

        switch ($MonitorType) {

            active { $uri += '&type={0}' -f $MonitorType }
            passive { $uri += '&type={0}' -f $MonitorType }
            performance { $uri += '&type={0}' -f $MonitorType }
        }

        try {

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            switch ($MonitorType) {

                active { $response.data.activeMonitors }
                passive { $response.data.passiveMonitors }
                performance { $response.data.performanceMonitors }
            }
        }
        catch {

            Write-Error $_
        }
    }
}


#endregion

#region Reporting


function Get-WUGDeviceGroupUptime {

    param(

        [Parameter(Mandatory)]
        [string] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $GroupID,

        [string] $BusinessHoursID,

        [Parameter()]
        [ValidateSet('today', 'lastPolled', 'yesterday', 'lastMonth', 'lastQuarter', 'weekToDate', 'monthToDate', 'quarterToDate')]
        [string] $ReportRange = 'today'
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

            Request-WUGRefreshToken
        }
    }

    process {

        $uri = '{0}:9644/api/v1/device-groups/{1}/devices/reports/ping-availability?returnHierarchy=false' -f $Script:urlVar, $GroupID

        switch ($PSBoundParameters.Keys) {

            'BusinessHoursID' { $uri += '&businessHoursId={0}' -f $BusinessHoursID }
            'ReportRange' { $uri += '&range={0}' -f $ReportRange }
        }

        try {

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $Script:wugHeaders

            $response.data
        }
        catch {

            Write-Error $_
        }
    }
}


#endregion
