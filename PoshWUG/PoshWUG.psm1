
#region Core API Functions


function Get-WUGToken {

    param (

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [Switch] $IgnoreCertificateErrors
    )

    if ($IgnoreCertificateErrors) {

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

        $currentPolicy = [System.Net.ServicePointManager]::CertificatePolicy

        [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName InSecureWebPolicy
    }

    if ($NoTLS) {

        $Script:urlVar = 'http://{0}' -f $WUGServer
    }
    else {

        $Script:urlVar = 'https://{0}' -f $WUGServer
    }

    $uri = '{0}:9644/api/v1/token' -f $Script:urlVar

    $requestBody = @{

        username   = $Credential.UserName
        password   = $Credential.GetNetworkCredential().Password
        grant_type = 'password'
    }

    try {

        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $requestBody

        $token = $response.access_token

        $token
    }
    catch {

        $result = $_.Exception.Response.GetResponseStream()

        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()

        $responseBody = $reader.ReadToEnd() | ConvertFrom-Json

        Write-Log -Message $($responseBody.error) -Severty Error -Console
    }

    [System.Net.ServicePointManager]::CertificatePolicy = $currentPolicy
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
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [string] $GroupID = '0',

        [string] $DeviceName
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }

    }

    process {

        $uri = '{0}:9644/api/v1/device-groups/{1}/devices?search={2}' -f $Script:urlVar, $GroupID, $DeviceName

        try {

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "Bearer $authToken")
            $headers.Add("Accept", "application/json")

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

            [string] $response.data.'devices'.'id'
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

function Add-MonitoredDevice {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [string] $GroupID = '0',

        [Parameter(Mandatory)]
        [string[]] $DeviceIPAddress,

        [bool] $ForceAdd = $True,

        [string] $DisplayName
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
    }

    process {

        foreach ($device in $DeviceIPAddress) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/newDevice?ipOrName={2}' -f $Script:urlVar, $GroupID, $device

            if ($ForceAdd -eq $true) {

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

                $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $headers.Add("Content-Type", "application/json")
                $headers.Add("Authorization", "Bearer $authToken")
                $headers.Add("Accept", "application/json")

                $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body $requestBody

                if ($response.data."success" -eq $true) {

                    Write-Log -Message ('[INFO] Successfully added device {0}' -f $device) -Severty Info -Console

                    $deviceId = Get-DeviceIDByName -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device

                    Write-Log -Message '[INFO] Waiting for device to be created to obtain device ID' -Severty Info -Console

                    while ($deviceId.Length -le 0) {

                        $deviceId = Get-DeviceIDByName -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device
                    }

                    Write-Log -Message ('[INFO] New device ID {0}' -f $deviceId) -Severty Info -Console

                    Update-DeviceProperties -WUGServer $WUGServer -Credential $Credential -DeviceID $deviceId -DisplayName $DisplayName
                }
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
}

function Update-DeviceProperty {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [Parameter(Mandatory)]
        [string] $DeviceID,

        [string] $DisplayName,

        [string] $Notes
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
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

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "Bearer $authToken")
            $headers.Add("Accept", "application/json")

            $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body $requestBody

            if ($response.data."success" -eq $true) {

                Write-Log -Message ('[INFO] Successfully updated device {0}' -f $DisplayName) -Severty Info -Console
            }
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

#region Device Group Functions


function Get-DeviceGroupsSummary {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
    }

    process {

        $deviceGroups = Get-DeviceGroups -WUGServer $WUGServer -Credential $Credential

        foreach ($group in $deviceGroups) {

            $uri = '{0}:9644/api/v1/device-groups/{1}/status' -f $Script:urlVar, $group.id

            try {

                $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $headers.Add("Content-Type", "application/json")
                $headers.Add("Authorization", "Bearer $authToken")
                $headers.Add("Accept", "application/json")

                $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

                [PSCustomObject]@{

                    GroupName          = $group.name
                    UpDevices          = $response.data.stateSummaries.deviceCount[0]
                    DownDevices        = $response.data.stateSummaries.deviceCount[1]
                    MaintenanceDevices = $response.data.stateSummaries.deviceCount[2]
                    UnknownDevices     = $response.data.stateSummaries.deviceCount[3]
                }
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
}

function Get-DeviceGroup {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [string] $FindGroup,

        [ValidateSet('static', 'dynamic', 'layer2')]
        [string] $GroupType
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
    }

    process {

        if ($FindGroup) {

            $uri = '{0}:9644/api/v1/device-groups/-?search={1}' -f $Script:urlVar, $FindGroup
        }
        else {

            switch ($GroupType) {

                'static' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=static_group' -f $Script:urlVar }

                'dynamic' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=dynamic_group' -f $Script:urlVar }

                'static' { $uri = '{0}:9644/api/v1/device-groups/-?groupType=layer2' -f $Script:urlVar }

                Default { $uri = '{0}:9644/api/v1/device-groups/-' -f $Script:urlVar }
            }
        }

        try {

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "Bearer $authToken")
            $headers.Add("Accept", "application/json")

            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

            $response.data.groups
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

function Add-DeviceGroup {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [Parameter(Mandatory)]
        [string] $ParentGroupID,

        [Parameter(Mandatory)]
        [string] $GroupName,

        [string] $GroupDescription
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
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

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "Bearer $authToken")
            $headers.Add("Accept", "application/json")

            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $requestBody

            Write-Log -Message ('[INFO] Successfully added group {0}' -f $GroupName) -Severty Info -Console
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

#region Monitor Functions


function Get-Monitor {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }
    }

    process {

        $uri = '{0}:9644/api/v1/monitors/-' -f $Script:urlVar

        try {

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "Bearer $authToken")
            $headers.Add("Accept", "application/json")

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

function Add-Monitor {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [switch] $NoTLS,

        [ValidateSet('active', 'performance', 'passive')]
        [string] $MonitorType,

        [Parameter(Mandatory)]
        [string] $MonitorName,

        [Parameter(Mandatory)]
        [string] $MonitorDescription
    )

    begin {

        if ($NoTLS) {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
        }
        else {

            $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential
        }

    }

    process {

        $uri = '{0}:9644/api/v1/monitors/-' -f $Script:urlVar

        $requestBody = @(
            @{
                name            = $MonitorName
                description     = $MonitorDescription
                monitorTypeInfo = @{
                    baseType = $MonitorType
                    classId  = '92c56b83-d6a7-43a4-a094-8fe5f8fa4b2c'
                }
                propertyBags    = @(
                    @{
                        name  = 'Test Name'
                        value = 'Test Value'
                    }
                )

            }
        )

        $requestBody = $requestBody | ConvertTo-Json

        try {

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "Bearer $authToken")
            $headers.Add("Accept", "application/json")

            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $requestBody

            if ($response.data.update."success" -eq $true) {

                Write-Log -Message ('[INFO] Successfully added monitor {0}' -f $MonitorName) -Severty Info -Console
            }
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
