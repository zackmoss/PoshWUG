#Requires -Modules core

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

        Write-Host -Object ('[ERROR] {0}' -f $responseBody.error) -ForegroundColor 'Red'
    }

    [System.Net.ServicePointManager]::CertificatePolicy = $currentPolicy
}

function Get-DeviceIDByName {

    param (

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $GroupID = '0',

        [string] $DeviceName
    )

    begin {

        $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
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

            Write-Host -Object ('[ERROR] {0}' -f $responseBody.error) -ForegroundColor 'Red'
        }
    }
}

function Get-DeviceGroups {

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

            Write-Host -Object ('[ERROR] {0}' -f $responseBody.error) -ForegroundColor 'Red'
        }
    }
}

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

                Write-Host -Object ('[ERROR] {0}' -f $responseBody.error) -ForegroundColor 'Red'
            }
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

            Invoke-DebugIt -Message 'INFO' -Value ('Successfully added group {0}' -f $GroupName) -Console -Force
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
}

function Update-DeviceProperties {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $DeviceID,

        [string] $DisplayName,

        [string] $Notes
    )

    begin {

        $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
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

                Invoke-DebugIt -Message 'INFO' -Value ('Successfully updated device {0}' -f $DisplayName) -Console -Force
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
}

function Add-MonitoredDevice {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $GroupID = '0',

        [Parameter(Mandatory)]
        [string[]] $DeviceIPAddress,

        [bool] $ForceAdd = $True,

        [string] $DisplayName
    )

    begin {

        $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
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
    
                    Invoke-DebugIt -Message 'INFO' -Value ('Successfully added device {0}' -f $device) -Console -Force
    
                    $deviceId = Get-DeviceIDByName -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device
    
                    Invoke-DebugIt -Message 'INFO' -Value ('Waiting for device to be created to obtain device ID') -Console -Force
    
                    while ($deviceId.Length -le 0) {
    
                        $deviceId = Get-DeviceIDByName -WUGServer $WUGServer -Credential $Credential -GroupID $GroupID -DeviceName $device
                    }
    
                    Invoke-DebugIt -Message 'INFO' -Value ('New device ID {0}' -f $deviceId) -Console -Force
    
                    Update-DeviceProperties -WUGServer $WUGServer -Credential $Credential -DeviceID $deviceId -DisplayName $DisplayName
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
    }
}

function Enable-DeviceMaintMode {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential,

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

                Invoke-DebugIt -Message 'INFO' -Value ('Successfully disabled maintenance mode on {0}' -f $DeviceName) -Console -Force
            }
            else {

                Invoke-DebugIt -Message 'INFO' -Value ('Successfully enabled maintenance mode on {0}' -f $DeviceName) -Console -Force
            }
        }


    }
    catch {

        $result = $_.Exception.Response.GetResponseStream()

        $reader = New-Object System.IO.StreamReader($result)

        $reader.BaseStream.Position = 0

        $reader.DiscardBufferedData()

        $responseBody = $reader.ReadToEnd() | ConvertFrom-Json

        Invoke-DebugIt -Message 'ERROR' -Value $($responseBody.error) -Color 'Red' -Console -Force
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

                Invoke-DebugIt -Message 'INFO' -Value ('Successfully added monitor {0}' -f $MonitorName) -Console -Force
            }
        }
        catch {

            $result = $_.Exception.Response.GetResponseStream()

            $reader = New-Object System.IO.StreamReader($result)

            $reader.BaseStream.Position = 0

            $reader.DiscardBufferedData()

            $responseBody = $reader.ReadToEnd() | ConvertFrom-Json

            Invoke-DebugIt -Message 'ERROR' -Value $($responseBody.error) -Color 'Red' -Console -Force
        }
    }
}

function Get-Monitors {

    param(

        [Parameter(Mandatory)]
        [ipaddress] $WUGServer,

        [Parameter(Mandatory)]
        [pscredential] $Credential
    )

    begin {

        $authToken = Get-WUGToken -WUGServer $WUGServer -Credential $Credential -NoTLS
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

            Invoke-DebugIt -Message 'ERROR' -Value $($responseBody.error) -Color 'Red' -Console -Force
        }
    }
}