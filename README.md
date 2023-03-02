# PoshWUG
PowerShell Module for Progress What's Up Gold 2022

All updates to this repo will be uploaded to the PowerShell Gallery

[PowerShell Gallery Link](https://www.powershellgallery.com/packages/PoshWUG)

## Install Using PowerShell Gallery
`Install-Module -Name PoshWUG`

# Getting Started
The `Get-WUGToken` function will be ran with each function inside the module which will generate and renew the token automatically.

**One thing to note is if you are running this against a self signed cert you can pass the `-NoTLS` switch to the function being ran or install the certificate to your local machine. This also applies if WhatsUp Gold was installed with no certificate.**