#=============================================================================
# SCRIPT: Configure LDAPS in Active Directory
# Requirement: Run as administrator on each Domain Controller
#=============================================================================

#region === VARIABLES ===
$DomainController = $env:COMPUTERNAME
$Domain = (Get-ADDomain).DNSRoot
$DCfqdn = "$DomainController.$Domain"
#endregion

#region === 1. VERIFY CA ===
Write-Host "=== Verifying Certificate Authority ===" -ForegroundColor Cyan

# Search for CA in AD automatically (no popup)
$CAInfo = certutil -dump 2>$null | Select-String "Config:"
if ($CAInfo) {
    $CAConfig = ($CAInfo -split "Config:")[1].Trim().Trim('"')
    Write-Host "CA found: $CAConfig" -ForegroundColor Green
} else {
    # Search in AD
    $CA = Get-ADObject -Filter {objectClass -eq "pKIEnrollmentService"} -SearchBase "CN=Configuration,$((Get-ADDomain).DistinguishedName)" -Properties * 2>$null
    if ($CA) {
        Write-Host "CA found: $($CA.Name)" -ForegroundColor Green
    } else {
        Write-Host "ERROR: No CA found in domain." -ForegroundColor Red
        exit
    }
}
#endregion

#region === 2. VERIFY EXISTING CERTIFICATE ===
Write-Host "`n=== Verifying existing certificates on this DC ===" -ForegroundColor Cyan

$ExistingCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1" -and
    $_.Subject -match $DomainController -and
    $_.NotAfter -gt (Get-Date)
}

if ($ExistingCerts) {
    Write-Host "Valid certificate found:" -ForegroundColor Green
    $ExistingCerts | Format-Table Subject, Thumbprint, NotAfter -AutoSize
} else {
    Write-Host "No valid certificate found. A new one will be requested..." -ForegroundColor Yellow
}
#endregion

#region === 3. REQUEST CERTIFICATE IF NOT EXISTS ===
if (-not $ExistingCerts) {
    Write-Host "`n=== Requesting certificate ===" -ForegroundColor Cyan
    
    # Force silent autoenrollment
    Start-Process certutil -ArgumentList "-pulse" -NoNewWindow -Wait
    Start-Sleep -Seconds 3
    
    # Update policies
    Start-Process gpupdate -ArgumentList "/force" -NoNewWindow -Wait
    Start-Sleep -Seconds 3
    
    # Verify again
    $NewCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1" -and
        $_.Subject -match $DomainController -and
        $_.NotAfter -gt (Get-Date)
    }
    
    if ($NewCert) {
        Write-Host "Certificate obtained successfully" -ForegroundColor Green
        $NewCert | Format-Table Subject, Thumbprint, NotAfter -AutoSize
    } else {
        Write-Host "Autoenrollment did not work. Trying manual request..." -ForegroundColor Yellow
        
        # Try with different templates
        $Templates = @("DomainController", "KerberosAuthentication", "Machine")
        $Success = $false
        
        foreach ($Template in $Templates) {
            if ($Success) { break }
            
            try {
                Write-Host "Trying template: $Template" -ForegroundColor Gray
                
                $Request = @"
[NewRequest]
Subject = "CN=$DCfqdn"
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1
"@
                $InfFile = "$env:TEMP\certreq.inf"
                $ReqFile = "$env:TEMP\certreq.req"
                
                $Request | Out-File $InfFile -Encoding ASCII
                
                $Result = certreq -new $InfFile $ReqFile 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $SubmitResult = certreq -submit -attrib "CertificateTemplate:$Template" $ReqFile 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Certificate requested with template $Template" -ForegroundColor Green
                        $Success = $true
                    }
                }
                
                Remove-Item $InfFile -ErrorAction SilentlyContinue
                Remove-Item $ReqFile -ErrorAction SilentlyContinue
                
            } catch {
                Write-Host "Template $Template not available" -ForegroundColor Gray
            }
        }
        
        if (-not $Success) {
            Write-Host "`nCould not obtain certificate automatically." -ForegroundColor Red
            Write-Host "Run manually: certlm.msc -> Personal -> Request New Certificate" -ForegroundColor Yellow
        }
    }
}
#endregion

#region === 4. CONFIGURE REGISTRY FOR LDAP ===
Write-Host "`n=== Configuring registry for LDAP Signing ===" -ForegroundColor Cyan

try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapServerIntegrity" -Value 2 -Type DWord -Force
    Write-Host "LDAP Signing configured" -ForegroundColor Green
} catch {
    Write-Host "Could not configure registry: $_" -ForegroundColor Yellow
}
#endregion

#region === 5. TEST LDAPS ===
Write-Host "`n=== Testing LDAPS connection (port 636) ===" -ForegroundColor Cyan

Start-Sleep -Seconds 2

$LdapsTest = Test-NetConnection -ComputerName $DCfqdn -Port 636 -WarningAction SilentlyContinue
$LdapTest = Test-NetConnection -ComputerName $DCfqdn -Port 389 -WarningAction SilentlyContinue

Write-Host "LDAP  (389): $(if($LdapTest.TcpTestSucceeded){'OK'}else{'FAILED'})"
Write-Host "LDAPS (636): $(if($LdapsTest.TcpTestSucceeded){'OK'}else{'FAILED'})"

if ($LdapsTest.TcpTestSucceeded) {
    Write-Host "`nLDAPS working correctly!" -ForegroundColor Green
    
    # Verify certificate
    try {
        $TcpClient = New-Object System.Net.Sockets.TcpClient($DCfqdn, 636)
        $SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream(), $false, {$true})
        $SslStream.AuthenticateAsClient($DCfqdn)
        $Cert = $SslStream.RemoteCertificate
        
        Write-Host "`nSSL Certificate in use:" -ForegroundColor Cyan
        Write-Host "  Subject: $($Cert.Subject)"
        Write-Host "  Valid until: $($Cert.GetExpirationDateString())"
        
        $SslStream.Close()
        $TcpClient.Close()
    } catch {
        Write-Host "Could not read certificate details" -ForegroundColor Gray
    }
} else {
    Write-Host "`nLDAPS not responding. Options:" -ForegroundColor Yellow
    Write-Host "  1. Restart DC: Restart-Computer -Force" -ForegroundColor Gray
    Write-Host "  2. Verify certificate is installed: certlm.msc" -ForegroundColor Gray
}
#endregion

#region === SUMMARY ===
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Server: $DCfqdn"

$FinalCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1" -and
    $_.NotAfter -gt (Get-Date)
} | Select-Object -First 1

Write-Host "Certificate: $(if($FinalCert){'YES - ' + $FinalCert.Thumbprint.Substring(0,8) + '...'}else{'NO'})"
Write-Host "LDAPS (636): $(if($LdapsTest.TcpTestSucceeded){'ACTIVE'}else{'INACTIVE - restart DC'})"
Write-Host "========================================`n" -ForegroundColor Cyan
#endregion
