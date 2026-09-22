# Run in PowerShell as Administrator. English-locale subcategory names.
$ErrorActionPreference = "Stop"

auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable

# Include command lines in 4688 (NOTE: secrets typed on command lines will be logged - keep logs local)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# DNS client log (for shadow-AI panel)
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true

# Larger Security log so events survive until Alloy reads them (200 MB)
wevtutil sl Security /ms:209715200

Write-Host "Done. Verify with: auditpol /get /category:*" -ForegroundColor Green
