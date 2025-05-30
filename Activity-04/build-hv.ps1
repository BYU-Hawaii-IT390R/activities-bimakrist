# build-hv.ps1 - Automate VM creation and Windows installation using Hyper-V

# Set strict mode for better error handling
Set-StrictMode -Version Latest

# Ensure execution policy allows running scripts
Write-Host "Ensure execution policy is set..." -ForegroundColor Yellow
$policy = Get-ExecutionPolicy -Scope CurrentUser
if ($policy -ne "RemoteSigned" -and $policy -ne "Unrestricted") {
    Write-Host "Setting execution policy to RemoteSigned..." -ForegroundColor Yellow
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
}

# Variables (edit these paths if needed)
$vmName     = "AutomatedWin10"
$vhdPath    = "C:\ISO Folder\AutomatedWin10.vhdx"
$windowsISO = "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerISO  = "C:\ISO Folder\answer.iso"
$vmMemory   = 4GB
$vSwitch    = Get-VMSwitch | Where-Object { $_.SwitchType -eq 'External' } | Select-Object -First 1 -ExpandProperty Name

if (-not $vSwitch) {
    Write-Error "No external virtual switch found. Please create one before proceeding."
    exit
}

# Check required files exist
Write-Host "Checking required files..." -ForegroundColor Yellow
foreach ($file in @($windowsISO, $answerISO)) {
    if (-not (Test-Path $file)) {
        Write-Error "Required file not found: $file"
        exit
    }
}

# Remove existing VM if it exists (optional cleanup)
if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing VM: $vmName..." -ForegroundColor Yellow
    Stop-VM -Name $vmName -Force -ErrorAction SilentlyContinue
    Remove-VM -Name $vmName -Force
}

# Create a new dynamic VHDX (40 GB)
Write-Host "Creating new VHDX at $vhdPath..." -ForegroundColor Green
New-VHD -Path $vhdPath -SizeBytes 40GB -Dynamic | Out-Null

# Create a Generation 2 VM with specified memory and attach the VHDX
Write-Host "Creating new VM: $vmName..." -ForegroundColor Green
New-VM -Name $vmName -Generation 2 -MemoryStartupBytes $vmMemory -VHDPath $vhdPath -SwitchName $vSwitch | Out-Null

# Disable Secure Boot to allow automated installation
Write-Host "Disabling Secure Boot..." -ForegroundColor Green
Set-VMFirmware -VMName $vmName -EnableSecureBoot Off

# Attach Windows installation ISO and the answer file ISO
Write-Host "Attaching DVD drives..." -ForegroundColor Green
Add-VMDvdDrive -VMName $vmName -Path $windowsISO
Add-VMDvdDrive -VMName $vmName -Path $answerISO

# Optionally set boot order: DVD first
$dvds = Get-VMDvdDrive -VMName $vmName
Set-VMFirmware -VMName $vmName -BootOrder $dvds[0], $dvds[1]

# Start the VM
Write-Host "Starting VM: $vmName..." -ForegroundColor Green
Start-VM -Name $vmName

Write-Host "VM setup complete. Automated install should begin shortly." -ForegroundColor Cyan