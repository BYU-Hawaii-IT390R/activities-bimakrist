# build-vbox.ps1 - Automate VM creation and Windows installation using VirtualBox

# Set strict mode for better error handling
Set-StrictMode -Version Latest

# Define paths and settings
$vmName = "AutomatedWin10"
$vboxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# Paths - edit these as needed
$isoFolder = "C:\ISO Folder"
$vdiPath = "$isoFolder\AutomatedWin10.vdi"
$windowsISO = "$isoFolder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerISO = "$isoFolder\answer.iso"

# VM Settings
$memSizeMB = 4096     # Memory size in MB
$cpuCount = 2         # Number of CPUs
$diskSizeMB = 40000   # Disk size in MB (40 GB)
$ostype = "Windows10_64"

# Check if VBoxManage exists
if (-not (Test-Path $vboxManage)) {
    Write-Error "VBoxManage not found at: $vboxManage"
    Write-Host "Make sure VirtualBox is installed." -ForegroundColor Red
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
Write-Host "Checking for existing VM..." -ForegroundColor Yellow
$existingVM = & "$vboxManage" list vms | Select-String -SimpleMatch "$vmName"
if ($existingVM) {
    Write-Host "Removing existing VM: $vmName..." -ForegroundColor Yellow
    & "$vboxManage" controlvm "$vmName" poweroff | Out-Null
    & "$vboxManage" unregistervm "$vmName" --delete
}

# Create the VM
Write-Host "Creating new VM: $vmName..." -ForegroundColor Green
& "$vboxManage" createvm --name "$vmName" --register
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to create VM."; exit }

# Configure VM settings
Write-Host "Setting VM memory and CPU..." -ForegroundColor Green
& "$vboxManage" modifyvm "$vmName" --memory $memSizeMB --cpus $cpuCount --ostype "$ostype"
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to configure VM memory or CPU."; exit }

# Create virtual hard disk
Write-Host "Creating virtual hard disk..." -ForegroundColor Green
& "$vboxManage" createmedium disk --filename "$vdiPath" --size $diskSizeMB
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to create VDI."; exit }

# Attach SATA controller and HDD
Write-Host "Adding SATA controller and attaching HDD..." -ForegroundColor Green
& "$vboxManage" storagectl "$vmName" --name "SATA Controller" --add sata --controller IntelAhci
& "$vboxManage" storageattach "$vmName" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$vdiPath"
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to attach HDD."; exit }

# Add IDE controller and attach DVD drives
Write-Host "Adding IDE controller and attaching DVDs..." -ForegroundColor Green
& "$vboxManage" storagectl "$vmName" --name "IDE Controller" --add ide

# Attach Windows ISO
& "$vboxManage" storageattach "$vmName" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "$windowsISO"
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to attach Windows ISO."; exit }

# Attach Answer ISO
& "$vboxManage" storageattach "$vmName" --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium "$answerISO"
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to attach Answer ISO."; exit }

# Boot from DVD first
Write-Host "Setting boot order..." -ForegroundColor Green
& "$vboxManage" modifyvm "$vmName" --boot1 dvd --boot2 disk --boot3 none --boot4 none

# Start the VM
Write-Host "Starting VM: $vmName..." -ForegroundColor Green
& "$vboxManage" startvm "$vmName"
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to start VM."; exit }

Write-Host "✅ VM setup complete. Automated install should begin shortly." -ForegroundColor Cyan