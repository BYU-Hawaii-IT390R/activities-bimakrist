# Builds answer.iso containing only Autounattend.xml

$iso = "answer.iso"
$xml = "Autounattend.xml"
$tempFolder = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

if (-Not (Test-Path $xml)) {
    Write-Error "Missing $xml"
    exit 1
}

# Path to oscdimg.exe (ensure ADK is installed)
$oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

if (-Not (Test-Path $oscdimg)) {
    Write-Error "oscdimg.exe not found at expected location: $oscdimg"
    Write-Host "You may need to install Windows ADK or update the path."
    exit 1
}

# Create temp folder
New-Item -ItemType Directory -Path $tempFolder | Out-Null

# Copy the XML into the temp folder
Copy-Item -Path $xml -Destination "$tempFolder\Autounattend.xml"

# Build the ISO
Write-Host "Creating ISO..."
& "$oscdimg" -u2 -udfver102 -lANS "$tempFolder" "$iso"

# Clean up
Remove-Item -Recurse -Force $tempFolder

Write-Host "✅ Created $iso"