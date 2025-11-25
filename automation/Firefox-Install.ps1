# Path to the Firefox installer
$InstallerPath = "C:\Users\labuser\Downloads\Firefox Setup 110.0b5.exe"

# Verify installer exists
if (Test-Path -Path $InstallerPath) {

    try {
        # Run the installer silently
        Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait -NoNewWindow
        Write-Host "Firefox installed successfully."
    }
    catch {
        Write-Host "An error occurred while running the Firefox installer: $($_.Exception.Message)"
    }

} else {
    Write-Host "Firefox installer not found at: $InstallerPath"
}
