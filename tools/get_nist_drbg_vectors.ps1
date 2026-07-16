param(
    [string]$Destination = "test_vectors/nist_drbg"
)

$ErrorActionPreference = "Stop"

$VectorUrl = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip"
$Destination = [System.IO.Path]::GetFullPath($Destination)
$DownloadPath = Join-Path $Destination "drbgtestvectors.zip"
$OuterDirectory = Join-Path $Destination "outer"

New-Item -ItemType Directory -Force -Path $Destination | Out-Null

Write-Host "Downloading official NIST DRBG vectors..."
Invoke-WebRequest -Uri $VectorUrl -OutFile $DownloadPath

if (Test-Path $OuterDirectory) {
    Remove-Item -Recurse -Force $OuterDirectory
}

Expand-Archive -Path $DownloadPath -DestinationPath $OuterDirectory -Force

$NestedArchives = Get-ChildItem -Path $OuterDirectory -Recurse -File -Filter "*.zip"

if ($NestedArchives.Count -eq 0) {
    throw "The NIST archive did not contain the expected nested ZIP files."
}

foreach ($Archive in $NestedArchives) {
    $TargetDirectory = Join-Path $Destination $Archive.BaseName

    if (Test-Path $TargetDirectory) {
        Remove-Item -Recurse -Force $TargetDirectory
    }

    Write-Host "Extracting $($Archive.Name)..."
    Expand-Archive -Path $Archive.FullName -DestinationPath $TargetDirectory -Force
}

$ResponseFiles = Get-ChildItem -Path $Destination -Recurse -File -Filter "Hash_DRBG.rsp"

if ($ResponseFiles.Count -eq 0) {
    throw "No Hash_DRBG.rsp files were found after extraction."
}

Write-Host ""
Write-Host "Hash_DRBG response files:"
$ResponseFiles | ForEach-Object {
    Write-Host "  $($_.FullName)"
}
