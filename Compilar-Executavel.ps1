[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDirectory = $PSScriptRoot
$sourcePath = Join-Path $scriptDirectory "src\DiscordWireGuardLauncher.cs"
$wireProxyDirectory = Join-Path $scriptDirectory "tools\wireproxy"
$wireProxyPath = Join-Path $wireProxyDirectory "wireproxy.exe"
$wireProxyArchivePath = Join-Path $wireProxyDirectory "wireproxy_windows_amd64.tar.gz"
$outputPath = Join-Path $scriptDirectory "Discord-WireGuard-Auto.exe"
$buildDirectory = Join-Path $scriptDirectory ".build"
$resourcePath = Join-Path $buildDirectory "DiscordWireGuardResources.resources"
$wireProxyVersion = "v1.1.3"
$wireProxyArchiveUrl = "https://github.com/windtf/wireproxy/releases/download/$wireProxyVersion/wireproxy_windows_amd64.tar.gz"
$expectedWireProxyArchiveHash = "bce041ea9fe0f8a3351301dcbe29cdf6a523bb25cf9c62f17ebb5699a8051d0f"
$expectedWireProxyHash = "b176b561fd8bf15d828fcab484cfd5b4fb941cb9f61807901ca64b955af27e1f"

function Assert-FileHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $ExpectedHash) {
        throw "$Description SHA256 verification failed."
    }
}

function Install-WireProxyDependency {
    [void](New-Item -ItemType Directory -Path $wireProxyDirectory -Force)

    if (Test-Path -LiteralPath $wireProxyPath -PathType Leaf) {
        Assert-FileHash -Path $wireProxyPath -ExpectedHash $expectedWireProxyHash -Description "wireproxy executable"
        Write-Output "[OK] Existing wireproxy dependency verified."
        return
    }

    if (Test-Path -LiteralPath $wireProxyArchivePath -PathType Leaf) {
        Assert-FileHash -Path $wireProxyArchivePath -ExpectedHash $expectedWireProxyArchiveHash -Description "wireproxy archive"
        Write-Output "[OK] Existing wireproxy archive verified."
    }
    else {
        $temporaryDownloadPath = "$wireProxyArchivePath.download"
        try {
            Write-Output "[INFO] Downloading wireproxy $wireProxyVersion from the official GitHub release..."
            Invoke-WebRequest -Uri $wireProxyArchiveUrl -OutFile $temporaryDownloadPath -UseBasicParsing
            Assert-FileHash -Path $temporaryDownloadPath -ExpectedHash $expectedWireProxyArchiveHash -Description "wireproxy download"
            Move-Item -LiteralPath $temporaryDownloadPath -Destination $wireProxyArchivePath
        }
        finally {
            if (Test-Path -LiteralPath $temporaryDownloadPath -PathType Leaf) {
                Remove-Item -LiteralPath $temporaryDownloadPath -Force
            }
        }
    }

    $tarCommand = Get-Command "tar.exe" -ErrorAction SilentlyContinue
    if ($null -eq $tarCommand) {
        throw "tar.exe was not found. Install the Windows tar component or extract $wireProxyArchivePath manually."
    }

    & $tarCommand.Source -xzf $wireProxyArchivePath -C $wireProxyDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "wireproxy extraction failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $wireProxyPath -PathType Leaf)) {
        throw "wireproxy.exe was not created after archive extraction."
    }

    Assert-FileHash -Path $wireProxyPath -ExpectedHash $expectedWireProxyHash -Description "wireproxy executable"
    Write-Output "[OK] wireproxy dependency installed and verified."
}

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Required source file not found: $sourcePath"
}

Install-WireProxyDependency

$cscCandidates = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
)
$cscPath = $cscCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($cscPath)) {
    throw "The .NET Framework C# compiler was not found."
}

[void](New-Item -ItemType Directory -Path $buildDirectory -Force)

$resourceWriter = $null
try {
    $wireProxyBytes = [System.IO.File]::ReadAllBytes($wireProxyPath)
    $resourceWriter = New-Object System.Resources.ResourceWriter($resourcePath)
    $resourceWriter.AddResource("wireproxy", $wireProxyBytes)
    $resourceWriter.Generate()
    $resourceWriter.Close()
    $resourceWriter = $null

    $compilerArguments = @(
        "/nologo",
        "/target:exe",
        "/platform:x64",
        "/optimize+",
        "/debug-",
        "/out:$outputPath",
        "/resource:$resourcePath,DiscordWireGuardResources.resources",
        "/reference:System.dll",
        "/reference:System.Core.dll",
        "/reference:System.Management.dll",
        "/reference:System.Security.dll",
        "/reference:System.ServiceProcess.dll",
        "/reference:System.Windows.Forms.dll",
        $sourcePath
    )

    & $cscPath @compilerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "C# compilation failed with exit code $LASTEXITCODE."
    }

    if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
        throw "The compiled executable was not created."
    }

    $outputItem = Get-Item -LiteralPath $outputPath
    $outputHash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output "[OK] Executable created: $outputPath"
    Write-Output "[INFO] Size: $($outputItem.Length) bytes"
    Write-Output "[INFO] SHA256: $outputHash"
}
finally {
    if ($null -ne $resourceWriter) {
        $resourceWriter.Dispose()
    }
    if (Test-Path -LiteralPath $resourcePath -PathType Leaf) {
        Remove-Item -LiteralPath $resourcePath -Force
    }
}
