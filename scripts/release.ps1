param(
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$manifestPath = Join-Path $root '.codex-plugin\plugin.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$version = [string]$manifest.version
if ($manifest.name -ne 'reverseplugin' -or $version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'Release manifest must contain reverseplugin and a stable semantic version.'
}

cmake --preset release -S $root
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed with exit code $LASTEXITCODE" }
cmake --build --preset release --clean-first
if ($LASTEXITCODE -ne 0) { throw "CMake build failed with exit code $LASTEXITCODE" }
ctest --preset release
if ($LASTEXITCODE -ne 0) { throw "CTest failed with exit code $LASTEXITCODE" }

$outputRoot = [System.IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
if (-not $outputRoot.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar,
                               [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must resolve inside the project root.'
}
$stage = Join-Path $outputRoot "reverseplugin-$version"
if (Test-Path -LiteralPath $stage) {
    $resolvedStage = [System.IO.Path]::GetFullPath($stage)
    if (-not $resolvedStage.StartsWith($outputRoot + [System.IO.Path]::DirectorySeparatorChar,
                                      [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to clean a release stage outside the output directory.'
    }
    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}

$binaryDirectory = Join-Path $stage 'build\release\Release'
New-Item -ItemType Directory -Path $binaryDirectory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'build\release\Release\reverseplugin-mcp.exe') -Destination $binaryDirectory
Copy-Item -LiteralPath (Join-Path $root '.codex-plugin') -Destination $stage -Recurse
Copy-Item -LiteralPath (Join-Path $root 'skills') -Destination $stage -Recurse
Copy-Item -LiteralPath (Join-Path $root '.mcp.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'THIRD_PARTY_NOTICES.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'CHANGELOG.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'SECURITY.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'docs') -Destination $stage -Recurse

$archive = Join-Path $outputRoot "reverseplugin-$version.zip"
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal -Force
$hash = Get-FileHash -LiteralPath $archive -Algorithm SHA256
Set-Content -LiteralPath ($archive + '.sha256') -Value ($hash.Hash.ToLowerInvariant() + '  ' + (Split-Path -Leaf $archive))
Write-Output $archive
Write-Output $hash.Hash.ToLowerInvariant()
