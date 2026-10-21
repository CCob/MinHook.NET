[CmdletBinding()]
param([ValidateSet('Release', 'Debug')][string] $Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($architecture in @('x86', 'x64')) {
    $platform = if ($architecture -eq 'x86') { 'Win32' } else { 'x64' }
    $build = Join-Path $root "artifacts/native/$architecture"
    & cmake -S (Join-Path $root 'native/MinHook.Threads') -B $build -A $platform
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed for $architecture" }
    & cmake --build $build --config $Configuration
    if ($LASTEXITCODE -ne 0) { throw "Native build failed for $architecture" }
}
