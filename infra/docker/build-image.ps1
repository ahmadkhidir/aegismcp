# build-image.ps1 - Windows twin of infra/docker/build-image.
#
# Builds the gateway image, writes its SPDX SBOM, and fails when the scan reports a CRITICAL or
# HIGH vulnerability or any embedded secret anywhere in the image (NFR-028, NFR-023). Keep this
# file and build-image in step: both run the same pinned Trivy image and the same policy.
#
# Usage: pwsh infra/docker/build-image.ps1 [image-ref]
#   image-ref        tag to build, default aegismcp-gateway:local
# Environment:
#   AEGIS_IMAGE_REF  same as the argument
#   AEGIS_SBOM_PATH  SBOM destination, default infra/docker/build/aegismcp-gateway.spdx.json
#
# Exit status: 0 when the image builds and the gate passes, 1 otherwise.

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "../..")).Path

$imageRef = if ($args.Count -ge 1) { $args[0] } elseif ($env:AEGIS_IMAGE_REF) { $env:AEGIS_IMAGE_REF } else { "aegismcp-gateway:local" }
$sbomPath = if ($env:AEGIS_SBOM_PATH) { $env:AEGIS_SBOM_PATH } else { Join-Path $scriptDir "build/aegismcp-gateway.spdx.json" }

# Trivy 0.76.2, pinned by digest so the gate cannot change under a moving tag (NFR-028).
$trivyImage = "aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"

function Fail([string] $message) {
    Write-Error "build-image: $message" -ErrorAction Continue
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "docker is not on PATH"
}

$revision = (git -C $repoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $revision) { $revision = "unknown" }

$version = (git -C $repoRoot describe --tags --always 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $version) { $version = "unknown" }

$dirty = (git -C $repoRoot status --porcelain 2>$null)
if ($dirty) { $version = "$version-dirty" }

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("aegis-image-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workDir | Out-Null
$archive = Join-Path $workDir "image.tar"

try {
    Write-Host "build-image: building $imageRef (revision $revision, version $version)"
    docker build `
        -f (Join-Path $scriptDir "Dockerfile") `
        --build-arg "BUILD_REVISION=$revision" `
        --build-arg "BUILD_VERSION=$version" `
        -t $imageRef `
        $repoRoot
    if ($LASTEXITCODE -ne 0) { Fail "the image build failed" }

    Write-Host "build-image: saving the image for the scanner"
    docker save -o $archive $imageRef
    if ($LASTEXITCODE -ne 0) { Fail "docker save failed" }

    $sbomDir = Split-Path -Parent $sbomPath
    if (-not (Test-Path $sbomDir)) { New-Item -ItemType Directory -Path $sbomDir | Out-Null }

    Write-Host "build-image: writing the SBOM to $sbomPath"
    docker run --rm -v "${workDir}:/scan" $trivyImage image `
        --input /scan/image.tar `
        --cache-dir /scan/trivy-cache `
        --format spdx-json `
        --output /scan/sbom.spdx.json `
        --timeout 30m `
        --quiet
    if ($LASTEXITCODE -ne 0) { Fail "the SBOM could not be generated" }
    Copy-Item -Path (Join-Path $workDir "sbom.spdx.json") -Destination $sbomPath -Force

    Write-Host "build-image: scanning for CRITICAL/HIGH vulnerabilities"
    docker run --rm -v "${workDir}:/scan" $trivyImage image `
        --input /scan/image.tar `
        --cache-dir /scan/trivy-cache `
        --scanners vuln `
        --severity CRITICAL,HIGH `
        --exit-code 1 `
        --timeout 30m
    if ($LASTEXITCODE -ne 0) { Fail "the image violates the NFR-028 vulnerability policy" }

    Write-Host "build-image: scanning for embedded secrets in any layer"
    docker run --rm -v "${workDir}:/scan" $trivyImage image `
        --input /scan/image.tar `
        --cache-dir /scan/trivy-cache `
        --scanners secret `
        --exit-code 1 `
        --timeout 30m
    if ($LASTEXITCODE -ne 0) { Fail "the image bakes a credential into a layer (NFR-023)" }

    Write-Host "build-image: $imageRef passed the gate; SBOM at $sbomPath"
}
finally {
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
}
