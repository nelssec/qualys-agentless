# Release Process

## Prerequisites

1. **GitHub Repositories:**
   - `nelssec/qualys-agentless` - Main project repository
   - `nelssec/homebrew-tap` - Homebrew tap repository

2. **GitHub Secrets (in qualys-agentless repo):**
   - `HOMEBREW_TAP_TOKEN` - Personal access token with `repo` scope for homebrew-tap

## Creating a Release

1. **Update version** (if needed):
   ```bash
   # Update version in any hardcoded locations
   git add -A && git commit -m "Prepare release vX.Y.Z"
   ```

2. **Create and push tag:**
   ```bash
   git tag -a v0.1.0 -m "Release v0.1.0"
   git push origin v0.1.0
   ```

3. **Automated steps** (GitHub Actions):
   - Builds binaries for all platforms (linux/darwin, amd64/arm64, windows)
   - Compresses Linux binaries with UPX (~13MB)
   - Creates checksums.txt
   - Publishes GitHub Release
   - Updates Homebrew formula with new version and SHA256 hashes

## Manual Release (if needed)

```bash
# Build all platforms
make build-all

# Create checksums
cd build && sha256sum qualys-k8s-* > checksums.txt

# Upload to GitHub Release manually
```

## Setting Up Homebrew Tap

1. Create repository `nelssec/homebrew-tap` on GitHub

2. Initialize with the Formula:
   ```bash
   cd /path/to/homebrew-tap
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/nelssec/homebrew-tap.git
   git push -u origin main
   ```

3. Create Personal Access Token:
   - Go to GitHub → Settings → Developer settings → Personal access tokens
   - Create token with `repo` scope
   - Add as secret `HOMEBREW_TAP_TOKEN` in qualys-agentless repo

## Verifying Release

```bash
# Test install script
curl -fsSL https://raw.githubusercontent.com/nelssec/qualys-agentless/main/install.sh | sh

# Test Homebrew
brew tap nelssec/tap
brew install qualys-k8s
qualys-k8s --version
```
