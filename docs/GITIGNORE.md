# .gitignore Documentation

This project's `.gitignore` file is carefully designed to ensure only necessary source code files are committed, avoiding build artifacts, temporary files, and sensitive information.

## File Structure

```
.gitignore          # Main gitignore in project root
docs/.gitignore     # Documentation-specific gitignore
```

## Ignore Rules Categories

### 1. Go Language Related

#### Build Artifacts
- `*.exe`, `*.dll`, `*.so`, `*.dylib` - Compiled binary files
- `bin/` - Binary files directory
- `*.test` - Test binary files
- `*.out` - Coverage output files

#### Go Module Files
- `go.sum` - Go module checksum file (auto-generated)
- `vendor/` - Vendored dependencies (when using vendor mode)

#### Go Development Tools
- `*.prof` - Profiling output files
- `*.pprof` - Performance profiling files
- `cpu.out`, `mem.out` - Profiling data files

### 2. IDE and Editor Files

#### Visual Studio Code
- `.vscode/` - VS Code workspace settings
- `*.code-workspace` - VS Code workspace files

#### GoLand / IntelliJ IDEA
- `.idea/` - IDE configuration directory
- `*.iml` - IntelliJ module files

#### Vim
- `*.swp`, `*.swo` - Vim swap files
- `*~` - Vim backup files

#### Emacs
- `*~` - Emacs backup files
- `\#*\#` - Emacs auto-save files

### 3. Operating System Files

#### macOS
- `.DS_Store` - macOS directory metadata
- `._*` - macOS resource fork files
- `.Spotlight-V100` - Spotlight index files
- `.Trashes` - Trash metadata

#### Windows
- `Thumbs.db` - Windows thumbnail cache
- `ehthumbs.db` - Windows thumbnail database
- `Desktop.ini` - Windows folder configuration

#### Linux
- `*~` - Backup files
- `.fuse_hidden*` - FUSE hidden files
- `.directory` - KDE directory metadata
- `.Trash-*` - Linux trash files

### 4. Development Tools

#### Git
- `*.orig` - Git merge conflict backup files
- `*.rej` - Git patch reject files

#### Docker
- `.dockerignore` - Docker ignore file (if not needed in repo)

#### Testing and Coverage
- `coverage.out` - Go coverage output
- `coverage.html` - HTML coverage reports
- `*.coverprofile` - Coverage profile files
- `test-results/` - Test result directories

### 5. Documentation Build

#### VitePress (Documentation)
- `docs/node_modules/` - Node.js dependencies
- `docs/.vitepress/dist/` - Built documentation
- `docs/.vitepress/cache/` - VitePress cache
- `docs/package-lock.json` - NPM lock file (if using yarn)

#### Other Documentation Tools
- `docs/_site/` - Jekyll build output
- `docs/.sass-cache/` - Sass cache
- `docs/.jekyll-metadata` - Jekyll metadata

### 6. Temporary and Cache Files

#### General Temporary Files
- `tmp/` - Temporary files directory
- `temp/` - Alternative temporary directory
- `*.tmp` - Temporary files
- `*.cache` - Cache files

#### Log Files
- `*.log` - Log files
- `logs/` - Log directory

#### Backup Files
- `*.bak` - Backup files
- `*.backup` - Alternative backup extension

### 7. Security and Sensitive Data

#### Environment Files
- `.env` - Environment variables
- `.env.local` - Local environment overrides
- `.env.*.local` - Environment-specific local files

#### Certificates and Keys
- `*.pem` - PEM certificate files
- `*.key` - Private key files
- `*.crt` - Certificate files
- `*.p12` - PKCS#12 files

#### Configuration Files
- `config.local.*` - Local configuration overrides
- `secrets.yaml` - Secret configuration files

### 8. Project-Specific

#### CVSS Skills Specific
- `examples/output/` - Example program outputs
- `benchmark-results/` - Benchmark result files
- `test-vectors/` - Test vector files (if large)

#### Build and Release
- `dist/` - Distribution files
- `release/` - Release artifacts
- `*.tar.gz` - Compressed archives
- `*.zip` - Zip archives

## Best Practices

### 1. Global vs Local Gitignore

**Global gitignore** (recommended for personal files):
```bash
# Set up global gitignore for personal preferences
git config --global core.excludesfile ~/.gitignore_global
```

Add to `~/.gitignore_global`:
```
# Personal IDE preferences
.vscode/
.idea/

# Personal OS files
.DS_Store
Thumbs.db
```

**Local gitignore** (for project-specific files):
- Keep in project repository
- Include build artifacts
- Include project-specific temporary files

### 2. Gitignore Patterns

#### Wildcards
```bash
*.log           # All .log files
logs/*.log      # .log files in logs directory
**/*.tmp        # .tmp files in any subdirectory
```

#### Negation
```bash
*.log           # Ignore all .log files
!important.log  # But keep important.log
```

#### Directory vs File
```bash
build/          # Ignore build directory
build           # Ignore build file or directory
```

### 3. Testing Gitignore Rules

```bash
# Check if a file would be ignored
git check-ignore -v path/to/file

# List all ignored files
git ls-files --others --ignored --exclude-standard

# Show what would be added (dry run)
git add --dry-run .
```

## Related Files

- **`.gitignore`** - Main ignore rules
- **`docs/.gitignore`** - Documentation-specific rules
- **`.gitattributes`** - Git attributes for line endings, etc.
- **`README.md`** - Project documentation
- **`CONTRIBUTING.md`** - Contribution guidelines