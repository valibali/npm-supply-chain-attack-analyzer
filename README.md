# NPM Security Analysis Tool

A comprehensive security analysis tool for detecting compromised NPM packages in your projects, including support for VSCode extensions analysis.

## 🚨 Background

This tool was developed in response to the September 2025 NPM supply chain attacks, including:
- **September 8, 2025**: Initial chalk/debug compromise
- **September 16, 2025**: Shai-Hulud worm campaign
- **Extended package list**: Analysis of 200+ compromised packages

## 🎯 Features

- **Recursive Analysis**: Scans all `node_modules` directories recursively
- **Package.json Fallback**: Analyzes `package.json` files when `node_modules` not available
- **VSCode Extensions**: Checks VSCode extensions for compromised packages
- **Comprehensive Reporting**: Generates detailed text and CSV reports
- **Real-time Collection**: Collects compromised packages during runtime
- **Flexible Input**: Supports badlist files or URLs
- **Cross-platform**: Works on Linux, macOS, and Windows (with bash)

## 📋 Requirements

- **Bash shell** (version 4.0+)
- **Standard Unix tools**: `find`, `grep`, `awk`
- **Optional**: `curl` or `wget` for downloading badlists from URLs
- **Optional**: `sha256sum` for file integrity checks

## 🚀 Installation

1. Clone or download the script:
```bash
wget https://raw.githubusercontent.com/your-repo/npm-attack-analysis.sh
chmod +x npm-attack-analysis.sh
```

2. Ensure you have a badlist file or URL (see [Badlist Format](#badlist-format))

## 📖 Usage

### Basic Usage

```bash
# Analyze current directory
./npm-attack-analysis.sh

# Analyze specific directory
./npm-attack-analysis.sh /path/to/project

# Using --target flag
./npm-attack-analysis.sh --target /path/to/project
```

### Advanced Usage

```bash
# Use custom badlist file
./npm-attack-analysis.sh --target /path/to/project --badlist-file custom-badlist.txt

# Download badlist from URL
./npm-attack-analysis.sh --target /path/to/project --badlist-url https://raw.githubusercontent.com/valibali/npm-supply-chain-attack-analyzer/refs/heads/master/npm-supply-chain-analyzer.sh

# Find VSCode installations (debugging)
./npm-attack-analysis.sh --find-vscode

# Show help
./npm-attack-analysis.sh --help
```

## 📝 Command Line Options

| Option | Description |
|--------|-------------|
| `TARGET_DIR` | Directory to analyze (default: current directory) |
| `--target, -t DIR` | Target directory to analyze |
| `--badlist-file FILE` | Path to badlist file (default: badlist.txt) |
| `--badlist-url URL` | URL to download badlist from |
| `--find-vscode` | Find and display VSCode installation details |
| `--help, -h` | Show help message |

## 📄 Badlist Format

The badlist file uses a simple format:

```
# Comments start with #
package_name:version1,version2,version3

# Examples:
chalk:5.6.1
@crowdstrike/commitlint:8.1.1,8.1.2
rxnt-authentication:0.0.3,0.0.4,0.0.5,0.0.6
```

### Rules:
- One package per line
- Format: `package_name:comma_separated_versions`
- Comments start with `#`
- Empty lines are ignored
- Whitespace is automatically trimmed

## 📊 Output Files

The tool generates several output files in a timestamped directory:

### Main Reports
- `compromised_packages_report.txt` - Detailed human-readable report
- `compromised_packages_report.csv` - CSV format for spreadsheet analysis
- `summary_report.txt` - Quick overview of the analysis

### Analysis Details
- `analysis.log` - Detailed log of all operations
- `node_modules_analysis.txt` - Node modules specific findings
- `package_json_analysis.txt` - Package.json specific findings
- `vscode_analysis.txt` - VSCode extensions analysis
- `vscode_extensions.txt` - VSCode extension discovery log

### Reference Files
- `loaded_badlist.txt` - List of loaded compromised packages
- `loaded_badlist_sorted.txt` - Sorted version of the badlist

## 🔍 Analysis Behavior

### 1. Node Modules Analysis (Primary)
- Recursively finds all `node_modules` directories
- Analyzes installed packages by reading their `package.json` files
- Compares package names and versions against the badlist
- Reports exact installed versions

### 2. Package.json Analysis (Fallback)
- Activated when no `node_modules` found or no compromised packages detected
- Scans all `package.json` files for dependency references
- Checks both `dependencies` and `devDependencies` sections
- Reports referenced versions from package files

### 3. VSCode Extensions Analysis
- Searches common VSCode extension directories
- Analyzes extension `package.json` files
- Checks extension `node_modules` for compromised dependencies
- Supports multiple VSCode installations (regular, Insiders, server)

## 🎨 Output Examples

### Console Output
```
🚨 COMPROMISED PACKAGES SUMMARY:
================================
• chalk (5.6.1)
• @crowdstrike/commitlint (8.1.1,8.1.2)
```

### Report File Example
```
COMPROMISED PACKAGES SUMMARY REPORT
===================================

Analysis Date: Mon Sep 22 13:45:30 UTC 2025
Repository: /path/to/project
Total Findings: 2
Unique Compromised Packages: 2

⚠️  CRITICAL SECURITY ALERT!
============================

1. PACKAGE: chalk
   Compromised versions: 5.6.1
   Found in locations:
     - /path/to/project/node_modules/chalk (installed)

2. PACKAGE: @crowdstrike/commitlint
   Compromised versions: 8.1.1,8.1.2
   Found in locations:
     - /path/to/project/package.json (reference)
```

## 🛡️ Security Recommendations

When compromised packages are found:

1. **🚨 IMMEDIATE**: Stop using affected packages
2. **🔍 INVESTIGATE**: Review all locations where packages are found
3. **🗑️ REMOVE**: Delete compromised package versions
4. **🔄 UPDATE**: Install clean, verified versions
5. **🛡️ SCAN**: Run security scans after cleanup
6. **📞 ESCALATE**: Contact security team if available

## 🔧 Troubleshooting

### Common Issues

**"No badlist source specified"**
- Ensure `badlist.txt` exists in current directory, or
- Use `--badlist-file` or `--badlist-url` options

**"Target directory does not exist"**
- Check the path is correct
- Ensure you have read permissions

**"No VSCode extensions found"**
- Run `./npm-attack-analysis.sh --find-vscode` for debugging
- VSCode may not be installed or in a custom location

### Debug Mode
Use the `--find-vscode` option to debug VSCode detection:
```bash
./npm-attack-analysis.sh --find-vscode
```

## 📈 Exit Codes

- `0`: Success, no critical issues found
- `1`: Critical security issues detected (compromised packages found)

## 🤝 Contributing

To add new compromised packages to the badlist:

1. Follow the badlist format
2. Include package name and all compromised versions
3. Add comments with source/date information
4. Test with the analysis tool

## 📜 License

This tool is provided as-is for security analysis purposes. Use responsibly and in accordance with your organization's security policies.

## 🔗 Related Resources

- [NPM Security Best Practices](https://docs.npmjs.com/security)
- [Supply Chain Security Guide](https://slsa.dev/)
- [Node.js Security Working Group](https://github.com/nodejs/security-wg)

## 📞 Support

For issues or questions:
1. Check the troubleshooting section
2. Run with `--find-vscode` for VSCode issues
3. Review the generated log files
4. Ensure badlist format is correct

---

**⚠️ Important**: This tool is designed to detect known compromised packages. It should be part of a comprehensive security strategy, not the only security measure.
