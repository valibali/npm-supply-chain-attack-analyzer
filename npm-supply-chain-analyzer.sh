#!/bin/bash

#############################################################################
# NPM Repository Security Analysis Script
# 
# This script analyzes a repository for compromised NPM packages based on
# the September 2025 supply chain attacks including:
# - Initial chalk/debug compromise (Sept 8, 2025)
# - Shai-Hulud worm campaign (Sept 16, 2025) 
# - Extended package list analysis
#
# Author: Balazs Valkony
# Date: September 2025
#############################################################################

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_REPO_PATH="."
DEFAULT_BADLIST_FILE="badlist.txt"
BADLIST_URL=""
REPO_PATH=""
BADLIST_FILE=""

# Malicious file hashes (SHA-256)
MALICIOUS_HASHES=(
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6"
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3"
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e"
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c"
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
)

# Suspicious patterns to search for
SUSPICIOUS_PATTERNS=(
    "checkethereumw"
    "webhook.site"
    "Shai-Hulud"
    "bundle.js"
    "processor.sh"
    "migrate-repos.sh"
    "shai-hulud-workflow.yml"
)

# Parse command line arguments
parse_arguments() {
    # Set defaults
    REPO_PATH="$DEFAULT_REPO_PATH"
    BADLIST_FILE="$DEFAULT_BADLIST_FILE"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --target|-t)
                REPO_PATH="$2"
                shift 2
                ;;
            --badlist-file)
                BADLIST_FILE="$2"
                shift 2
                ;;
            --badlist-url)
                BADLIST_URL="$2"
                shift 2
                ;;
            --find-vscode)
                find_vscode_manual
                exit 0
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            -*)
                echo "Unknown option: $1"
                exit 1
                ;;
            *)
                # If no --target specified, treat first positional arg as target
                if [ "$REPO_PATH" = "$DEFAULT_REPO_PATH" ]; then
                    REPO_PATH="$1"
                fi
                shift
                ;;
        esac
    done
}

# Show help message
show_help() {
    echo "Usage: $0 [TARGET_DIR] [OPTIONS]"
    echo "       $0 --target TARGET_DIR [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  TARGET_DIR             Directory to analyze (default: current directory)"
    echo ""
    echo "Options:"
    echo "  --target, -t DIR       Target directory to analyze"
    echo "  --badlist-file FILE    Path to badlist file (default: badlist.txt)"
    echo "  --badlist-url URL      URL to download badlist from"
    echo "  --find-vscode          Find and display VSCode installation details"
    echo "  --help, -h             Show this help message"
    echo ""
    echo "Analysis behavior:"
    echo "  - Recursively searches for all node_modules directories"
    echo "  - Analyzes installed packages in node_modules"
    echo "  - If no node_modules found, analyzes package.json files"
    echo "  - Checks VSCode extensions for compromised packages"
    echo ""
    echo "Note: Either --badlist-file or --badlist-url must be provided, or"
    echo "      a 'badlist.txt' file must exist in the current directory."
    echo ""
    echo "Badlist file format:"
    echo "  package_name:version1,version2,version3"
    echo "  # Comments start with #"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/project"
    echo "  $0 --target /path/to/project --badlist-url https://example.com/badlist.txt"
    echo "  $0 . --badlist-file custom-badlist.txt"
}

# Manual VSCode finder for debugging
find_vscode_manual() {
    echo -e "${BLUE}=== VSCode Manual Detection Tool ===${NC}"
    echo -e "This tool helps you locate your VSCode installation and extensions."
    echo
    
    # Check if VSCode command is available
    echo -e "${BLUE}1. Checking VSCode command availability...${NC}"
    if command -v code >/dev/null 2>&1; then
        echo -e "${GREEN}✓ 'code' command found${NC}"
        echo "Version information:"
        code --version 2>/dev/null || echo "Could not get version"
        echo
        
        echo "Installed extensions:"
        code --list-extensions 2>/dev/null || echo "Could not list extensions"
        echo
    else
        echo -e "${YELLOW}✗ 'code' command not found in PATH${NC}"
    fi
    
    # Check for VSCode processes
    echo -e "${BLUE}2. Checking for running VSCode processes...${NC}"
    if command -v pgrep >/dev/null 2>&1; then
        local vscode_pids
        vscode_pids=$(pgrep -f "code\|Code" 2>/dev/null || true)
        if [ -n "$vscode_pids" ]; then
            echo -e "${GREEN}✓ Found VSCode processes:${NC}"
            pgrep -fl "code\|Code" 2>/dev/null || true
        else
            echo -e "${YELLOW}✗ No VSCode processes found${NC}"
        fi
    else
        echo "Using ps to check for VSCode processes:"
        ps aux 2>/dev/null | grep -i code | grep -v grep || echo -e "${YELLOW}No VSCode processes found${NC}"
    fi
    echo
    
    # Check specific extension paths
    echo -e "${BLUE}3. Checking specific extension paths...${NC}"
    local ext_paths=(
        "$HOME/.vscode/extensions"
        "$HOME/.vscode-server/extensions"
        "$HOME/.vscode-insiders/extensions"
        "$HOME/Library/Application Support/Code/User/extensions"
        "$HOME/.config/Code/User/extensions"
        "$HOME/AppData/Roaming/Code/User/extensions"
        "$HOME/.var/app/com.visualstudio.code/config/Code/User/extensions"
        "$HOME/snap/code/common/.config/Code/User/extensions"
    )
    
    for ext_path in "${ext_paths[@]}"; do
        if [ -d "$ext_path" ]; then
            local ext_count
            ext_count=$(find "$ext_path" -maxdepth 1 -type d -name "*.*" 2>/dev/null | wc -l)
            echo -e "${GREEN}✓ Found extensions: $ext_path ($ext_count extensions)${NC}"
            
            # List first 5 extensions as example
            echo "  Extensions"
            find "$ext_path" -maxdepth 1 -type d -name "*.*" 2>/dev/null | while read -r ext; do
                echo "    $(basename "$ext")"
            done || true
        else
            echo -e "${YELLOW}✗ Not found: $ext_path${NC}"
        fi
    done
    echo
    
    # System information
    echo -e "${BLUE}4. System information:${NC}"
    echo "OS: $(uname -s 2>/dev/null || echo "unknown")"
    echo "User: ${USER:-unknown}"
    echo "Home: ${HOME:-unknown}"
    echo "Current directory: $(pwd 2>/dev/null || echo "unknown")"
    echo "Shell: ${SHELL:-unknown}"
    
    echo
    echo -e "${GREEN}=== VSCode Detection Complete ===${NC}"
    echo -e "${BLUE}If VSCode extensions were found above, the main script should detect them.${NC}"
    echo -e "${BLUE}If not found, VSCode may not be installed or may be in a custom location.${NC}"
}

# Initialize variables after parsing arguments
initialize_variables() {
    OUTPUT_DIR="./security_analysis_$(date +%Y%m%d_%H%M%S)"
    TEMP_DIR="/tmp/npm_security_$$"
    LOG_FILE="$OUTPUT_DIR/analysis.log"
    
    # Global variable for compromised packages
    declare -g -A COMPROMISED_PACKAGES
}

# Initialize
init_analysis() {
    echo -e "${BLUE}=== NPM Security Analysis Tool ===${NC}"
    echo -e "Target directory: ${YELLOW}$REPO_PATH${NC}"
    echo -e "Started at: ${GREEN}$(date)${NC}"
    echo
    
    # Validate target directory
    if [ ! -d "$REPO_PATH" ]; then
        echo -e "${RED}ERROR: Target directory does not exist: $REPO_PATH${NC}"
        exit 1
    fi
    
    if [ ! -r "$REPO_PATH" ]; then
        echo -e "${RED}ERROR: Cannot read target directory: $REPO_PATH${NC}"
        exit 1
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$TEMP_DIR"
    
    # Initialize log
    echo "NPM Security Analysis Log - $(date)" > "$LOG_FILE"
    echo "Repository: $REPO_PATH" >> "$LOG_FILE"
    echo "============================================" >> "$LOG_FILE"
}

# Function to log messages
log_message() {
    local level="$1"
    local message="$2"
    echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# Check if required tools are available
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    local missing_tools=()
    
    # Check for required tools
    for tool in find grep awk sha256sum; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${YELLOW}Missing optional tools: ${missing_tools[*]}${NC}"
        echo "Some features may be limited, but analysis will continue."
        log_message "INFO" "Missing optional tools: ${missing_tools[*]}"
    else
        echo -e "${GREEN}All core dependencies available${NC}"
    fi
    
    echo -e "${GREEN}Dependencies check complete${NC}"
    log_message "INFO" "Dependency check completed"
}

# Download or load badlist
load_badlist() {
    echo -e "${BLUE}Loading compromised package list...${NC}"
    
    local badlist_source=""
    
    # Download from URL if specified
    if [ -n "$BADLIST_URL" ]; then
        echo -e "${YELLOW}Downloading badlist from: $BADLIST_URL${NC}"
        badlist_source="$TEMP_DIR/downloaded_badlist.txt"
        
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL "$BADLIST_URL" -o "$badlist_source" 2>/dev/null; then
                echo -e "${GREEN}✓ Successfully downloaded badlist${NC}"
                log_message "INFO" "Downloaded badlist from $BADLIST_URL"
            else
                echo -e "${RED}Failed to download badlist from URL${NC}"
                log_message "ERROR" "Failed to download badlist from $BADLIST_URL"
                exit 1
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -q "$BADLIST_URL" -O "$badlist_source" 2>/dev/null; then
                echo -e "${GREEN}✓ Successfully downloaded badlist${NC}"
                log_message "INFO" "Downloaded badlist from $BADLIST_URL"
            else
                echo -e "${RED}Failed to download badlist from URL${NC}"
                log_message "ERROR" "Failed to download badlist from $BADLIST_URL"
                exit 1
            fi
        else
            echo -e "${RED}Neither curl nor wget available for download${NC}"
            log_message "ERROR" "No download tool available (curl/wget)"
            exit 1
        fi
    elif [ -f "$BADLIST_FILE" ]; then
        echo -e "${YELLOW}Loading badlist from file: $BADLIST_FILE${NC}"
        badlist_source="$BADLIST_FILE"
        log_message "INFO" "Loading badlist from file $BADLIST_FILE"
    else
        echo -e "${RED}ERROR: No badlist source specified!${NC}"
        echo -e "${RED}Please provide either:${NC}"
        echo -e "${RED}  - A badlist file: --badlist-file badlist.txt${NC}"
        echo -e "${RED}  - A badlist URL: --badlist-url https://example.com/badlist.txt${NC}"
        echo -e "${RED}  - Or create a 'badlist.txt' file in the current directory${NC}"
        echo
        echo -e "${YELLOW}Badlist file format:${NC}"
        echo -e "${YELLOW}package_name:version1,version2,version3${NC}"
        echo -e "${YELLOW}Example:${NC}"
        echo -e "${YELLOW}chalk:5.6.1${NC}"
        echo -e "${YELLOW}@crowdstrike/commitlint:8.1.1,8.1.2${NC}"
        log_message "ERROR" "No badlist source specified"
        exit 1
    fi
    
    # Validate badlist file exists and is readable
    if [ ! -f "$badlist_source" ]; then
        echo -e "${RED}ERROR: Badlist file not found: $badlist_source${NC}"
        log_message "ERROR" "Badlist file not found: $badlist_source"
        exit 1
    fi
    
    if [ ! -r "$badlist_source" ]; then
        echo -e "${RED}ERROR: Cannot read badlist file: $badlist_source${NC}"
        log_message "ERROR" "Cannot read badlist file: $badlist_source"
        exit 1
    fi
    
    # Get file info safely
    local file_lines
    file_lines=$(wc -l < "$badlist_source" 2>/dev/null || echo "unknown")
    echo "📄 Reading badlist file: $badlist_source"
    echo "📊 File size: $file_lines lines"
    
    # Parse badlist file
    local packages_loaded=0
    local line_number=0
    
    echo "🔍 Parsing badlist entries..."
    
    # Use a more robust file reading approach
    while IFS= read -r line || [ -n "$line" ]; do
        ((line_number++))
        
        # Show progress every 50 lines
        if [ $((line_number % 50)) -eq 0 ]; then
            echo "  Processing line $line_number..."
        fi
        
        # Skip empty lines and comments
        if [[ -z "$line" ]] || [[ "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        # Parse format: package_name:version1,version2,version3
        if [[ "$line" =~ ^([^:]+):(.+)$ ]]; then
            local package_name="${BASH_REMATCH[1]}"
            local package_versions="${BASH_REMATCH[2]}"
            
            # Trim whitespace - use parameter expansion instead of sed for reliability
            package_name="${package_name#"${package_name%%[![:space:]]*}"}"   # remove leading whitespace
            package_name="${package_name%"${package_name##*[![:space:]]}"}"   # remove trailing whitespace
            package_versions="${package_versions#"${package_versions%%[![:space:]]*}"}"
            package_versions="${package_versions%"${package_versions##*[![:space:]]}"}"
            
            # Validate package name is not empty
            if [ -z "$package_name" ]; then
                echo -e "${YELLOW}Warning: Empty package name on line $line_number: $line${NC}"
                log_message "WARNING" "Empty package name on line $line_number: $line"
                continue
            fi
            
            # Validate versions are not empty
            if [ -z "$package_versions" ]; then
                echo -e "${YELLOW}Warning: Empty versions for package '$package_name' on line $line_number${NC}"
                log_message "WARNING" "Empty versions for package '$package_name' on line $line_number"
                continue
            fi
            
            COMPROMISED_PACKAGES["$package_name"]="$package_versions"
            ((packages_loaded++))
            
            # Show first few packages being loaded
            if [ $packages_loaded -le 5 ]; then
                echo "  ✓ Loaded: $package_name (versions: $package_versions)"
            fi
        else
            echo -e "${YELLOW}Warning: Invalid badlist format on line $line_number: $line${NC}"
            echo -e "${YELLOW}Expected format: package_name:version1,version2,version3${NC}"
            log_message "WARNING" "Invalid badlist format on line $line_number: $line"
        fi
    done < "$badlist_source"
    
    echo "📋 Parsing complete. Processed $line_number lines."
    
    if [ $packages_loaded -eq 0 ]; then
        echo -e "${RED}ERROR: No valid packages loaded from badlist!${NC}"
        echo -e "${RED}Please check the badlist file format.${NC}"
        log_message "ERROR" "No valid packages loaded from badlist"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Successfully loaded $packages_loaded compromised packages${NC}"
    log_message "INFO" "Loaded $packages_loaded compromised packages from badlist"
    
    # Save loaded badlist for reference
    {
        echo "Loaded Compromised Packages:"
        echo "============================"
        echo "Source: $badlist_source"
        echo "Loaded at: $(date)"
        echo "Total packages: $packages_loaded"
        echo
    } > "$OUTPUT_DIR/loaded_badlist.txt"
    
    # Create sorted output
    echo "📊 Creating sorted package list..."
    local sorted_temp="$OUTPUT_DIR/loaded_badlist_sorted.tmp"
    
    # Create sorted list more safely
    if [ ${#COMPROMISED_PACKAGES[@]} -gt 0 ]; then
        for package in "${!COMPROMISED_PACKAGES[@]}"; do
            echo "$package:${COMPROMISED_PACKAGES[$package]}"
        done | sort > "$sorted_temp" 2>/dev/null || {
            echo "Error creating sorted list, continuing anyway..."
            echo "# Error creating sorted list" > "$sorted_temp"
        }
        
        cat "$sorted_temp" >> "$OUTPUT_DIR/loaded_badlist.txt" 2>/dev/null || true
        mv "$sorted_temp" "$OUTPUT_DIR/loaded_badlist_sorted.txt" 2>/dev/null || true
    fi
    
    {
        echo
        echo "Sorted list saved to: loaded_badlist_sorted.txt"
    } >> "$OUTPUT_DIR/loaded_badlist.txt"
    
    echo -e "${GREEN}✓ Badlist loading complete${NC}"
    echo
}

# Find VSCode extension directories - returns only paths
find_vscode_extensions() {
    local vscode_dirs=()
    local vscode_analysis="$OUTPUT_DIR/vscode_extensions.txt"
    
    echo "VSCode Extension Analysis" > "$vscode_analysis"
    echo "========================" >> "$vscode_analysis"
    echo "Search performed at: $(date)" >> "$vscode_analysis"
    echo >> "$vscode_analysis"
    
    # Expanded VSCode extension paths for better detection
    local vscode_paths=(
        "$HOME/.vscode/extensions"
        "$HOME/.vscode-insiders/extensions"
        "$HOME/.vscode-server/extensions"
        "$HOME/Library/Application Support/Code/User/extensions"
        "$HOME/.config/Code/User/extensions"
        "$HOME/AppData/Roaming/Code/User/extensions"
        "$HOME/.var/app/com.visualstudio.code/config/Code/User/extensions"
        "$HOME/snap/code/common/.config/Code/User/extensions"
        "$REPO_PATH/.vscode/extensions"
    )
    
    echo "🔍 Checking VSCode extension paths..." >> "$vscode_analysis"
    echo "===================================" >> "$vscode_analysis"
    
    for vscode_path in "${vscode_paths[@]}"; do
        echo "Checking: $vscode_path" >> "$vscode_analysis"
        
        if [ -d "$vscode_path" ]; then
            echo "✓ FOUND: $vscode_path" >> "$vscode_analysis"
            vscode_dirs+=("$vscode_path")
            
            # Count extensions
            local ext_count
            ext_count=$(find "$vscode_path" -maxdepth 1 -type d -name "*.*" 2>/dev/null | wc -l)
            echo "  Extensions count: $ext_count" >> "$vscode_analysis"
            
            log_message "INFO" "Found VSCode extensions directory: $vscode_path with $ext_count extensions"
        else
            echo "✗ Not found: $vscode_path" >> "$vscode_analysis"
        fi
    done
    
    echo >> "$vscode_analysis"
    echo "Summary:" >> "$vscode_analysis"
    echo "Found ${#vscode_dirs[@]} VSCode extension directories" >> "$vscode_analysis"
    
    # Only return the paths, no display output
    printf '%s\n' "${vscode_dirs[@]}"
}

# Display VSCode extension search results
display_vscode_search() {
    echo -e "${BLUE}Finding VSCode extension directories...${NC}"
    
    local vscode_dirs
    mapfile -t vscode_dirs < <(find_vscode_extensions)
    
    # Display header
    echo -e "${YELLOW}💻 VSCode Extension Detection:${NC}"
    echo "============================="
    
    if [ ${#vscode_dirs[@]} -gt 0 ]; then
        for vscode_path in "${vscode_dirs[@]}"; do
            echo -e "${GREEN}✓ Found VSCode extensions: $vscode_path${NC}"
            
            # Count extensions
            local ext_count
            ext_count=$(find "$vscode_path" -maxdepth 1 -type d -name "*.*" 2>/dev/null | wc -l)
            echo "  📦 Extensions found: $ext_count"
        done
    fi
    
    echo "============================="
    echo -e "${GREEN}✅ Found ${#vscode_dirs[@]} VSCode extension directories${NC}"
    
    if [ ${#vscode_dirs[@]} -eq 0 ]; then
        echo -e "${YELLOW}ℹ️  No VSCode extensions found${NC}"
        echo -e "${BLUE}   Use --find-vscode for detailed detection${NC}"
    fi
    echo
}

# Analyze VSCode extensions for compromised packages
analyze_vscode_extensions() {
    echo -e "${BLUE}Analyzing VSCode extensions...${NC}"
    
    local vscode_dirs
    mapfile -t vscode_dirs < <(find_vscode_extensions)
    
    if [ ${#vscode_dirs[@]} -eq 0 ]; then
        echo -e "${YELLOW}ℹ️  No VSCode extension directories found to analyze${NC}"
        return
    fi
    
    local vscode_analysis="$OUTPUT_DIR/vscode_analysis.txt"
    local vscode_findings=0
    
    echo "VSCode Extension Security Analysis" > "$vscode_analysis"
    echo "=================================" >> "$vscode_analysis"
    echo "Analysis Date: $(date)" >> "$vscode_analysis"
    echo "Packages monitored: ${#COMPROMISED_PACKAGES[@]}" >> "$vscode_analysis"
    echo >> "$vscode_analysis"
    
    for vscode_dir in "${vscode_dirs[@]}"; do
        echo -e "${YELLOW}🔍 Analyzing VSCode extensions in: $vscode_dir${NC}"
        echo "VSCode Directory: $vscode_dir" >> "$vscode_analysis"
        
        if [ ! -d "$vscode_dir" ]; then
            echo "  ⚠️  Directory not accessible"
            echo "  Directory not accessible" >> "$vscode_analysis"
            continue
        fi
        
        # Find package.json files in VSCode extensions recursively
        local ext_package_files=()
        while IFS= read -r -d '' file; do
            ext_package_files+=("$file")
        done < <(find "$vscode_dir" -type f -name "package.json" -print0 2>/dev/null)
        
        echo "  📦 Found ${#ext_package_files[@]} package.json files in extensions"
        echo "  Package files found: ${#ext_package_files[@]}" >> "$vscode_analysis"
        
        # Analyze each package.json in VSCode extensions
        for package_file in "${ext_package_files[@]}"; do
            local ext_name
            ext_name=$(dirname "$package_file" | xargs basename)
            echo "    🔍 Checking extension: $ext_name"
            echo "    Extension: $ext_name ($package_file)" >> "$vscode_analysis"
            
            local ext_findings=0
            
            if [ -f "$package_file" ]; then
                for package in "${!COMPROMISED_PACKAGES[@]}"; do
                    if grep -q "\"$package\"" "$package_file" 2>/dev/null; then
                        echo -e "${RED}      ⚠️  Found compromised package: $package${NC}"
                        echo "        📁 Extension: $ext_name"
                        echo "        📄 File: $package_file"
                        echo "        🚨 Compromised versions: ${COMPROMISED_PACKAGES[$package]}"
                        
                        # Try to extract version from the file
                        local found_version
                        found_version=$(grep -A1 "\"$package\"" "$package_file" | grep -o '"[^"]*"' | tail -1 | tr -d '"' 2>/dev/null || echo "unknown")
                        echo "        📌 Found version: $found_version"
                        
                        echo "      COMPROMISED PACKAGE: $package" >> "$vscode_analysis"
                        echo "        Compromised versions: ${COMPROMISED_PACKAGES[$package]}" >> "$vscode_analysis"
                        echo "        Found version: $found_version" >> "$vscode_analysis"
                        
                        # Record the finding for the report
                        record_compromised_package "$package" "VSCode extension $ext_name ($package_file)" "$found_version"
                        
                        ((vscode_findings++))
                        ((ext_findings++))
                        log_message "CRITICAL" "Found compromised package $package in VSCode extension $ext_name ($package_file)"
                        echo
                    fi
                done
                
                # Also check node_modules within extensions recursively
                local ext_node_modules="$(dirname "$package_file")/node_modules"
                if [ -d "$ext_node_modules" ]; then
                    echo "      🔍 Checking node_modules in extension recursively..."
                    local nm_package_files=()
                    while IFS= read -r -d '' file; do
                        nm_package_files+=("$file")
                    done < <(find "$ext_node_modules" -type f -name "package.json" -print0 2>/dev/null)
                    
                    for nm_package_file in "${nm_package_files[@]}"; do
                        local nm_package_name
                        nm_package_name=$(dirname "$nm_package_file" | xargs basename)
                        
                        for package in "${!COMPROMISED_PACKAGES[@]}"; do
                            if [[ "$nm_package_name" == "$package" ]] || grep -q "\"name\"[[:space:]]*:[[:space:]]*\"$package\"" "$nm_package_file" 2>/dev/null; then
                                echo -e "${RED}        ⚠️  Found compromised dependency: $package${NC}"
                                echo "          📁 Extension: $ext_name"
                                echo "          📄 Dependency file: $nm_package_file"
                                echo "          🚨 Compromised versions: ${COMPROMISED_PACKAGES[$package]}"
                                
                                # Try to extract version
                                local dep_version
                                dep_version=$(grep "\"version\"" "$nm_package_file" | grep -o '"[^"]*"' | tail -1 | tr -d '"' 2>/dev/null || echo "unknown")
                                echo "          📌 Found version: $dep_version"
                                
                                echo "        COMPROMISED DEPENDENCY: $package" >> "$vscode_analysis"
                                echo "          Compromised versions: ${COMPROMISED_PACKAGES[$package]}" >> "$vscode_analysis"
                                echo "          Found version: $dep_version" >> "$vscode_analysis"
                                echo "          Dependency file: $nm_package_file" >> "$vscode_analysis"
                                
                                # Record the finding for the report
                                record_compromised_package "$package" "VSCode extension $ext_name dependency ($nm_package_file)" "$dep_version"
                                
                                ((vscode_findings++))
                                ((ext_findings++))
                                log_message "CRITICAL" "Found compromised dependency $package in VSCode extension $ext_name ($nm_package_file)"
                                echo
                            fi
                        done
                    done
                fi
            fi
            
            if [ $ext_findings -eq 0 ]; then
                echo "      ✅ No compromised packages found in this extension"
            fi
            
            echo >> "$vscode_analysis"
        done
        
        echo >> "$vscode_analysis"
    done
    
    echo "================================"
    echo "📊 VSCode Analysis Summary:"
    echo "  📁 VSCode directories scanned: ${#vscode_dirs[@]}"
    echo "  🚨 Compromised packages found: $vscode_findings"
    echo "================================"
    
    if [ $vscode_findings -gt 0 ]; then
        echo -e "${RED}⚠️  VSCODE SECURITY ALERT: $vscode_findings compromised packages detected!${NC}"
        echo -e "${RED}📋 Action required: Review and update VSCode extensions${NC}"
    else
        echo -e "${GREEN}✅ No compromised packages found in VSCode extensions${NC}"
    fi
    
    echo "✅ VSCode extension analysis complete"
    echo
}

# Analyze directories with package.json files for vulnerable packages
analyze_package_directories() {
    echo -e "${BLUE}Analyzing directories with package.json files...${NC}"
    
    local package_dirs=()
    local package_files=()
    local total_findings=0
    
    # Find all package.json files recursively
    echo -e "${YELLOW}📦 Finding package.json files recursively...${NC}"
    while IFS= read -r -d '' file; do
        package_files+=("$file")
        local dir_path
        dir_path=$(dirname "$file")
        # Only add unique directories
        if [[ ! " ${package_dirs[*]} " =~ " ${dir_path} " ]]; then
            package_dirs+=("$dir_path")
        fi
        echo "  Found: $file"
    done < <(find "$REPO_PATH" -type f -name "package.json" -print0 2>/dev/null)
    
    echo "✅ Found ${#package_files[@]} package.json files in ${#package_dirs[@]} directories"
    echo
    
    if [ ${#package_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}ℹ️  No package.json files found${NC}"
        return 0
    fi
    
    local analysis_file="$OUTPUT_DIR/package_analysis.txt"
    echo "Package Directory Security Analysis Results" > "$analysis_file"
    echo "===========================================" >> "$analysis_file"
    echo "Analysis Date: $(date)" >> "$analysis_file"
    echo "Target Directory: $REPO_PATH" >> "$analysis_file"
    echo "Package.json files found: ${#package_files[@]}" >> "$analysis_file"
    echo "Directories analyzed: ${#package_dirs[@]}" >> "$analysis_file"
    echo "Packages monitored: ${#COMPROMISED_PACKAGES[@]}" >> "$analysis_file"
    echo >> "$analysis_file"
    
    # Analyze each directory with package.json
    for package_dir in "${package_dirs[@]}"; do
        echo -e "${YELLOW}🔍 Analyzing directory: $package_dir${NC}"
        echo "Directory: $package_dir" >> "$analysis_file"
        
        local dir_findings=0
        local package_file="$package_dir/package.json"
        
        if [ ! -f "$package_file" ]; then
            echo "  ⚠️  package.json not found in directory"
            echo "  package.json not found" >> "$analysis_file"
            continue
        fi
        
        echo "  📄 Analyzing: $package_file"
        echo "  Package file: $package_file" >> "$analysis_file"
        
        # 1. Check dependencies in package.json
        echo "    🔍 Checking dependencies in package.json..."
        for package in "${!COMPROMISED_PACKAGES[@]}"; do
            if grep -q "\"$package\"" "$package_file" 2>/dev/null; then
                # Extract version from dependencies
                local declared_version
                declared_version=$(grep -A1 -B1 "\"$package\"" "$package_file" | grep -o '"[^"]*"' | tail -1 | tr -d '"' 2>/dev/null || echo "unknown")
                
                echo -e "${RED}      ⚠️  Found vulnerable dependency: $package${NC}"
                echo "        📁 Location: $package_file"
                echo "        📌 Declared version: $declared_version"
                echo "        🚨 Vulnerable versions: ${COMPROMISED_PACKAGES[$package]}"
                
                echo "      VULNERABLE DEPENDENCY: $package" >> "$analysis_file"
                echo "        Declared version: $declared_version" >> "$analysis_file"
                echo "        Vulnerable versions: ${COMPROMISED_PACKAGES[$package]}" >> "$analysis_file"
                
                # Record the finding
                record_compromised_package "$package" "$package_file (dependency)" "$declared_version"
                
                ((dir_findings++))
                ((total_findings++))
                log_message "CRITICAL" "Found vulnerable dependency $package v$declared_version in $package_file"
                echo
            fi
        done
        
        # 2. Check installed packages in node_modules (if exists)
        local node_modules_dir="$package_dir/node_modules"
        if [ -d "$node_modules_dir" ]; then
            echo "    🔍 Checking installed packages in node_modules..."
            echo "    Node modules directory: $node_modules_dir" >> "$analysis_file"
            
            # Find all installed packages
            local installed_packages=()
            while IFS= read -r -d '' installed_package_file; do
                installed_packages+=("$installed_package_file")
            done < <(find "$node_modules_dir" -type f -name "package.json" -print0 2>/dev/null)
            
            echo "      📦 Found ${#installed_packages[@]} installed packages"
            echo "      Installed packages found: ${#installed_packages[@]}" >> "$analysis_file"
            
            # Check each installed package
            for installed_package_file in "${installed_packages[@]}"; do
                local installed_package_dir
                installed_package_dir=$(dirname "$installed_package_file")
                local installed_package_name
                
                # Extract package name from package.json
                installed_package_name=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$installed_package_file" 2>/dev/null | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
                
                # Fallback to directory name if extraction failed
                if [ -z "$installed_package_name" ]; then
                    installed_package_name=$(basename "$installed_package_dir")
                fi
                
                # Check if this is a vulnerable package
                for vulnerable_package in "${!COMPROMISED_PACKAGES[@]}"; do
                    if [[ "$installed_package_name" == "$vulnerable_package" ]]; then
                        # Extract installed version
                        local installed_version
                        installed_version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$installed_package_file" 2>/dev/null | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "unknown")
                        
                        echo -e "${RED}        ⚠️  Found vulnerable installed package: $installed_package_name${NC}"
                        echo "          📁 Installation path: $installed_package_dir"
                        echo "          📌 Installed version: $installed_version"
                        echo "          🚨 Vulnerable versions: ${COMPROMISED_PACKAGES[$vulnerable_package]}"
                        echo "          📄 Package file: $installed_package_file"
                        
                        echo "        VULNERABLE INSTALLED PACKAGE: $installed_package_name" >> "$analysis_file"
                        echo "          Installation path: $installed_package_dir" >> "$analysis_file"
                        echo "          Installed version: $installed_version" >> "$analysis_file"
                        echo "          Vulnerable versions: ${COMPROMISED_PACKAGES[$vulnerable_package]}" >> "$analysis_file"
                        echo "          Package file: $installed_package_file" >> "$analysis_file"
                        
                        # Record the finding with detailed location info
                        record_compromised_package "$installed_package_name" "$installed_package_dir (installed: $installed_version)" "$installed_version"
                        
                        ((dir_findings++))
                        ((total_findings++))
                        log_message "CRITICAL" "Found vulnerable installed package $installed_package_name v$installed_version in $installed_package_dir"
                        echo
                        break
                    fi
                done
            done
        else
            echo "    ℹ️  No node_modules directory found"
            echo "    No node_modules directory" >> "$analysis_file"
        fi
        
        # 3. Check package-lock.json or yarn.lock for locked versions
        local lock_files=("$package_dir/package-lock.json" "$package_dir/yarn.lock")
        for lock_file in "${lock_files[@]}"; do
            if [ -f "$lock_file" ]; then
                echo "    🔍 Checking lock file: $(basename "$lock_file")"
                echo "    Lock file: $lock_file" >> "$analysis_file"
                
                for package in "${!COMPROMISED_PACKAGES[@]}"; do
                    if grep -q "\"$package\"" "$lock_file" 2>/dev/null; then
                        # Try to extract version from lock file
                        local locked_version
                        if [[ "$lock_file" == *"package-lock.json" ]]; then
                            locked_version=$(grep -A5 "\"$package\"" "$lock_file" | grep '"version"' | head -1 | grep -o '"[^"]*"' | tail -1 | tr -d '"' 2>/dev/null || echo "unknown")
                        else
                            locked_version=$(grep "$package@" "$lock_file" | head -1 | sed 's/.*@\([^:]*\):.*/\1/' 2>/dev/null || echo "unknown")
                        fi
                        
                        echo -e "${RED}        ⚠️  Found vulnerable package in lock file: $package${NC}"
                        echo "          📁 Lock file: $lock_file"
                        echo "          📌 Locked version: $locked_version"
                        echo "          🚨 Vulnerable versions: ${COMPROMISED_PACKAGES[$package]}"
                        
                        echo "        VULNERABLE PACKAGE IN LOCK FILE: $package" >> "$analysis_file"
                        echo "          Lock file: $lock_file" >> "$analysis_file"
                        echo "          Locked version: $locked_version" >> "$analysis_file"
                        echo "          Vulnerable versions: ${COMPROMISED_PACKAGES[$package]}" >> "$analysis_file"
                        
                        # Record the finding
                        record_compromised_package "$package" "$lock_file (locked: $locked_version)" "$locked_version"
                        
                        ((dir_findings++))
                        ((total_findings++))
                        log_message "CRITICAL" "Found vulnerable package $package v$locked_version in $lock_file"
                        echo
                    fi
                done
            fi
        done
        
        if [ $dir_findings -eq 0 ]; then
            echo "    ✅ No vulnerable packages found in this directory"
        else
            echo "    🚨 Found $dir_findings vulnerable packages in this directory"
        fi
        
        echo >> "$analysis_file"
    done
    
    echo "================================"
    echo "📊 Package Directory Analysis Summary:"
    echo "  📁 Directories analyzed: ${#package_dirs[@]}"
    echo "  📦 Package.json files scanned: ${#package_files[@]}"
    echo "  🚨 Vulnerable packages found: $total_findings"
    echo "================================"
    
    return $total_findings
}

# Main analysis function that analyzes package directories
analyze_basic() {
    echo -e "${BLUE}Running comprehensive security analysis...${NC}"
    echo -e "${BLUE}Target directory: ${YELLOW}$REPO_PATH${NC}"
    echo
    
    # Check if target directory exists
    if [ ! -d "$REPO_PATH" ]; then
        echo -e "${RED}ERROR: Target directory does not exist: $REPO_PATH${NC}"
        log_message "ERROR" "Target directory does not exist: $REPO_PATH"
        exit 1
    fi
    
    local total_findings=0
    
    # Analyze directories with package.json files
    analyze_package_directories
    local package_findings=$?
    ((total_findings += package_findings))
    
    echo
    echo "================================"
    echo "📊 Overall Analysis Summary:"
    echo "  🎯 Target directory: $REPO_PATH"
    echo "  🚨 Total vulnerable packages found: $total_findings"
    echo "================================"
    
    if [ $total_findings -gt 0 ]; then
        echo -e "${RED}⚠️  SECURITY ALERT: $total_findings vulnerable packages detected!${NC}"
        echo -e "${RED}📋 Action required: Review and remediate vulnerable packages${NC}"
    else
        echo -e "${GREEN}✅ No vulnerable packages found${NC}"
    fi
    
    echo "✅ Analysis complete"
    echo
}

# Global variables for runtime collection
declare -g -A FOUND_COMPROMISED_PACKAGES
declare -g -A FOUND_PACKAGE_LOCATIONS
declare -g TOTAL_FINDINGS=0

# Function to record a compromised package finding
record_compromised_package() {
    local package_name="$1"
    local location="$2"
    local found_version="$3"
    
    # Add to found packages if not already present
    if [[ ! " ${!FOUND_COMPROMISED_PACKAGES[*]} " =~ " ${package_name} " ]]; then
        FOUND_COMPROMISED_PACKAGES["$package_name"]="${COMPROMISED_PACKAGES[$package_name]}"
    fi
    
    # Add location to package
    if [ -z "${FOUND_PACKAGE_LOCATIONS[$package_name]}" ]; then
        FOUND_PACKAGE_LOCATIONS["$package_name"]="$location"
    else
        FOUND_PACKAGE_LOCATIONS["$package_name"]="${FOUND_PACKAGE_LOCATIONS[$package_name]}|$location"
    fi
    
    ((TOTAL_FINDINGS++))
}

# Generate comprehensive compromised packages report
generate_compromised_packages_report() {
    echo -e "${BLUE}Generating compromised packages report...${NC}"
    
    local report_file="$OUTPUT_DIR/compromised_packages_report.txt"
    local csv_report_file="$OUTPUT_DIR/compromised_packages_report.csv"
    
    # Get unique packages from runtime collection
    local unique_packages=()
    for package in "${!FOUND_COMPROMISED_PACKAGES[@]}"; do
        unique_packages+=("$package")
    done
    
    # Generate text report
    cat > "$report_file" << EOF
COMPROMISED PACKAGES SUMMARY REPORT
===================================

Analysis Date: $(date)
Repository: $REPO_PATH
Total Findings: $TOTAL_FINDINGS
Unique Compromised Packages: ${#unique_packages[@]}

EOF

    if [ ${#unique_packages[@]} -eq 0 ]; then
        cat >> "$report_file" << EOF
🎉 NO COMPROMISED PACKAGES FOUND!

All checked packages are secure.
Continue regular security monitoring.

EOF
    else
        cat >> "$report_file" << EOF
⚠️  CRITICAL SECURITY ALERT!
============================

The following compromised packages were identified:

DETAILED LIST:
=============

EOF

        # Sort packages alphabetically for better readability
        IFS=$'\n' sorted_packages=($(sort <<<"${unique_packages[*]}"))
        unset IFS
        
        local counter=1
        for package in "${sorted_packages[@]}"; do
            echo "${counter}. PACKAGE: $package" >> "$report_file"
            echo "   Compromised versions: ${FOUND_COMPROMISED_PACKAGES[$package]}" >> "$report_file"
            echo "   Found in locations:" >> "$report_file"
            
            # Split locations by pipe and display each
            IFS='|' read -ra locations <<< "${FOUND_PACKAGE_LOCATIONS[$package]}"
            for location in "${locations[@]}"; do
                echo "     - $location" >> "$report_file"
            done
            echo >> "$report_file"
            ((counter++))
        done
        
        cat >> "$report_file" << EOF

IMMEDIATE ACTIONS REQUIRED:
==========================

1. 🚨 STOP using the affected packages immediately
2. 🔍 Review all locations where compromised packages are found
3. 🗑️  Remove or replace compromised package versions
4. 🔄 Update to clean, verified versions
5. 🛡️  Run security scans after cleanup
6. 📞 Contact security team if available

RISK ASSESSMENT:
===============

- HIGH RISK: Compromised packages may contain malicious code
- POTENTIAL IMPACT: Data theft, system compromise, supply chain attack
- URGENCY: Immediate action required

EOF
    fi
    
    # Generate CSV report for easier processing
    echo "Package Name,Compromised Versions,Locations,Risk Level" > "$csv_report_file"
    
    if [ ${#unique_packages[@]} -gt 0 ]; then
        for package in "${sorted_packages[@]}"; do
            local locations_csv
            locations_csv=$(echo "${FOUND_PACKAGE_LOCATIONS[$package]}" | tr '|' ';')
            echo "\"$package\",\"${FOUND_COMPROMISED_PACKAGES[$package]}\",\"$locations_csv\",\"HIGH\"" >> "$csv_report_file"
        done
    fi
    
    echo -e "${GREEN}✅ Compromised packages report generated:${NC}"
    echo -e "   📄 Text report: $report_file"
    echo -e "   📊 CSV report: $csv_report_file"
    
    # Display summary to console
    if [ ${#unique_packages[@]} -gt 0 ]; then
        echo
        echo -e "${RED}🚨 COMPROMISED PACKAGES SUMMARY:${NC}"
        echo -e "${RED}================================${NC}"
        for package in "${sorted_packages[@]}"; do
            echo -e "${RED}• $package${NC} (${FOUND_COMPROMISED_PACKAGES[$package]})"
        done
        echo
    fi
}

# Generate simple summary
generate_simple_summary() {
    echo -e "${BLUE}Generating analysis summary...${NC}"
    
    local summary_file="$OUTPUT_DIR/summary_report.txt"
    
    cat > "$summary_file" << EOF
NPM Security Analysis Summary
============================
Repository: $REPO_PATH
Analysis Date: $(date)
Analysis Type: Basic Scan

Files Analyzed:
- Package files: $(find "$REPO_PATH" -name "package.json" 2>/dev/null | wc -l)
- Node modules directories: $(find "$REPO_PATH" -name "node_modules" -type d 2>/dev/null | wc -l)
- Packages monitored: ${#COMPROMISED_PACKAGES[@]}

Security Findings:
- Check analysis.log for detailed results
- Review any critical findings immediately

Output Directory: $OUTPUT_DIR

For detailed analysis, ensure all dependencies are available and re-run.
EOF

    echo -e "${GREEN}✅ Summary generated: $summary_file${NC}"
}

# Main execution
main() {
    # Parse command line arguments first
    parse_arguments "$@"
    
    # Initialize variables after parsing
    initialize_variables
    
    # Set up signal handlers for cleanup
    trap 'rm -rf "$TEMP_DIR" 2>/dev/null || true' EXIT
    
    # Start timer
    SECONDS=0
    
    # Run analysis steps
    init_analysis
    check_dependencies
    load_badlist
    display_vscode_search
    analyze_basic
    analyze_vscode_extensions
    generate_compromised_packages_report
    generate_simple_summary
    
    # Final summary with enhanced display
    echo
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Analysis Complete           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}📊 Analysis Summary:${NC}"
    echo -e "   ⏱️  Total time: ${YELLOW}$((SECONDS / 60)) minutes, $((SECONDS % 60)) seconds${NC}"
    echo -e "   📁 Results saved to: ${YELLOW}$OUTPUT_DIR${NC}"
    echo -e "   📦 Packages monitored: ${YELLOW}${#COMPROMISED_PACKAGES[@]}${NC}"
    echo
    echo -e "${BLUE}📋 Next Steps:${NC}"
    echo -e "   1️⃣  Review summary: ${YELLOW}$OUTPUT_DIR/summary_report.txt${NC}"
    echo -e "   2️⃣  Check analysis log: ${YELLOW}$OUTPUT_DIR/analysis.log${NC}"
    echo -e "   3️⃣  Install missing dependencies for full analysis if needed"
    echo
    
    # Enhanced critical issues check with detailed output
    local critical_issues=false
    local warning_issues=false
    
    if grep -q "CRITICAL" "$LOG_FILE" 2>/dev/null; then
        critical_issues=true
    fi
    
    if grep -q "WARNING" "$LOG_FILE" 2>/dev/null; then
        warning_issues=true
    fi
    
    # Display findings summary
    echo -e "${BLUE}🔍 Findings Summary:${NC}"
    
    if [ "$critical_issues" = true ]; then
        local critical_count
        critical_count=$(grep -c "CRITICAL" "$LOG_FILE" 2>/dev/null || echo "0")
        echo -e "   🚨 Critical issues: ${RED}$critical_count found${NC}"
    else
        echo -e "   ✅ Critical issues: ${GREEN}None found${NC}"
    fi
    
    if [ "$warning_issues" = true ]; then
        local warning_count
        warning_count=$(grep -c "WARNING" "$LOG_FILE" 2>/dev/null || echo "0")
        echo -e "   ⚠️  Warning issues: ${YELLOW}$warning_count found${NC}"
    else
        echo -e "   ✅ Warning issues: ${GREEN}None found${NC}"
    fi
    
    echo
    
    # Final status and exit
    if [ "$critical_issues" = true ]; then
        echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                    🚨 CRITICAL ALERT 🚨                       ║${NC}"
        echo -e "${RED}║                                                               ║${NC}"
        echo -e "${RED}║   CRITICAL SECURITY ISSUES DETECTED!                         ║${NC}"
        echo -e "${RED}║   Immediate action required - review analysis results        ║${NC}"
        echo -e "${RED}║                                                               ║${NC}"
        echo -e "${RED}║   Priority Actions:                                           ║${NC}"
        echo -e "${RED}║   • Review compromised packages immediately                   ║${NC}"
        echo -e "${RED}║   • Remove malicious package versions                        ║${NC}"
        echo -e "${RED}║   • Reinstall clean dependencies                             ║${NC}"
        echo -e "${RED}║   • Contact security team if available                       ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
        exit 1
    elif [ "$warning_issues" = true ]; then
        echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                    ⚠️  WARNINGS FOUND ⚠️                      ║${NC}"
        echo -e "${YELLOW}║                                                               ║${NC}"
        echo -e "${YELLOW}║   Warning-level issues detected                               ║${NC}"
        echo -e "${YELLOW}║   Review recommended - see analysis results                  ║${NC}"
        echo -e "${YELLOW}║                                                               ║${NC}"
        echo -e "${YELLOW}║   Recommended Actions:                                        ║${NC}"
        echo -e "${YELLOW}║   • Review warning findings                                   ║${NC}"
        echo -e "${YELLOW}║   • Update security practices                                 ║${NC}"
        echo -e "${YELLOW}║   • Monitor for changes                                      ║${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    ✅ ALL CLEAR ✅                             ║${NC}"
        echo -e "${GREEN}║                                                               ║${NC}"
        echo -e "${GREEN}║   No critical security issues detected                       ║${NC}"
        echo -e "${GREEN}║   Continue monitoring and follow security best practices     ║${NC}"
        echo -e "${GREEN}║                                                               ║${NC}"
        echo -e "${GREEN}║   Recommendations:                                            ║${NC}"
        echo -e "${GREEN}║   • Run regular security scans                               ║${NC}"
        echo -e "${GREEN}║   • Keep dependencies updated                                 ║${NC}"
        echo -e "${GREEN}║   • Monitor for new threats                                  ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
        exit 0
    fi
}

# Run the main function with all arguments
main "$@"
