#!/usr/bin/env bash
# ==============================================================================
# kshield - Git Initialization and GitHub Release Script
# Author: Luis Lázaro Pimentel
# Repository: https://github.com/Thepimen/kshield.git
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

REPO_URL="https://github.com/Thepimen/kshield.git"
COMMIT_MSG="feat: initial release of kshield - eBPF-powered Linux kernel intrusion detection agent"

echo -e "${BOLD}${BLUE}====================================================${NC}"
echo -e "${BOLD}${BLUE}   kshield - GitHub Release & Initialization        ${NC}"
echo -e "${BOLD}${BLUE}====================================================${NC}"

# 1. Initialize Git Repository
if [ ! -d ".git" ]; then
    echo -e "${BLUE}[*] Initializing git repository...${NC}"
    git init
else
    echo -e "${GREEN}[✓] Existing git repository detected.${NC}"
fi

# 2. Configure Default Branch to main
echo -e "${BLUE}[*] Setting default branch to main...${NC}"
git branch -M main

# 3. Configure Remote Origin
echo -e "${BLUE}[*] Configuring remote origin: ${REPO_URL}...${NC}"
git remote add origin "${REPO_URL}" 2>/dev/null || git remote set-url origin "${REPO_URL}"

# 4. Stage All Validated Files
echo -e "${BLUE}[*] Staging files (respecting .gitignore)...${NC}"
git add .

# 5. Semantic Commit
echo -e "${BLUE}[*] Creating initial release commit...${NC}"
if git diff --cached --quiet; then
    echo -e "${YELLOW}[!] No staged changes found to commit.${NC}"
else
    git commit -m "${COMMIT_MSG}"
    echo -e "${GREEN}[✓] Initial release committed successfully.${NC}"
fi

# 6. Push to Remote Main
echo ""
echo -e "${BOLD}${GREEN}====================================================${NC}"
echo -e "${BOLD}${GREEN}   Repository configured and ready for GitHub!      ${NC}"
echo -e "${BOLD}${GREEN}====================================================${NC}"
echo -e "Remote: ${REPO_URL}"
echo -e "Branch: main"
echo ""
echo -e "To push to GitHub, run:"
echo -e "    ${BOLD}git push -u origin main${NC}"
echo ""

# Push automatically if --push flag is provided
if [[ "${1:-}" == "--push" ]]; then
    echo -e "${BLUE}[*] Pushing branch main to origin...${NC}"
    git push -u origin main
fi
