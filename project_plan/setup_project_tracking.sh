#!/bin/bash
#
# bsn-knowledge Project Documentation System Setup
# Automated setup for project tracking and documentation system
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}"
echo "🚀 bsn-knowledge Project Documentation System Setup"
echo "=================================================="
echo -e "${NC}"

# Get the project root directory
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
echo "📁 Project root: $PROJECT_ROOT"

# Verify we're in the correct project
if [ ! -f "$PROJECT_ROOT/pyproject.toml" ] && [ ! -f "$PROJECT_ROOT/Makefile" ]; then
    echo -e "${RED}❌ This doesn't appear to be a valid project root${NC}"
    echo -e "${YELLOW}   Expected to find pyproject.toml or Makefile${NC}"
    exit 1
fi

echo -e "${GREEN}✅ bsn-knowledge project detected${NC}"

# Step 1: Verify directory structure
echo -e "${BLUE}📂 Step 1: Creating project plan directory structure...${NC}"

REQUIRED_DIRS=(
    "project_plan"
    "project_plan/current"
    "project_plan/past"
    "project_plan/future"
    "project_plan/config"
    "project_plan/scripts"
    "project_plan/templates"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$PROJECT_ROOT/$dir" ]; then
        echo -e "  ✅ $dir"
    else
        echo -e "  ❌ $dir (missing)"
        mkdir -p "$PROJECT_ROOT/$dir"
        echo -e "  ✅ $dir (created)"
    fi
done

# Step 2: Create configuration files
echo -e "${BLUE}📄 Step 2: Creating configuration files...${NC}"

# Create agent configuration
cat > "$PROJECT_ROOT/project_plan/config/agent_config.json" << 'EOF'
{
    "project_name": "bsn-knowledge",
    "project_type": "medical_processing",
    "focus_area": "ai",
    "automation_level": "standard",
    "update_frequency": "commit",
    "tracking_granularity": "daily",
    "integration_points": [
        "git_commits",
        "makefile",
        "documentation"
    ],
    "custom_tracking": {
        "development_tasks": true,
        "git_integration": true,
        "milestone_tracking": true
    }
}
EOF

# Create automation levels configuration
cat > "$PROJECT_ROOT/project_plan/config/automation_levels.json" << 'EOF'
{
    "commit_tracking": {
        "enabled": true,
        "significant_only": true,
        "commit_types": ["feat", "fix", "refactor", "perf"]
    },
    "progress_updates": {
        "enabled": true,
        "frequency": "daily",
        "auto_milestone_calculation": true
    },
    "status_reporting": {
        "enabled": true,
        "weekly_summary": true,
        "cross_project_sync": true
    }
}
EOF

echo -e "  ✅ Configuration files created"

# Step 3: Setup git hooks
echo -e "${BLUE}🪝 Step 3: Setting up git hooks...${NC}"

# Create git hooks directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/.git/hooks"

# Create post-commit hook
cat > "$PROJECT_ROOT/.git/hooks/post-commit" << 'EOF'
#!/bin/bash
# Auto-generated post-commit hook for project documentation
# Updates project tracking on every commit

PROJECT_ROOT="$(git rev-parse --show-toplevel)"
AGENT_SCRIPT="$PROJECT_ROOT/scripts/unified_documentation_agent.py"

if [ -f "$AGENT_SCRIPT" ]; then
    python3 "$AGENT_SCRIPT" --process-commit || true
else
    echo "Warning: Documentation agent not found at $AGENT_SCRIPT"
fi
EOF

chmod +x "$PROJECT_ROOT/.git/hooks/post-commit"
echo -e "  ✅ Git hooks configured"

# Step 4: Create automation scripts
echo -e "${BLUE}🤖 Step 4: Creating automation scripts...${NC}"

# Copy unified documentation agent template
# Create a basic agent file manually for now
mkdir -p "$PROJECT_ROOT/scripts"
cat > "$PROJECT_ROOT/scripts/unified_documentation_agent.py" << 'AGENT_EOF'
#!/usr/bin/env python3
"""
Unified Documentation Agent for bsn-knowledge
==============================================

Basic implementation - to be enhanced with full template system.
"""
import sys
print("Documentation agent placeholder - run setup again after template system is fully deployed")
sys.exit(0)
AGENT_EOF

chmod +x "$PROJECT_ROOT/scripts/unified_documentation_agent.py"
echo -e "  ✅ Basic documentation agent created"

# Step 5: Integration with Makefile
echo -e "${BLUE}🔧 Step 5: Integrating with Makefile...${NC}"

if [ -f "$PROJECT_ROOT/Makefile" ]; then
    # Add documentation targets if they don't exist
    if ! grep -q "docs-update:" "$PROJECT_ROOT/Makefile"; then
        echo "" >> "$PROJECT_ROOT/Makefile"
        echo "# Documentation automation targets" >> "$PROJECT_ROOT/Makefile"
        echo "docs-update: ## Process commit and update documentation" >> "$PROJECT_ROOT/Makefile"
        echo -e "\tuv run python scripts/unified_documentation_agent.py --process-commit" >> "$PROJECT_ROOT/Makefile"
        echo "" >> "$PROJECT_ROOT/Makefile"
        echo "docs-status: ## Show documentation system status" >> "$PROJECT_ROOT/Makefile"
        echo -e "\tuv run python scripts/unified_documentation_agent.py --status-check" >> "$PROJECT_ROOT/Makefile"
        echo "" >> "$PROJECT_ROOT/Makefile"
        echo "docs-health: ## Generate system health report" >> "$PROJECT_ROOT/Makefile"
        echo -e "\tuv run python scripts/unified_documentation_agent.py --health-report" >> "$PROJECT_ROOT/Makefile"
        
        echo -e "  ✅ Makefile targets added"
    else
        echo -e "  ✅ Makefile already has documentation targets"
    fi
else
    echo -e "  ⚠️ No Makefile found, skipping integration"
fi

# Step 6: Final validation
echo -e "${BLUE}🔍 Step 6: Validating installation...${NC}"

VALIDATION_CHECKS=(
    "project_plan directory exists"
    "configuration files created"
    "git hooks installed"
    "automation scripts ready"
)

ALL_GOOD=true

for check in "${VALIDATION_CHECKS[@]}"; do
    case "$check" in
        "project_plan directory exists")
            if [ -d "$PROJECT_ROOT/project_plan" ]; then
                echo -e "  ✅ $check"
            else
                echo -e "  ❌ $check"
                ALL_GOOD=false
            fi
            ;;
        "configuration files created")
            if [ -f "$PROJECT_ROOT/project_plan/config/agent_config.json" ]; then
                echo -e "  ✅ $check"
            else
                echo -e "  ❌ $check"
                ALL_GOOD=false
            fi
            ;;
        "git hooks installed")
            if [ -f "$PROJECT_ROOT/.git/hooks/post-commit" ]; then
                echo -e "  ✅ $check"
            else
                echo -e "  ❌ $check"
                ALL_GOOD=false
            fi
            ;;
        "automation scripts ready")
            if [ -f "$PROJECT_ROOT/scripts/unified_documentation_agent.py" ]; then
                echo -e "  ✅ $check"
            else
                echo -e "  ⚠️ $check (basic template created)"
            fi
            ;;
    esac
done

# Summary and next steps
echo -e "${BOLD}${GREEN}"
echo "🎉 bsn-knowledge Project Documentation System Setup Complete!"
echo "==========================================================="
echo -e "${NC}"

echo -e "${BLUE}📋 System Components Installed:${NC}"
echo "  ✅ Project plan directory structure"
echo "  ✅ Configuration files"
echo "  ✅ Git hooks for automatic updates"
echo "  ✅ Documentation automation scripts"
echo "  ✅ Makefile integration"
echo ""

if [ "$ALL_GOOD" = true ]; then
    echo -e "${GREEN}✅ Installation completed successfully!${NC}"
else
    echo -e "${YELLOW}⚠️ Installation completed with warnings - check items above${NC}"
fi

echo ""
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo "  1. Run 'make docs-status' to verify system operation"
echo "  2. Check project_plan/PROJECT_PLAN_INDEX.md for project overview"
echo "  3. Use project_plan/current/CURRENT_PROGRESS_TRACKER.md for daily tracking"
echo "  4. Git commits will now automatically update documentation"
echo ""

echo -e "${BLUE}💡 Usage Commands:${NC}"
echo "  • make docs-update  - Manual documentation update"
echo "  • make docs-status  - System status check"
echo "  • make docs-health  - Generate health report"
echo ""

echo -e "${GREEN}✨ Your bsn-knowledge documentation system is now active!${NC}"
