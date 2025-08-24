
# Project Documentation Automation
# Auto-generated integration for bsn-knowledge

docs-update: ## Process commit and update documentation
	@echo "🔄 Processing commit and updating documentation..."
	uv run python scripts/unified_documentation_agent.py --process-commit

docs-status: ## Show documentation system status  
	@echo "📊 Checking documentation system status..."
	uv run python scripts/unified_documentation_agent.py --status-check

docs-health: ## Generate system health report
	@echo "🏥 Generating system health report..."
	uv run python scripts/unified_documentation_agent.py --health-report
	@echo "📋 Health report available in project_plan/"

docs-validate: ## Validate documentation system
	@echo "🔍 Validating documentation system..."
	uv run python scripts/unified_documentation_agent.py --validate-system

docs-setup: ## Setup/reinstall documentation tracking system
	@echo "🚀 Setting up documentation tracking system..."
	./project_plan/setup_project_tracking.sh
