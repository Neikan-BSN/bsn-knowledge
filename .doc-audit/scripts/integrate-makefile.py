#!/usr/bin/env python3
"""
Makefile Integration Script
Integrates documentation audit commands into existing Makefile
"""

import sys
from pathlib import Path

def integrate_makefile():
    """Integrate documentation commands into Makefile."""
    project_root = Path(__file__).parent.parent.parent
    makefile = project_root / "Makefile"
    makefile_integration = project_root / "Makefile.doc-audit"
    
    if not makefile.exists():
        print("❌ No Makefile found")
        return False
    
    if not makefile_integration.exists():
        print("❌ No Makefile.doc-audit found")
        return False
    
    makefile_content = makefile.read_text()
    integration_content = makefile_integration.read_text()
    
    # Check if already integrated
    if "docs-audit" in makefile_content:
        print("✅ Documentation audit already integrated")
        return True
    
    # Add integration to Makefile
    updated_content = makefile_content + "\n\n" + integration_content
    makefile.write_text(updated_content)
    
    print("✅ Documentation audit integrated into Makefile")
    return True

if __name__ == "__main__":
    success = integrate_makefile()
    sys.exit(0 if success else 1)
