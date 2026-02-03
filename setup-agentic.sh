#!/bin/bash

# Create .agentic structure
mkdir -p .agentic/{context,indexes,prompts}

# Create context files
touch .agentic/context/{architecture,conventions,workflows,glossary}.md

# Create prompt templates
touch .agentic/prompts/{system,code-review,testing,documentation}.md

# Create config
cat > .agentic/config.json << 'EOF'
{
  "version": "1.0.0",
  "codebase": {
    "language": "",
    "framework": "",
    "entryPoint": ""
  }
}
EOF

# Create README placeholders
find . -type d -not -path '*/node_modules/*' -not -path '*/.git/*' -exec sh -c 'test ! -f "$1/README.md" && touch "$1/README.md"' _ {} \;

echo "✓ Agentic structure created"