#!/bin/bash
# Generate API documentation using OpenAPI

set -e

# Check if swagger-codegen is installed
if ! command -v swagger-codegen &> /dev/null; then
    echo "swagger-codegen not found. Installing..."
    
    # Check operating system
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        brew install swagger-codegen
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        sudo apt-get update && sudo apt-get install -y swagger-codegen
    else
        echo "Unsupported OS. Please install swagger-codegen manually."
        exit 1
    fi
fi

# Directory for OpenAPI spec
SPEC_DIR="docs/api"
OUTPUT_DIR="docs/api/generated"

# Create directories if they don't exist
mkdir -p $OUTPUT_DIR

# Generate documentation from OpenAPI spec
echo "Generating API documentation..."
swagger-codegen generate -i $SPEC_DIR/openapi.yaml -l html2 -o $OUTPUT_DIR

echo "API documentation generated successfully!"
echo "You can view the documentation by opening $OUTPUT_DIR/index.html in your browser."

# Copy to a location served by a web server if available
if [ -d "/var/www/html" ] && [ -w "/var/www/html" ]; then
    echo "Copying documentation to web server..."
    sudo cp -r $OUTPUT_DIR/* /var/www/html/api-docs/
    echo "Documentation available at http://localhost/api-docs/"
fi
