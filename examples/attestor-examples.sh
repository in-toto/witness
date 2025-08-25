#!/bin/bash
# Example script showing how to use different attestors with witness

# Generate a test key if it doesn't exist
if [ ! -f test-key.pem ]; then
    echo "Generating test key..."
    openssl genrsa -out test-key.pem 2048 2>/dev/null
    openssl rsa -in test-key.pem -pubout -out test-pub.pem 2>/dev/null
fi

echo "=== Witness Attestor Examples ==="
echo

# Git attestor - captures repository state
echo "1. Git attestor example:"
echo "witness run -s build -k test-key.pem -a git -- go build ./..."
echo

# Environment attestor - captures environment variables
echo "2. Environment attestor example:"
echo "witness run -s test -k test-key.pem -a environment -- pytest"
echo

# Material attestor - records input files
echo "3. Material attestor example:"
echo "witness run -s build -k test-key.pem -a material -- cargo build --release"
echo

# Product attestor - records output files  
echo "4. Product attestor example:"
echo "witness run -s package -k test-key.pem -a product -- npm run build"
echo

# Docker attestor - captures Docker image metadata
echo "5. Docker attestor example:"
echo "witness run -s package -k test-key.pem -a docker -- docker build -t myapp:latest ."
echo

# Command run attestor (automatic - no -a flag needed)
echo "6. Command run attestor example (automatic):"
echo "witness run -s compile -k test-key.pem -- make build"
echo

# Multiple attestors
echo "7. Multiple attestors example:"
echo "witness run -s build -k test-key.pem -a git,environment,material,product -- go build -o myapp ./cmd/main.go"
echo

# AWS attestor (only works on EC2)
echo "8. AWS attestor example (EC2 only):"
echo "witness run -s deploy -k test-key.pem -a aws -- terraform apply"
echo

# With output file
echo "9. Save attestation to file:"
echo "witness run -s build -k test-key.pem -a git -o build-attestation.json -- make build"
echo

# With timestamp server
echo "10. With timestamp server:"
echo "witness run -s build -k test-key.pem -a git -t https://freetsa.org/tsr -- go test ./..."
echo

echo
echo "Note: Replace 'test-key.pem' with your actual signing key"
echo "Note: Some attestors require specific environments (e.g., aws requires EC2, github requires GitHub Actions)"