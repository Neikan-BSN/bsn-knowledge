# bsn-knowledge

![Python](https://img.shields.io/badge/python-3.11+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Status](https://img.shields.io/badge/status-active-brightgreen.svg) ![Medical](https://img.shields.io/badge/medical-HIPAA-blue.svg) ![OCR](https://img.shields.io/badge/OCR-processing-green.svg)

HIPAA-compliant medical document processing with OCR validation

## Overview

**Medical Documentation System** - HIPAA-compliant medical document processing with OCR validation

**Project Type**: Medical Documentation
**Framework**: Fastapi
**Complexity**: Medium

## Key Features

- Medical document OCR processing
- HIPAA compliance framework
- Clinical terminology validation
- FDA regulatory compliance

## Quick Start

```bash
# Clone the repository
git clone <repository-url> bsn-knowledge
cd bsn-knowledge

# Install and setup
uv sync --all-extras

# Install and setup
python src/main.py --help

# Install and setup
make test

```

## Installation

### Requirements

- Python 3.11 or higher
- UV package manager (recommended) or pip
- Tesseract OCR engine
- HIPAA-compliant environment

### Setup

1. **Install dependencies:**
   ```bash
   uv sync --all-extras
   ```

2. **Start services:**
   ```bash
   docker-compose up -d
   ```

3. **Verify installation:**
   ```bash
   make test
   ```

## Usage

### Document OCR Processing

```python
from cicu import DocumentProcessor

# Initialize HIPAA-compliant processor
processor = DocumentProcessor(hipaa_mode=True)

# Process medical document
result = processor.process_document("medical_form.pdf")

print(f"Extracted text: {result.text}")
print(f"Confidence: {result.confidence}")
```

**Note**: This system is designed for educational and administrative purposes only. Not for clinical decision-making.

## HIPAA Compliance Notice

This system is designed to handle Protected Health Information (PHI) in compliance with HIPAA regulations:

- **Data Encryption**: All PHI is encrypted both in transit and at rest
- **Access Controls**: Role-based access control with audit logging
- **Data Retention**: Configurable retention policies for clinical data
- **Audit Trail**: Comprehensive logging of all PHI access and modifications

**Important**: This system is for administrative and educational purposes. Not intended for clinical decision-making.

## Documentation

- [API Documentation](docs/api.md) - Complete API reference
- [Architecture Guide](docs/architecture.md) - System design and components
- [Development Guide](docs/development.md) - Setup and contribution guidelines
- [Deployment Guide](docs/deployment.md) - Production deployment instructions
- [HIPAA Compliance](docs/hipaa.md) - Privacy and security guidelines
- [OCR Configuration](docs/ocr.md) - OCR engine setup and tuning

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Project Type**: Medical Documentation  
**Generated**: 2025-08-18 using automated documentation system