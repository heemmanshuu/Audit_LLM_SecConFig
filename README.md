# LLMSecConfig

LLMSecConfig is an innovative framework that leverages Large Language Models (LLMs) to enhance the security of Kubernetes configurations. The project addresses the critical challenge of identifying and rectifying security misconfigurations in cloud-native applications, combining traditional security scanning tools with advanced AI-driven analysis.

## Key Features

- **Multi-Scanner Integration**: Integrates multiple security scanners (Checkov, Kubesec, Terrascan) for comprehensive vulnerability detection
- **LLM-Powered Analysis**: Utilizes state-of-the-art language models to:
  - Analyze security scan results
  - Provide context-aware remediation suggestions
  - Generate human-readable explanations of security issues
- **Automated Data Collection**: Efficiently gathers and processes Kubernetes configurations from ArtifactHub
- **Intelligent Remediation**: Suggests security fixes based on best practices and learned patterns
- **Extensible Architecture**: Modular design allows easy integration of new security tools and LLM backends

The framework is designed for DevOps engineers, security professionals, and platform teams who need to maintain secure Kubernetes deployments at scale. It helps bridge the gap between automated security scanning and human-readable, actionable insights.

## Project Structure

### Core Components

- `vendors/`: Security scanning and analysis framework
  - `checkov/`: Checkov integration and custom rules
  - `base_vendor.py`: Base implementation for security vendors
  - `llm_vendor.py`: LLM-based analysis integration

- `fetch_artifacthub/`: Data collection and processing pipeline
  - `fetch_artifacthub.go`: Artifacthub API data fetcher
  - `gather_artifacthub.py`: Data consolidation
  - `get_yamls.py`: YAML extraction from Helm packages
  - `clean_yamls.py`: YAML validation and cleaning
  - `scan_and_analyse.py`: Security scanning pipeline
  - `split_cleaned_yamls.py`: YAML processing utilities
  - `resort.py`: Dataset organization

### Supporting Components

- `test_checkov.py`: Security analysis execution
- `gather_results.ipynb`: Results visualization
- `limiter.py`: Rate limiting utilities

### Directories
- `assets/`: Processed Kubernetes configurations
- `fetch_artifacthub/gathered/`: Processed data and analysis results
- `vendors/`: Extended security rules and tools

## Prerequisites

- Python 3.10
- Go 1.23.1
- LiteLLM backend
- Internet connection
- Checkov security scanner

## Installation & Setup

1. **Environment Setup**
   ```bash
   # Install Python dependencies
   pip install -r requirements.txt
   pip install -U checkov

   # Configure LiteLLM
   touch .env  # Add your LiteLLM credentials here
   # not really needed right now?
   ```

2. **Data Collection**
   ```bash
   # Fetch and process ArtifactHub data
   go run fetch_artifacthub/fetch_artifacthub.go
   ```
   If the above step errors out, create a go.mod file in the repository root
   ```bash
   go mod init llm_secconfig
   ```
   then, when you try 
   ```bash
   go run fetch_artifacthub/fetch_artifacthub.go
   
   # it will show you what modules need to be added. 
   # just run the go get commands it asks you to
   # remember to cd into fetch_artifactshub before running the go files
   ```
   Now run
   ```bash
   python gather_artifacthub.py
   python get_yamls.py
   python clean_yamls.py

   # Generate dataset
   python fetch_artifacthub/resort.py
   ```

3. **Security Analysis**
   ```bash
   # Update security rules (optional)
   python vendors/checkov/checkov_rules.py

   # View analysis options
   python test_checkov.py --help

   # Run analysis
   python test_checkov.py
   ```

4. **Results Visualization**
   ```bash
   jupyter notebook gather_results.ipynb
   ```

## Analysis Pipeline

1. **Data Collection & Processing**
   - Fetch metadata from ArtifactHub
   - Convert Helm charts to K8s YAML files
   - Clean configurations using SAT solver
   - Output: `fetch_artifacthub/gathered/cleaned_files.csv`

2. **Security Analysis**
   - Comprehensive Checkov security scanning
   - LLM-based configuration analysis
   - Interactive correction suggestions
   - All intermediate files stored in `test/` directory

3. **Results Analysis**
   - Detailed visualization of findings
   - Performance metrics and statistics
   - Configuration pattern analysis
   - Security improvement recommendations

## Dependencies

### Python Dependencies
- `pandas`: Data processing
- `checkov`: Security scanning
- `litellm`: LLM integration
- Additional requirements in `requirements.txt`

### External Tools
- Checkov security scanner
- LiteLLM backend
- Jupyter (for visualization)