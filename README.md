# PhishingAIDetection

![Security Analysis](https://img.shields.io/badge/Security-Analysis-blue)
![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green)
![License MIT](https://img.shields.io/badge/License-MIT-yellow)

A comprehensive tool for detecting phishing websites using [urlscan.io](https://urlscan.io) and [Anthropic's Claude API](https://www.anthropic.com/claude). This project provides in-depth security assessments of web pages by combining automated scanning with AI-powered analysis.

## Features

- **Complete URL Security Analysis**: Submit any URL for a comprehensive security assessment
- **Automated Screenshot Analysis**: Uses Claude's vision capabilities to analyze webpage screenshots
- **DOM Content Extraction**: Pulls and analyzes the Document Object Model (DOM) for malicious elements
- **Deep URL Extraction**: Identifies and examines all links, scripts, iframes, and other elements
- **AI-Powered Security Assessment**: Leverages Claude's intelligence to detect suspicious patterns
- **Structured Security Reports**: Provides detailed, organized security verdicts

## Requirements

- Python 3.8 or higher
- urlscan.io API key
- Anthropic API key (with access to Claude 3.5 Sonnet or compatible models)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/PhishingAIDetection.git
cd PhishingAIDetection

# Install dependencies
pip install requests beautifulsoup4 anthropic python-dotenv

# Set up environment variables
echo "URLSCAN_API_KEY=your_urlscan_api_key" > .env
echo "CLAUDE_API_KEY=your_claude_api_key" >> .env
```

## Usage

### Running the Script Directly

The simplest way to use this tool is to run the script directly:

```bash
python phishing_ai_detection.py
```

This will start the interactive CLI that guides you through the URL analysis process.

### Using as a Module

You can also import and use the `URLAnalyzer` class in your own Python scripts:

```python
from phishing_ai_detection import URLAnalyzer
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize with API keys
analyzer = URLAnalyzer(
    urlscan_api_key=os.getenv("URLSCAN_API_KEY"),
    claude_api_key=os.getenv("CLAUDE_API_KEY")
)

# Analyze a URL
result = analyzer.analyze_url(
    url="https://example.com",
    max_wait_time=120,  # Maximum seconds to wait for scan completion
    max_tokens=4096     # Maximum tokens for Claude's analysis
)

# Print analysis results
if "result" in result and "analysis" in result["result"]:
    print(result["result"]["analysis"])
```

## Architecture

The project consists of three main classes:

### `UrlScanAPI`

Handles all interactions with the urlscan.io API:
- Submits URLs for scanning
- Retrieves scan results
- Extracts DOM content
- Analyzes page components
- Downloads screenshots

### `ClaudeAPI`

Manages communication with Anthropic's Claude AI:
- Sends prompts with images
- Processes responses
- Handles API authentication

### `URLAnalyzer`

Coordinates the entire analysis process:
- Submits scan requests
- Waits for results
- Extracts key data
- Gathers DOM information
- Generates comprehensive analysis through Claude

## Analysis Structure

Each security assessment includes:

1. **Visual Analysis**: Examines the screenshot for suspicious visual elements
2. **DOM Analysis**: Investigates scripts, forms, and other components for malicious content
3. **Scan Analysis**: Reviews domain information, redirects, and connections
4. **Summary**: Provides a high-level overview of findings
5. **Verdict**: Delivers a final risk assessment with recommendations

## Security Use Cases

- Phishing detection
- Malware identification
- Suspicious script/obfuscation detection
- Brand impersonation detection
- Social engineering analysis
- Vulnerability assessment

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions, issues, and feature requests are welcome. Please check the issues page for current needs.

## Disclaimer

This tool is designed for security research and legitimate security testing only. Always ensure you have permission to scan the URLs you analyze.
