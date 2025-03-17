import requests
import json
import os
import time
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime
import anthropic
from bs4 import BeautifulSoup
import re

class UrlScanAPI:
    """A class to interact with urlscan.io API."""
    
    def __init__(self, api_key: str):
        """
        Initialize the UrlScanAPI with your API key.
        
        Args:
            api_key: Your urlscan.io API key
        """
        self.api_key = api_key
        self.headers = {
            'API-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        self.base_url = "https://urlscan.io/api/v1"
    
    def submit_url(self, url: str, visibility: str = "public") -> Dict[str, Any]:
        """
        Submit a URL to urlscan.io for scanning.
        
        Args:
            url: The URL to scan
            visibility: Scan visibility (public, unlisted, or private)
            
        Returns:
            Dict containing scan details including UUID
        """
        data = {
            "url": url,
            "visibility": visibility
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/scan/",
                headers=self.headers,
                data=json.dumps(data)
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_scan_results(self, uuid: str) -> Dict[str, Any]:
        """
        Get the results of a scan by UUID.
        
        Args:
            uuid: The UUID of the scan
            
        Returns:
            Dict containing scan results or error
        """
        try:
            response = requests.get(f"{self.base_url}/result/{uuid}/")
            
            if response.status_code == 404:
                return {"error": "Scan still in progress"}
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_page_source(self, uuid: str) -> Dict[str, Any]:
        """
        Extract the domURL data from scan results.
        
        Args:
            uuid: The UUID of the scan
            
        Returns:
            Dict containing domURL data
        """
        try:
            # Get scan results to extract domURL
            response = requests.get(f"{self.base_url}/result/{uuid}/")
            
            if response.status_code == 404:
                return {"error": "Scan still in progress"}
            
            response.raise_for_status()
            result_data = response.json()
            
            # Extract the domURL
            if "task" in result_data and "domURL" in result_data["task"]:
                dom_url = result_data["task"]["domURL"]
                return {"domURL": dom_url}
            else:
                return {"error": "domURL not found in scan results"}
            
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_dom_content(self, dom_url: str) -> Dict[str, Any]:
        """
        Fetch the actual DOM content from the domURL.
        
        Args:
            dom_url: The URL to the DOM content
            
        Returns:
            Dict containing DOM content or error
        """
        try:
            response = requests.get(dom_url)
            response.raise_for_status()
            
            # Return the DOM content
            return {
                "content": response.text,
                "status": response.status_code
            }
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def extract_urls_from_dom(self, html_content: str) -> Dict[str, Any]:
        """
        Extract all URLs from the DOM content.
        
        Args:
            html_content: The HTML content to analyze
            
        Returns:
            Dict containing extracted URLs
        """
        print("[DEBUG] Starting URL extraction from DOM content")
        print(f"[DEBUG] HTML content length: {len(html_content)} bytes")
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            print(f"[DEBUG] Successfully parsed HTML with BeautifulSoup")
            
            urls = {
                'a_tags': [],
                'script_tags': [],
                'iframe_tags': [],
                'img_tags': [],
                'form_tags': [],
                'meta_tags': [],
                'link_tags': [],
                'urls_in_text': []
            }
            
            # Extract URLs from <a> tags
            print("[DEBUG] Extracting URLs from <a> tags")
            a_tags = soup.find_all('a')
            print(f"[DEBUG] Found {len(a_tags)} <a> tags")
            for a in a_tags:
                href = a.get('href')
                if href:
                    urls['a_tags'].append({
                        'href': href,
                        'text': a.text.strip()[:50] if a.text else '',
                    })
                    print(f"[DEBUG] Found a href: {href}")
            
            # Extract URLs from <script> tags
            print("[DEBUG] Extracting URLs from <script> tags")
            script_tags = soup.find_all('script')
            print(f"[DEBUG] Found {len(script_tags)} <script> tags")
            for script in script_tags:
                src = script.get('src')
                if src:
                    urls['script_tags'].append({
                        'src': src,
                    })
                    print(f"[DEBUG] Found script src: {src}")
            
            # Extract URLs from <iframe> tags
            print("[DEBUG] Extracting URLs from <iframe> tags")
            iframe_tags = soup.find_all('iframe')
            print(f"[DEBUG] Found {len(iframe_tags)} <iframe> tags")
            for iframe in iframe_tags:
                src = iframe.get('src')
                if src:
                    urls['iframe_tags'].append({
                        'src': src,
                    })
                    print(f"[DEBUG] Found iframe src: {src}")
            
            # Extract URLs from <img> tags
            print("[DEBUG] Extracting URLs from <img> tags")
            img_tags = soup.find_all('img')
            print(f"[DEBUG] Found {len(img_tags)} <img> tags")
            for img in img_tags:
                src = img.get('src')
                if src:
                    urls['img_tags'].append({
                        'src': src,
                    })
                    print(f"[DEBUG] Found img src: {src}")
            
            # Extract URLs from <form> tags
            print("[DEBUG] Extracting URLs from <form> tags")
            form_tags = soup.find_all('form')
            print(f"[DEBUG] Found {len(form_tags)} <form> tags")
            for form in form_tags:
                action = form.get('action')
                if action:
                    urls['form_tags'].append({
                        'action': action,
                    })
                    print(f"[DEBUG] Found form action: {action}")
            
            # Extract URLs from <meta> tags (refresh redirects)
            print("[DEBUG] Extracting URLs from <meta> tags")
            meta_tags = soup.find_all('meta')
            print(f"[DEBUG] Found {len(meta_tags)} <meta> tags")
            for meta in meta_tags:
                content = meta.get('content', '')
                if meta.get('http-equiv', '').lower() == 'refresh' and 'url=' in content.lower():
                    # Extract URL from meta refresh
                    url_part = content.split('url=', 1)[1].strip()
                    urls['meta_tags'].append({
                        'type': 'refresh',
                        'content': content,
                        'url': url_part
                    })
                    print(f"[DEBUG] Found meta refresh URL: {url_part}")
            
            # Extract URLs from <link> tags
            print("[DEBUG] Extracting URLs from <link> tags")
            link_tags = soup.find_all('link')
            print(f"[DEBUG] Found {len(link_tags)} <link> tags")
            for link in link_tags:
                href = link.get('href')
                if href:
                    urls['link_tags'].append({
                        'href': href,
                        'rel': link.get('rel', ''),
                    })
                    print(f"[DEBUG] Found link href: {href}")
            
            # Extract URLs from inline text (using regex)
            print("[DEBUG] Extracting URLs from text content using regex")
            # URL pattern
            url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[a-zA-Z]{2,}'
            
            # Find URLs in all text nodes
            for text in soup.find_all(string=True):
                if text.parent.name not in ['script', 'style']:  # Skip script and style contents
                    for url in re.findall(url_pattern, text):
                        urls['urls_in_text'].append(url)
                        print(f"[DEBUG] Found URL in text: {url}")
            
            # Remove duplicates from urls_in_text
            urls['urls_in_text'] = list(set(urls['urls_in_text']))
            print(f"[DEBUG] Total unique URLs found in text: {len(urls['urls_in_text'])}")
            
            # Print summary
            total_urls = sum(len(urls[key]) for key in urls)
            print(f"[DEBUG] Total URLs extracted: {total_urls}")
            
            return urls
            
        except Exception as e:
            print(f"[DEBUG ERROR] Error extracting URLs: {str(e)}")
            return {"error": f"Error extracting URLs: {str(e)}"}
    
    def download_screenshot(self, uuid: str, output_path: str) -> str:
        """
        Download the screenshot of a scan.
        
        Args:
            uuid: The UUID of the scan
            output_path: Where to save the screenshot
            
        Returns:
            Path to the saved screenshot or error message
        """
        try:
            response = requests.get(f"https://urlscan.io/screenshots/{uuid}.png", stream=True)
            response.raise_for_status()
            
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return output_path
        except requests.exceptions.RequestException as e:
            return f"Error: {str(e)}"

class ClaudeAPI:
    """A class to interact with Anthropic's Claude API using the official SDK."""
    
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20240620"):
        """
        Initialize the ClaudeAPI with your API key.
        
        Args:
            api_key: Your Anthropic API key
            model: Claude model to use
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
    
    def generate_response_with_image(
        self, 
        prompt: str,
        image_path: str, 
        max_tokens: int = 4096, 
        temperature: float = 0.7,
        system_prompt: Optional[str] = None
    ) -> Dict[Any, Any]:
        """
        Send a prompt with an image to Claude and get a response.
        
        Args:
            prompt: The user message to send to Claude
            image_path: Path to the image file
            max_tokens: Maximum number of tokens in the response
            temperature: Controls randomness (0.0-1.0)
            system_prompt: Optional system prompt to guide Claude's behavior
            
        Returns:
            Dict containing Claude's response and metadata
        """
        try:
            # Read the image file as binary
            with open(image_path, "rb") as f:
                image_data = f.read()
            
            # Create a message with text and image content
            message_content = [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": self._get_media_type(image_path),
                        "data": base64.b64encode(image_data).decode("utf-8")
                    }
                },
                {
                    "type": "text",
                    "text": prompt
                }
            ]
            
            message_params = {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [
                    {"role": "user", "content": message_content}
                ]
            }
            
            if system_prompt:
                message_params["system"] = system_prompt
                
            message = self.client.messages.create(**message_params)
            
            # Convert API response to a consistent format
            return {
                "content": [{"type": "text", "text": message.content[0].text}],
                "model": message.model,
                "id": message.id,
                "usage": {
                    "input_tokens": message.usage.input_tokens,
                    "output_tokens": message.usage.output_tokens
                }
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _get_media_type(self, image_path: str) -> str:
        """Determine the media type based on file extension."""
        ext = image_path.lower().split('.')[-1]
        if ext == 'jpg' or ext == 'jpeg':
            return 'image/jpeg'
        elif ext == 'png':
            return 'image/png'
        elif ext == 'gif':
            return 'image/gif'
        elif ext == 'webp':
            return 'image/webp'
        else:
            return 'image/jpeg'  # Default to JPEG if unknown

class URLAnalyzer:
    """Main class to analyze URLs using urlscan.io and Claude."""
    
    def __init__(self, urlscan_api_key: str, claude_api_key: str):
        self.urlscan = UrlScanAPI(urlscan_api_key)
        self.claude = ClaudeAPI(claude_api_key, model="claude-3-5-sonnet-20240620")
        self.temp_dir = "temp"
        
        # Create temp directory if it doesn't exist
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)
    
    def analyze_url(self, url: str, max_wait_time: int = 120, max_tokens: int = 4096) -> Dict[str, Any]:
        """
        Complete process to analyze a URL using urlscan.io and Claude.
        
        Args:
            url: The URL to analyze
            max_wait_time: Maximum time to wait for scan results in seconds
            max_tokens: Maximum tokens for Claude's response
            
        Returns:
            Dict with analysis results
        """
        print(f"[+] Submitting URL to urlscan.io: {url}")
        submission = self.urlscan.submit_url(url)
        
        if "error" in submission:
            return {"error": submission["error"]}
        
        uuid = submission["uuid"]
        print(f"[+] Scan submitted successfully. UUID: {uuid}")
        print(f"[+] Scan result will be available at: {submission['result']}")
        
        # Wait for initial scan processing
        print("[+] Waiting 15 seconds for initial processing...")
        time.sleep(15)
        
        # Poll for results
        results = None
        start_time = time.time()
        while time.time() - start_time < max_wait_time:
            print(f"[+] Checking if scan is complete... ({int(time.time() - start_time)}s elapsed)")
            scan_results = self.urlscan.get_scan_results(uuid)
            
            if "error" not in scan_results:
                results = scan_results
                print("[+] Scan completed successfully!")
                break
                
            print("[+] Scan still in progress, waiting 5 seconds...")
            time.sleep(5)
        
        if not results:
            return {"error": f"Scan did not complete within {max_wait_time} seconds"}
        
        # Extract key scan data
        scan_data = self._extract_key_data(results)
        
        # Extract domURL data
        print("[+] Extracting domURL data...")
        page_source = self.urlscan.get_page_source(uuid)
        
        # Fetch DOM content if domURL is available
        dom_content = None
        dom_urls = None
        if "error" not in page_source and "domURL" in page_source:
            print(f"[+] Fetching DOM content from {page_source['domURL']}...")
            dom_content = self.urlscan.get_dom_content(page_source['domURL'])
            
            # Extract URLs from DOM content
            if "error" not in dom_content:
                print("[+] Extracting URLs from DOM content...")
                dom_urls = self.urlscan.extract_urls_from_dom(dom_content["content"])
                print(f"[DEBUG] URL extraction completed: {'success' if 'error' not in dom_urls else 'failed'}")
        
        # Prepare for analysis
        analysis_results = {}
        
        # Download screenshot
        screenshot_path = os.path.join(self.temp_dir, f"{uuid}.png")
        print(f"[+] Downloading screenshot to {screenshot_path}...")
        screenshot_result = self.urlscan.download_screenshot(uuid, screenshot_path)
        
        if screenshot_result.startswith("Error"):
            print(f"[!] Error downloading screenshot: {screenshot_result}")
            return {"error": "Failed to download screenshot"}
        
        # Analysis with screenshot
        print("[+] Sending data to Claude for analysis...")
        
        # Prepare DOM information for the prompt
        dom_info = ""
        if dom_urls and "error" not in dom_urls:
            # Use the extracted URL information
            print("[DEBUG] Preparing DOM URL information for Claude prompt")
            
            a_tags_sample = dom_urls.get('a_tags', [])[:20]  # Limit to 20 for readability
            script_tags_sample = dom_urls.get('script_tags', [])[:20]
            iframe_tags_sample = dom_urls.get('iframe_tags', [])[:20]
            urls_in_text_sample = dom_urls.get('urls_in_text', [])[:20]
            
            dom_info = f"""
            === DOM URLS ANALYSIS ===
            LINKS FOUND ({len(dom_urls.get('a_tags', []))} total):
            {json.dumps(a_tags_sample, indent=2)}
            
            SCRIPT SOURCES ({len(dom_urls.get('script_tags', []))} total):
            {json.dumps(script_tags_sample, indent=2)}
            
            IFRAME SOURCES ({len(dom_urls.get('iframe_tags', []))} total):
            {json.dumps(iframe_tags_sample, indent=2)}
            
            URLS IN TEXT ({len(dom_urls.get('urls_in_text', []))} total):
            {json.dumps(urls_in_text_sample, indent=2)}
            
            FORM ACTIONS ({len(dom_urls.get('form_tags', []))} total):
            {json.dumps(dom_urls.get('form_tags', [])[:10], indent=2)}
            
            META REDIRECTS:
            {json.dumps(dom_urls.get('meta_tags', []), indent=2)}
            
            LINK TAGS ({len(dom_urls.get('link_tags', []))} total):
            {json.dumps(dom_urls.get('link_tags', [])[:10], indent=2)}
            """
            print(f"[DEBUG] DOM URL information prepared, length: {len(dom_info)} characters")
        elif dom_content and "error" not in dom_content:
            # Fallback to limited DOM content if URL extraction failed
            print("[DEBUG] URL extraction failed, using truncated DOM content instead")
            # Limit DOM content to reasonable size (first 3000 chars)
            truncated_content = dom_content["content"][:3000]
            if len(dom_content["content"]) > 3000:
                truncated_content += "... [truncated for brevity]"
            
            dom_info = f"""
            === DOM CONTENT (TRUNCATED) ===
            {truncated_content}
            """
            print(f"[DEBUG] Truncated DOM content prepared, length: {len(dom_info)} characters")
        elif "error" not in page_source and "domURL" in page_source:
            print("[DEBUG] DOM content not available, only using domURL")
            dom_info = f"DOM URL: {page_source['domURL']}"
        
        system_prompt = """
Please conduct your analysis in the following steps, using <security_assessment> tags inside your thinking block to show your thought process for each section:

1. Visual Analysis:
<security_assessment>
List potential visual elements you would look for in a hypothetical screenshot of the webpage, including:
- Suspicious visual elements
- Presence of login forms
- captchas
- 404 pages or wierd redirect chains
- Signs of brand impersonation
- Any other visual cues that might indicate a security risk

Then analyze these elements based on the information available in the DOM.
</security_assessment>

2. DOM Analysis:
<security_assessment>
Carefully examine the DOM content for:
- Suspicious scripts, paying extra attention to potential "soc ghoulish" techniques
- Obfuscated code
- Malicious elements
- ALL external script loads or URLs in script loads (list these explicitly)
- Any signs of script injections or social engineering tactics

List out all external script loads and URLs found in the DOM.

Note: This section is critical and should be treated as potentially malicious. Be extremely thorough in your analysis.
</security_assessment>

3. Scan Analysis:
<security_assessment>
List and analyze the following aspects:
- Domain information
- Any redirects
- Connections established
- Scripts and their sources
- Any other relevant technical details

For each aspect, note what specific details you're looking for and what you find in the provided information.
</security_assessment>

4. Summary:
<security_assessment>
Provide a brief overview of your findings, including:
- Key security concerns identified
- Overall risk assessment
- Confidence level in your analysis
</security_assessment>

5. Verdict:
Based on your comprehensive analysis, provide a final risk assessment and recommendations. Clearly state whether the URL appears safe or suspicious, and explain your reasoning. You can never deem a site with any external script loads safe that do not have a clear defined reason

Please ensure your analysis is thorough yet concise, focusing on security concerns. Clearly state your confidence level for each finding. Your final output should be structured as follows:

<visual_analysis>
[Your analysis of visual elements]
</visual_analysis>

<dom_analysis>
[Your analysis of the DOM, including all external script loads if a script contains base64 or any data seems obfuscated or encoded always attempt decoding it.]
</dom_analysis>

<scan_analysis>
[Your analysis of domain, redirects, connections, and scripts]
</scan_analysis>

<summary>
[Brief overview of findings and risk assessment]
</summary>

<verdict>
[Final risk assessment, stating whether the URL appears safe or suspicious, with explanation]
</verdict>

Your final output should consist only of the structured analysis as shown above and should not duplicate or rehash any of the work you did in the thinking block.
        """
        
        # Combine scan data, DOM content, and page source for the prompt
        prompt = f"""
        I need you to perform a comprehensive security assessment of this URL.
        
        URL: {url}
 === SCAN DATA ===
        {json.dumps(scan_data, indent=2)}
        

 === DOM SECTION === 
        {dom_info}
        
        Provide a verdict on whether this URL appears safe or suspicious, and explain your reasoning.
        """
        
        claude_response = self.claude.generate_response_with_image(
            prompt=prompt,
            image_path=screenshot_path,
            max_tokens=max_tokens,
            temperature=0.7,
            system_prompt=system_prompt
        )
        
        # Process Claude's response
        if "error" in claude_response:
            analysis_results["analysis"] = {"error": claude_response["error"]}
        else:
            # Extract Claude's text response
            for item in claude_response.get("content", []):
                if item["type"] == "text":
                    analysis_results["analysis"] = item["text"]
            
            # Add token usage info for reference
            if "usage" in claude_response:
                analysis_results["usage"] = claude_response["usage"]
        
        return {
            "url": url,
            "uuid": uuid,
            "scan_url": submission['result'],
            "result": analysis_results
        }
    
    def _extract_key_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract the most relevant data from urlscan results for analysis.
        
        Args:
            results: Full urlscan results
            
        Returns:
            Dict with the most relevant data for security analysis
        """
        key_data = {
            "page": results.get("page", {}),
            "meta": results.get("meta", {}),
            "stats": results.get("stats", {}),
            "lists": {
                "domains": results.get("lists", {}).get("domains", [])[:20],
                "urls": results.get("lists", {}).get("urls", [])[:20],
                "countries": results.get("lists", {}).get("countries", [])
            },
            "verdicts": results.get("verdicts", {}),
            "security": results.get("security", {}),
            "cookies": results.get("cookies", [])[:10]
        }
        
        return key_data

def main():
    # Hardcoded API keys - replace with your actual keys or environment variables
    urlscan_api_key = os.getenv('URLSCAN_API_KEY')
    claude_api_key = os.getenv('CLAUDE_API_KEY')
    if not claude_api_key:
        print("Error: Claude API key not set.")
        return
    if not urlscan_api_key:
        print("Error: URLScan API key not set.")
        return
    
    # Simple menu
    print("\n===== URL Analyzer =====")
    
    # Get URL to analyze
    url = input("Enter URL to analyze: ").strip()
    
    if not url:
        print("Error: URL cannot be empty.")
        return
    
    # Add http:// prefix if not present
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Analysis options
    print("\n" + "=" * 50)
    print(f"Starting analysis of: {url}")
    print("=" * 50 + "\n")
    
    max_wait_time = int(input("Maximum wait time in seconds (default: 120): ").strip() or "120")
    max_tokens = int(input("Maximum output tokens (default: 4096): ").strip() or "4096")
    
    # Create analyzer with Claude 3.5 Sonnet
    analyzer = URLAnalyzer(urlscan_api_key, claude_api_key)
    
    # Analyze URL
    result = analyzer.analyze_url(
        url=url,
        max_wait_time=max_wait_time,
        max_tokens=max_tokens
    )
    
    if "error" in result:
        print(f"Error: {result['error']}")
        return
    
    # Print analysis results
    print("\n" + "=" * 80)
    print(f"SECURITY ANALYSIS FOR: {url}")
    print("=" * 80 + "\n")
    
    print(f"Scan URL: {result['scan_url']}")
    print(f"Scan UUID: {result['uuid']}")
    
    print("\n" + "-" * 80)
    print("ANALYSIS:")
    print("-" * 80)
    
    if "result" in result and "analysis" in result["result"]:
        print(result["result"]["analysis"])
"""         
        # Print token usage if available
        if "usage" in result["result"]:
            print("\n" + "-" * 50)hye
            print("API USAGE:")
            print(f"Input tokens: {result['result']['usage'].get('input_tokens', 'N/A')}")
            print(f"Output tokens: {result['result']['usage'].get('output_tokens', 'N/A')}")
    else:
        print("No analysis results available.")
    
    print("\n" + "=" * 50)
    print("Analysis complete!")
    print("=" * 50 + "\n")
 """
if __name__ == "__main__":
    main()