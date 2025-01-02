🛠️ HeaderHunter
HeaderHunter is a Python-based tool designed to analyze and report on HTTP security headers. It helps identify missing or misconfigured headers on web servers, providing detailed descriptions, recommended configurations, and exportable reports.

![Screenshot](https://github.com/user-attachments/assets/68c0ede6-9433-4708-89e7-e894cfb7089e)

🚀 Features
- Detects key security headers such as X-XSS-Protection, Content-Security-Policy, and Strict-Transport-Security.
- Detailed Findings: Outputs include:
- Description of the header's purpose.
- Recommended mitigation values.
- Scope (URL where the header was analyzed).
- Finding type (e.g., "Present Header" or "Missing Header").
- Customizable Output: Supports color-coded terminal output for better readability.
- Export to JSON: Save the analysis results in JSON format for further processing.
- Proxy Support: Use a proxy for requests.
- Custom Headers: Add custom headers to requests for specific use cases.

📋 Installation
Clone the repository:

```Bash
git clone https://github.com/TrKGOD/headerhunter.git
```

```Bash
cd headerhunter
```

Ensure Python 3 is installed on your system.

Install required dependencies:

```Bash
pip install -r requirements.txt
```

📋 Usage
Run the script using the following syntax:

```Python
python3 headerhunter.py [options] <target>
```
```
Options
-p, --port: Specify a custom port.
-c, --cookie: Add cookies to the request.
-a, --add-header: Add custom headers (e.g., Header: value).
-d, --disable-ssl-check: Disable SSL/TLS validation.
-g, --use-get-method: Use the GET method instead of HEAD.
-m, --use-method: Specify the HTTP method (e.g., POST, PUT).
-j, --json-output: Output results in JSON format.
--proxy: Use a proxy (e.g., http://127.0.0.1:8080).
--hfile: Load a list of targets from a file.
--colours: Set color profile (dark, light, none).
```

✨ Example
Analyze a single target with colorized output:

```Python
python3 headerhunter.py -p 443 https://example.com
```

Analyze multiple targets from a file and export results to JSON:

```Python
python3 headerhunter.py --hfile targets.txt -j > results.json
```

📄 License
This project is licensed under the GNU General Public License, as per the original tool.

🤝 Credits
Original tool: shcheck by Santoru.

