
# Security Scanner Project

This Go project is a security scanner that crawls a given URL to analyze HTML elements such as forms, links, and inputs for potential vulnerabilities, including SQL injection and CSRF protection status.

## Features

- **Crawl and Extract**: Extracts forms, links, inputs, and other HTML elements from a webpage.
- **CSRF Detection**: Identifies whether forms are protected against CSRF attacks by checking for CSRF tokens.
- **SQL Injection Testing**: Injects payloads into form fields and URL parameters to test for SQL injection vulnerabilities across various database management systems (MySQL, PostgreSQL, MSSQL, Oracle).
- **Report Generation**: Generates and saves a JSON report containing the scan results, including identified vulnerabilities.
- **Dynamic URL Testing**: Automatically extracts parameters from URLs and tests each for vulnerabilities.

## Getting Started

### Prerequisites

Ensure that you have the following installed:

- **Go** (1.16 or higher)

### Project Setup

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/security-scanner.git
   cd security-scanner
   ```

2. **Initialize a Go Module:**

   Run the following command to initialize the Go module for the project:

   ```bash
   go mod init security-scanner
   ```

3. **Install Dependencies:**

   Fetch the required package `golang.org/x/net/html` by running:

   ```bash
   go get golang.org/x/net/html
   ```

### Running the Scanner

To run the main program and start scanning websites for vulnerabilities, execute the following command:

```bash
go run .\crawler.go
```

### Usage Instructions

1. **Analyze a Website:**
   - When prompted, input a valid URL (beginning with http:// or https://) to analyze. The scanner will extract HTML elements (such as forms, inputs) and test for vulnerabilities like SQL injection and CSRF.

2. **View Reports:**
   - You can retrieve a security report by providing the unique scan ID generated during the analysis.
   
3. **Test for SQL Injections:**
   - You can test previous reports for SQL injection vulnerabilities by providing the scan ID.

### Example

```bash
> go run main.go
Tapez 1 pour analyser un site, 2 pour extraire les rapports de sécurité ou 3 pour tester une faille d'injection sur un report :
1
Entrez le lien du site à analyser (avec http:// ou https://) :
http://example.com
Analyse terminée avec succès. ID du scan : scan-1632339128997
```

### Directory Structure

```
security-scanner/
│
├── crawler.go            # Entry point for the scanner
├── security_reports.json # JSON file containing scan reports
├── README.md          # Project documentation
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
