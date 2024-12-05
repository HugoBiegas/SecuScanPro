// internal/storage/report.go
package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"SecuScanPro/internal/config"
	models "SecuScanPro/internal/model"
	"SecuScanPro/internal/security"
)

// Initialize crée le dossier reports s'il n'existe pas
func Initialize() error {
    reportsDir := strings.Split(config.SecurityReportsFileName, "/")[0]
    if _, err := os.Stat(reportsDir); os.IsNotExist(err) {
        err := os.Mkdir(reportsDir, 0755)
        if err != nil {
            return fmt.Errorf("erreur lors de la création du répertoire: %v", err)
        }
    }
    return nil
}

// SaveReport sauvegarde un rapport de sécurité en JSON
func SaveReport(report models.SecurityReport) error {
    fileName := fmt.Sprintf(config.SecurityReportsFileName, report.ID)
    
    data, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        return fmt.Errorf("erreur lors de la conversion en JSON: %v", err)
    }

    err = os.WriteFile(fileName, data, 0644)
    if err != nil {
        return fmt.Errorf("erreur lors de l'écriture du fichier: %v", err)
    }

    return nil
}

// LoadReportByID charge un rapport de sécurité à partir de son ID
func LoadReportByID(scanID string) (*models.SecurityReport, error) {
    fileName := fmt.Sprintf(config.SecurityReportsFileName, scanID)
    
    data, err := os.ReadFile(fileName)
    if err != nil {
        return nil, fmt.Errorf("erreur lors de la lecture du fichier JSON pour l'ID %s: %v", scanID, err)
    }

    var report models.SecurityReport
    err = json.Unmarshal(data, &report)
    if err != nil {
        return nil, fmt.Errorf("erreur lors du parsing du fichier JSON pour l'ID %s: %v", scanID, err)
    }

    return &report, nil
}

// ExtractReportByID extrait et traite un rapport spécifique
func ExtractReportByID(scanID string, typeSecuScan int) error {
    report, err := LoadReportByID(scanID)
    if err != nil {
        return fmt.Errorf("error loading report: %v", err)
    }

    if typeSecuScan == 0 {
        elementsToTest := filterElementsToTest(report.Results)
        fmt.Printf("Elements to test for SQL Injection: %d\n", len(elementsToTest))

        progressChan := make(chan float64)
        updatedElements, err := security.InjectionBDDTest(elementsToTest, progressChan)
        if err != nil {
            return fmt.Errorf("error testing for SQL Injection: %v", err)
        }

        updateReportResults(report, updatedElements)

        if err := SaveReport(*report); err != nil {
            return fmt.Errorf("error saving updated report: %v", err)
        }
    }

    return nil
}

// filterElementsToTest filtre les éléments à tester
func filterElementsToTest(elements []models.PageElement) []models.PageElement {
    var elementsToTest []models.PageElement
    for _, el := range elements {
        if el.InjectionSQL == config.InjectionSQLAtester || 
           el.InjectionSQL == config.InjectionSQLSecurise || 
           el.InjectionSQL == config.InjectionSQLNonSecurise {
            elementsToTest = append(elementsToTest, el)
        }
    }
    return elementsToTest
}

// updateReportResults met à jour les résultats du rapport
func updateReportResults(report *models.SecurityReport, updatedElements []models.PageElement) {
    for i, el := range report.Results {
        for _, updatedEl := range updatedElements {
            if el.Content == updatedEl.Content && el.ElementType == updatedEl.ElementType {
                report.Results[i] = updatedEl
            }
        }
    }
}

func ListReports() ([]models.SecurityReport, error) {
    var reports []models.SecurityReport

    // Lire le dossier reports
    files, err := os.ReadDir("reports")
    if err != nil {
        return nil, fmt.Errorf("erreur lors de la lecture du dossier reports: %v", err)
    }

    // Pour chaque fichier dans le dossier
    for _, file := range files {
        // Vérifier si c'est un fichier JSON
        if strings.HasSuffix(file.Name(), ".json") {
            // Extraire l'ID du scan du nom du fichier
            // Le format est "report_[ID].json"
            scanID := strings.TrimPrefix(file.Name(), "report_")
            scanID = strings.TrimSuffix(scanID, ".json")

            // Charger le rapport
            report, err := LoadReportByID(scanID)
            if err != nil {
                // Log l'erreur mais continue avec les autres fichiers
                log.Printf("Erreur lors du chargement du rapport %s: %v", scanID, err)
                continue
            }

            // Ajouter le rapport à la liste
            reports = append(reports, *report)
        }
    }

    // Si aucun rapport n'est trouvé, retourner une erreur spécifique
    if len(reports) == 0 {
        return nil, fmt.Errorf("aucun rapport trouvé dans le dossier reports")
    }

    // Trier les rapports par date (du plus récent au plus ancien)
    sort.Slice(reports, func(i, j int) bool {
        timeI, errI := time.Parse("2006-01-02 15:04:05", reports[i].Date)
        timeJ, errJ := time.Parse("2006-01-02 15:04:05", reports[j].Date)
        
        // En cas d'erreur de parsing des dates, mettre ces éléments à la fin
        if errI != nil {
            return false
        }
        if errJ != nil {
            return true
        }
        
        // Trier par date décroissante (plus récent en premier)
        return timeI.After(timeJ)
    })

    return reports, nil
}

func generateID() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}


// DisplayReport affiche le contenu d'un rapport
func DisplayReport(report *models.SecurityReport) {
    fmt.Printf("ID du scan : %s\n", report.ID)
    fmt.Printf("URL : %s\n", report.URL)
    fmt.Printf("Date : %s\n", report.Date)
    fmt.Println("Résultats :")
    
    for _, el := range report.Results {
        fmt.Printf("\nType d'élément : %s\n", el.ElementType)
        fmt.Printf("Attribut : %s\n", el.Attribute)
        fmt.Printf("Contenu : %s\n", el.Content)
        if el.ElementType == "form" {
            fmt.Printf("Champs d'entrée : %v\n", el.Inputs)
            fmt.Printf("Statut CSRF : %s\n", el.CSRFStatus)
        }
        if el.InjectionSQL != "" {
            fmt.Printf("Statut Injection SQL : %s\n", el.InjectionSQL)
        }
        fmt.Println("----")
    }
}