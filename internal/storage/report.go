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
)

// Initialize vérifie et crée le répertoire pour les rapports de sécurité si nécessaire.
func Initialize() error {
    reportsDir := strings.Split(config.SecurityReportsFileName, "/")[0]
    if _, err := os.Stat(reportsDir); os.IsNotExist(err) {
        if err := os.Mkdir(reportsDir, 0755); err != nil {
            return fmt.Errorf("erreur lors de la création du répertoire: %v", err)
        }
    }
    return nil
}

// SaveReport enregistre un rapport de sécurité au format JSON dans un fichier.
func SaveReport(report models.SecurityReport) error {
    fileName := fmt.Sprintf(config.SecurityReportsFileName, report.ID)
    data, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        return fmt.Errorf("erreur lors de la conversion en JSON: %v", err)
    }
    if err := os.WriteFile(fileName, data, 0644); err != nil {
        return fmt.Errorf("erreur lors de l'écriture du fichier: %v", err)
    }
    return nil
}

// LoadReportByID charge un rapport de sécurité à partir de son ID.
func LoadReportByID(scanID string) (*models.SecurityReport, error) {
    fileName := fmt.Sprintf(config.SecurityReportsFileName, scanID)
    data, err := os.ReadFile(fileName)
    if err != nil {
        return nil, fmt.Errorf("erreur lors de la lecture du fichier JSON pour l'ID %s: %v", scanID, err)
    }
    var report models.SecurityReport
    if err := json.Unmarshal(data, &report); err != nil {
        return nil, fmt.Errorf("erreur lors du parsing du fichier JSON pour l'ID %s: %v", scanID, err)
    }
    return &report, nil
}

// filterElementsToTest retourne une liste d'éléments devant être testés selon des critères définis.
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

// UpdateReportResults met à jour les résultats d'un rapport avec des éléments actualisés.
func UpdateReportResults(report *models.SecurityReport, updatedElements []models.PageElement) {
    for i, el := range report.Results {
        for _, updatedEl := range updatedElements {
            if el.Content == updatedEl.Content && el.ElementType == updatedEl.ElementType {
                report.Results[i] = updatedEl
            }
        }
    }
}

// ListReports retourne tous les rapports de sécurité disponibles, triés par date décroissante.
func ListReports() ([]models.SecurityReport, error) {
    var reports []models.SecurityReport
    files, err := os.ReadDir("reports")
    if err != nil {
        return nil, fmt.Errorf("erreur lors de la lecture du dossier reports: %v", err)
    }
    for _, file := range files {
        if strings.HasSuffix(file.Name(), ".json") {
            scanID := strings.TrimPrefix(file.Name(), "report_")
            scanID = strings.TrimSuffix(scanID, ".json")
            report, err := LoadReportByID(scanID)
            if err != nil {
                log.Printf("Erreur lors du chargement du rapport %s: %v", scanID, err)
                continue
            }
            reports = append(reports, *report)
        }
    }
    if len(reports) == 0 {
        return nil, fmt.Errorf("aucun rapport trouvé dans le dossier reports")
    }
    sort.Slice(reports, func(i, j int) bool {
        timeI, errI := time.Parse("2006-01-02 15:04:05", reports[i].Date)
        timeJ, errJ := time.Parse("2006-01-02 15:04:05", reports[j].Date)
        if errI != nil {
            return false
        }
        if errJ != nil {
            return true
        }
        return timeI.After(timeJ)
    })
    return reports, nil
}

// generateID génère un ID unique basé sur l'horodatage actuel.
func generateID() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}

// DisplayReport affiche un rapport de sécurité de manière lisible dans la console.
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
