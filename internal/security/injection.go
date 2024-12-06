package security

import (
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"

	"SecuScanPro/internal/config"
	models "SecuScanPro/internal/model"
)

// InjectionBDDTest teste les injections SQL sur une liste d'éléments de page.
// Retourne les éléments mis à jour avec le statut d'injection SQL, et un canal de progression pour suivre l'avancement.
func InjectionBDDTest(elements []models.PageElement, progressChan chan float64) ([]models.PageElement, error) {
    // Filtrer les éléments à tester pour les injections SQL
    elementsToTest := make([]models.PageElement, 0)
    for _, el := range elements {
        if el.InjectionSQL == config.InjectionSQLAtester {
            elementsToTest = append(elementsToTest, el)
        }
    }

    // Créer une copie des éléments pour mise à jour
    updatedElements := make([]models.PageElement, len(elements))
    copy(updatedElements, elements)

    // Calculer le nombre total de payloads à tester
    totalPayloads := calculateTotalPayloads(elementsToTest)
    completedPayloads := 0

    // Définir l'ordre des bases de données à tester
    dbmsOrder := []string{"MySQL", "PostgreSQL", "MSSQL", "Oracle"}

    for i, originalEl := range updatedElements {
        // Vérifier si l'élément fait partie de ceux à tester
        shouldTest := false
        for _, testEl := range elementsToTest {
            if testEl.Content == originalEl.Content && testEl.ElementType == originalEl.ElementType {
                shouldTest = true
                break
            }
        }

        if shouldTest {
            wasVulnerable := false

            // Tester en fonction du type d'élément
            switch originalEl.ElementType {
            case "form":
                // Tester chaque formulaire avec les payloads SQL
                for _, dbms := range dbmsOrder {
                    if testFormInputs(&updatedElements[i], config.SQLInjectionPayloads[dbms], &completedPayloads, totalPayloads, progressChan) {
                        wasVulnerable = true
                        break
                    }
                }
                // Si aucun test n'a détecté de vulnérabilité, marquer l'élément comme sécurisé
                if !wasVulnerable {
                    updatedElements[i].InjectionSQL = config.InjectionSQLSecurise
                }

            case "input":
                // Tester chaque champ d'entrée (input) avec les payloads SQL
                for _, dbms := range dbmsOrder {
                    if testSingleInput(&updatedElements[i], config.SQLInjectionPayloads[dbms], &completedPayloads, totalPayloads, progressChan) {
                        wasVulnerable = true
                        break
                    }
                }
                // Si aucun test n'a détecté de vulnérabilité, marquer l'élément comme sécurisé
                if !wasVulnerable {
                    updatedElements[i].InjectionSQL = config.InjectionSQLSecurise
                }
            }
        }
    }

    return updatedElements, nil
}

// testSingleInput teste un seul champ d'entrée pour des vulnérabilités SQLi.
// Retourne vrai si une vulnérabilité est détectée.
func testSingleInput(el *models.PageElement, payloads []string, completedPayloads *int, totalPayloads int, progressChan chan float64) bool {
    // Envoyer une requête initiale pour obtenir une réponse de référence
    initialData := url.Values{}
    initialData.Set(el.Attribute, "test_value")

    initialResp, err := http.PostForm(el.Content, initialData)
    if err != nil {
        log.Printf("Erreur avec la requête initiale : %v", err)
        return false
    }
    defer initialResp.Body.Close()
    initialBody, _ := io.ReadAll(initialResp.Body)
    initialResponse := string(initialBody)

    // Tester chaque payload
    for _, payload := range payloads {
        // Mise à jour de la progression
        *completedPayloads++
        progress := (float64(*completedPayloads) / float64(totalPayloads)) * 100
        progressChan <- math.Round(progress*100) / 100

        // Préparer les données avec le payload
        testData := url.Values{}
        testData.Set(el.Attribute, payload)

        resp, err := http.PostForm(el.Content, testData)
        if err != nil {
            log.Printf("Erreur lors du test du champ %s : %v", el.Attribute, err)
            continue
        }

        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        response := string(body)

        // Détecter si la réponse diffère de la réponse de référence ou contient des indicateurs de succès
        if response != initialResponse || 
           strings.Contains(response, "Login successful") || 
           strings.Contains(response, "Welcome") || 
           strings.Contains(response, "successfully") {
            el.InjectionSQL = config.InjectionSQLNonSecurise
            return true
        }
    }

    // Si aucune vulnérabilité n'a été détectée, marquer l'élément comme sécurisé
    el.InjectionSQL = config.InjectionSQLSecurise
    return false
}

// calculateTotalPayloads calcule le nombre total de payloads à tester pour une liste d'éléments.
func calculateTotalPayloads(elements []models.PageElement) int {
    total := 0
    for _, el := range elements {
        if el.ElementType == "link" {
            // Ajouter tous les payloads pour chaque DBMS
            for _, payloads := range config.SQLInjectionPayloads {
                total += len(payloads)
            }
        } else if el.ElementType == "form" {
            inputCount := len(el.Inputs)
            if inputCount == 0 {
                inputCount = 1
            }
            // Ajouter tous les payloads pour chaque input pour chaque DBMS
            for _, payloads := range config.SQLInjectionPayloads {
                total += len(payloads) * inputCount
            }
        }
    }
    return total
}

// testFormInputs teste les champs d'un formulaire pour des vulnérabilités SQLi.
// Retourne vrai si une vulnérabilité est détectée.
func testFormInputs(el *models.PageElement, payloads []string, completedPayloads *int, totalPayloads int, progressChan chan float64) bool {
    if len(el.Inputs) == 0 {
        el.InjectionSQL = config.InjectionSQLSecurise
        return false
    }

    // Envoyer une requête initiale pour obtenir une réponse de référence
    initialData := url.Values{}
    for _, input := range el.Inputs {
        initialData.Set(input, "test_user")
    }

    initialResp, err := http.PostForm(el.Content, initialData)
    if err != nil {
        log.Printf("Erreur avec la requête initiale : %v", err)
        return false
    }
    defer initialResp.Body.Close()
    initialBody, _ := io.ReadAll(initialResp.Body)
    initialResponse := string(initialBody)

    // Tester chaque champ avec les payloads
    for _, input := range el.Inputs {
        for _, payload := range payloads {
            *completedPayloads++
            progress := (float64(*completedPayloads) / float64(totalPayloads)) * 100
            progressChan <- math.Round(progress*100) / 100

            // Préparer les données avec le payload
            testData := url.Values{}
            testData.Set(input, payload)
            for _, otherInput := range el.Inputs {
                if otherInput != input {
                    testData.Set(otherInput, "test_user")
                }
            }

            resp, err := http.PostForm(el.Content, testData)
            if err != nil {
                log.Printf("Erreur lors du test du champ %s : %v", input, err)
                continue
            }

            body, _ := io.ReadAll(resp.Body)
            resp.Body.Close()
            response := string(body)

            // Détecter si la réponse diffère ou contient des indicateurs de succès
            if response != initialResponse || 
               strings.Contains(response, "Login successful") || 
               strings.Contains(response, "Welcome") || 
               strings.Contains(response, "successfully") {
                el.InjectionSQL = config.InjectionSQLNonSecurise
                progressChan <- 100.0
                return true
            }
        }
    }

    // Si aucune vulnérabilité n'a été détectée, marquer l'élément comme sécurisé
    el.InjectionSQL = config.InjectionSQLSecurise
    return false
}
// urlEncode encode une chaîne de caractères pour l'inclure en toute sécurité dans une URL.
func urlEncode(payload string) string {
    return url.QueryEscape(payload)
}

