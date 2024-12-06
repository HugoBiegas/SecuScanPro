// internal/crawler/crawler.go
package crawler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"SecuScanPro/internal/config"
	"SecuScanPro/internal/model"

	"golang.org/x/net/html"
)

// CrawlAndExtract effectue une requête HTTP GET sur un site donné,
// analyse le contenu HTML et extrait les éléments intéressants (liens, formulaires, etc.).
// Retourne une liste d'éléments ou une erreur.
func CrawlAndExtract(site string) ([]models.PageElement, error) {
    // Envoyer une requête HTTP GET au site cible
    resp, err := http.Get(site)
    if err != nil {
        return nil, fmt.Errorf("erreur lors de la requête: %v", err)
    }
    defer resp.Body.Close()

    // Analyser l'URL de base du site
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

// extractPageElements parcourt le contenu HTML d'une réponse HTTP pour extraire les éléments pertinents.
// Utilise un tokenizer pour analyser les balises HTML.
func extractPageElements(resp *http.Response, baseURL *url.URL) ([]models.PageElement, error) {
    var elements []models.PageElement
    z := html.NewTokenizer(resp.Body)
    var currentForm models.PageElement

    for {
        tt := z.Next()
        switch tt {
        case html.ErrorToken:
            // Retourne les éléments extraits lorsqu'il n'y a plus de contenu à analyser
            return elements, nil
        case html.StartTagToken, html.SelfClosingTagToken:
            // Extraire les éléments intéressants (liens, formulaires, etc.)
            t := z.Token()
            elements = append(elements, extractElement(t, baseURL, &currentForm)...)
        case html.EndTagToken:
            // Si une balise de formulaire se termine, ajouter le formulaire extrait
            t := z.Token()
            if t.Data == "form" {
                if currentForm.CSRFStatus == "" {
                    currentForm.CSRFStatus = config.InjectionSQLNonSecurise
                }
                elements = append(elements, currentForm)
                currentForm = models.PageElement{}
            }
        }
    }
}

// extractElement identifie et extrait les éléments spécifiques (liens, formulaires, champs d'entrée).
// Retourne une liste d'éléments extraits.
func extractElement(t html.Token, baseURL *url.URL, currentForm *models.PageElement) []models.PageElement {
    var elements []models.PageElement

    switch t.Data {
    case "a":
        // Extraire les liens (<a>)
        if link := extractLink(t, baseURL); link.ElementType != "" {
            elements = append(elements, link)
        }
    case "form":
        // Extraire un formulaire (<form>)
        *currentForm = extractForm(t, baseURL)
    case "input", "textarea":
        // Extraire les champs d'entrée (<input>, <textarea>)
        extractInput(t, currentForm)
    }
    return elements
}

// extractLink extrait un élément de type lien (<a>).
// Retourne un élément contenant le lien et son attribut "href".
func extractLink(t html.Token, baseURL *url.URL) models.PageElement {
    for _, attr := range t.Attr {
        if attr.Key == "href" {
            link, err := baseURL.Parse(attr.Val)
            if err != nil {
                continue
            }
            pageElement := models.PageElement{
                ElementType: "link",
                Attribute:   "href",
                Content:     link.String(),
            }
            // Marquer les liens avec des paramètres comme à tester pour SQLi
            if link.RawQuery != "" {
                pageElement.InjectionSQL = config.InjectionSQLAtester
            }
            return pageElement
        }
    }
    return models.PageElement{}
}

// extractForm extrait un formulaire (<form>).
// Retourne un élément contenant l'attribut "action" et les informations associées.
func extractForm(t html.Token, baseURL *url.URL) models.PageElement {
    form := models.PageElement{
        ElementType:  "form",
        Attribute:    "action",
        InjectionSQL: config.InjectionSQLAtester,
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

// extractInput extrait les informations des champs d'entrée (<input>, <textarea>)
// et les ajoute à l'objet formulaire en cours de traitement.
func extractInput(t html.Token, currentForm *models.PageElement) {
    inputName := ""
    isCSRFInput := false

    for _, attr := range t.Attr {
        if attr.Key == "name" {
            inputName = attr.Val
            // Identifier les champs potentiellement liés à la protection CSRF
            if strings.Contains(strings.ToLower(inputName), "csrf") {
                isCSRFInput = true
            }
        }
    }

    if inputName != "" {
        // Ajouter le champ d'entrée au formulaire
        currentForm.Inputs = append(currentForm.Inputs, inputName)
    }

    if isCSRFInput {
        // Marquer le formulaire comme protégé si un champ CSRF est trouvé
        currentForm.CSRFStatus = config.InjectionSQLSecurise
    }
}
