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

// CrawlAndExtract parcourt une page web et extrait les éléments pertinents
func CrawlAndExtract(site string) ([]models.PageElement, error) {
    resp, err := http.Get(site)
    if err != nil {
        return nil, fmt.Errorf("erreur lors de la requête: %v", err)
    }
    defer resp.Body.Close()

    baseURL, err := url.Parse(site)
    if err != nil {
        return nil, fmt.Errorf("erreur lors de l'analyse de l'URL: %v", err)
    }

    elements, err := extractPageElements(resp, baseURL)
    if err != nil {
        return nil, fmt.Errorf("erreur lors de l'extraction des éléments: %v", err)
    }

    return elements, nil
}

// extractPageElements extrait tous les éléments d'une page HTML
func extractPageElements(resp *http.Response, baseURL *url.URL) ([]models.PageElement, error) {
    var elements []models.PageElement
    z := html.NewTokenizer(resp.Body)

    var currentForm models.PageElement

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
                    currentForm.CSRFStatus = config.InjectionSQLNonSecurise
                }
                elements = append(elements, currentForm)
                currentForm = models.PageElement{}
            }
        }
    }
}

// extractElement extrait les informations d'un élément HTML spécifique
func extractElement(t html.Token, baseURL *url.URL, currentForm *models.PageElement) []models.PageElement {
    var elements []models.PageElement

    switch t.Data {
    case "a":
        if link := extractLink(t, baseURL); link.ElementType != "" {
            elements = append(elements, link)
        }
    case "form":
        *currentForm = extractForm(t, baseURL)
    case "input", "textarea":
        extractInput(t, currentForm)
    }
    return elements
}

// extractLink extrait les informations d'un lien
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
            if link.RawQuery != "" {
                pageElement.InjectionSQL = config.InjectionSQLAtester
            }
            return pageElement
        }
    }
    return models.PageElement{}
}

// extractForm extrait les informations d'un formulaire
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

// extractInput extrait les informations d'un champ de saisie
func extractInput(t html.Token, currentForm *models.PageElement) {
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
    
    if inputName != "" {
        currentForm.Inputs = append(currentForm.Inputs, inputName)
    }
    
    if isCSRFInput {
        currentForm.CSRFStatus = config.InjectionSQLSecurise
    }
}