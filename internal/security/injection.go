package security

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"SecuScanPro/internal/config"
	models "SecuScanPro/internal/model"
)

func launchSQLInjectionTest(_ fyne.Window, report models.SecurityReport) {
   testWindow := fyne.CurrentApp().NewWindow("Test d'injection SQL")
   testWindow.Resize(fyne.NewSize(800, 600))

   resultsText := widget.NewTextGrid()
   progress := widget.NewProgressBar()
   progress.Max = 100
   
   progressChan := make(chan float64)

   go func() {
       resultsText.SetText(fmt.Sprintf("Début des tests d'injection SQL pour le scan %s...\n", report.ID))
       
       go func() {
           for percentage := range progressChan {
               progress.SetValue(percentage)
               resultsText.SetText(fmt.Sprintf("Tests en cours... %.0f%%", percentage))
           }
       }()

       updatedElements, err := InjectionBDDTest(report.Results, progressChan)
       close(progressChan)

       if err != nil {
           resultsText.SetText(fmt.Sprintf("Erreur lors des tests : %v", err))
       } else {
           report.Results = updatedElements
           resultsText.SetText(fmt.Sprintf("Tests terminés avec succès\nID: %s\nURL: %s\nDate: %s", 
               report.ID, report.URL, report.Date))
       }
   }()

   closeButton := widget.NewButton("Fermer", func() {
       testWindow.Close()
   })

   content := container.NewBorder(
       container.NewVBox(
           widget.NewLabel("Test d'injection SQL en cours"),
           progress,
       ),
       container.NewHBox(layout.NewSpacer(), closeButton, layout.NewSpacer()),
       nil,
       nil,
       container.NewScroll(resultsText),
   )

   testWindow.SetContent(content)
   testWindow.Show()
}

func InjectionBDDTest(elements []models.PageElement, progressChan chan float64) ([]models.PageElement, error) {
    detectedVulnDBMS := ""
    totalPayloads := calculateTotalPayloads(elements)
    completedPayloads := 0

    for i, el := range elements {
        dbmsToTest := getDBMSToTest(detectedVulnDBMS)
        for _, dbms := range dbmsToTest {
            payloads := config.SQLInjectionPayloads[dbms]
            if el.ElementType == "link" {
                updatedEl, vulnerable := testSQLInjection(el, dbms, payloads, testSQLInjectionInURL, &completedPayloads, totalPayloads, progressChan)
                elements[i] = updatedEl
                if vulnerable {
                    detectedVulnDBMS = dbms
                    break
                }
            } else if el.ElementType == "form" {
                formVulnerable := testFormInputs(el, dbms, payloads, &completedPayloads, totalPayloads, progressChan)
                if !formVulnerable {
                    elements[i].InjectionSQL = config.InjectionSQLSecurise
                }
            }
        }
    }

    displayTestResults(elements)
    return elements, nil
}

func calculateTotalPayloads(elements []models.PageElement) int {
    totalPayloads := 0
    for _, el := range elements {
        if el.ElementType == "link" || el.ElementType == "form" {
            for dbms := range config.SQLInjectionPayloads {
                totalPayloads += len(config.SQLInjectionPayloads[dbms])
            }
        }
    }
    return totalPayloads
}

func getDBMSToTest(detectedVulnDBMS string) []string {
    if detectedVulnDBMS == "" {
        dbmsToTest := []string{}
        for dbms := range config.SQLInjectionPayloads {
            dbmsToTest = append(dbmsToTest, dbms)
        }
        return dbmsToTest
    }
    return []string{detectedVulnDBMS}
}

func testSQLInjection(el models.PageElement, dbms string, payloads []string, testFunc func(models.PageElement, string, string) (bool, error), completedPayloads *int, totalPayloads int, progressChan chan float64) (models.PageElement, bool) {
    for _, payload := range payloads {
        vulnerable, err := testFunc(el, dbms, payload)
        if err != nil {
            log.Printf("Error during SQLi test: %v\n", err)
            continue
        }
        *completedPayloads++
        progress := float64(*completedPayloads) / float64(totalPayloads) * 100
        progressChan <- progress

        if vulnerable {
            el.InjectionSQL = config.InjectionSQLNonSecurise
            return el, true
        }
    }
    el.InjectionSQL = config.InjectionSQLSecurise
    return el, false
}

func testFormInputs(el models.PageElement, dbms string, payloads []string, completedPayloads *int, totalPayloads int, progressChan chan float64) bool {
    formVulnerable := false
    for range el.Inputs {
        _, vulnerable := testSQLInjection(el, dbms, payloads, testSQLInjectionInForm, completedPayloads, totalPayloads, progressChan)
        if vulnerable {
            formVulnerable = true
        }
    }
    return formVulnerable
}

 
func testSQLInjectionInURL(el models.PageElement, dbms, payload string) (bool, error) {
   parsedURL, err := url.Parse(el.Content)
   if err != nil {
       return false, fmt.Errorf("error parsing URL: %v", err)
   }

   params := parsedURL.Query()
   for paramName := range params {
       params.Set(paramName, urlEncode(payload))
       parsedURL.RawQuery = params.Encode()
       injectedURL := parsedURL.String()

       fmt.Printf("Testing URL: %s with payload: %s\n", injectedURL, payload)

       resp, err := http.Get(injectedURL)
       if err != nil {
           return false, fmt.Errorf("error during GET request: %v", err)
       }
       defer resp.Body.Close()

       if isVulnerable(resp) {
           return true, nil
       }
   }

   return false, nil
}

func testSQLInjectionInForm(el models.PageElement, dbms, payload string) (bool, error) {
   postData := fmt.Sprintf("%s=%s", el.Content, urlEncode(payload))
   
   fmt.Printf("Testing form action: %s with payload: %s\n", el.Content, payload)

   resp, err := http.Post(el.Content, "application/x-www-form-urlencoded", strings.NewReader(postData))
   if err != nil {
       return false, fmt.Errorf("error during POST request: %v", err)
   }
   defer resp.Body.Close()

   return isVulnerable(resp), nil
}

func isVulnerable(resp *http.Response) bool {
   if resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusServiceUnavailable {
       return true
   }

   body, err := io.ReadAll(resp.Body)
   if err != nil {
       return false
   }

   bodyStr := string(body)
   return strings.Contains(bodyStr, "SQL syntax") || 
          strings.Contains(bodyStr, "database error") || 
          strings.Contains(bodyStr, "unclosed quotation mark")
}

func urlEncode(payload string) string {
   return url.QueryEscape(payload)
}

func displayTestResults(elements []models.PageElement) {
   fmt.Println("\nSQL Injection testing completed.")
   fmt.Println("=================================")
   fmt.Println("Results:")
   for _, el := range elements {
       fmt.Printf("Element: %s (Type: %s, Injection: %s)\n", 
           el.Content, el.ElementType, el.InjectionSQL)
   }
   fmt.Println("=================================")
}