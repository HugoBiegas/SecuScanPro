package ui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"SecuScanPro/internal/crawler"
	models "SecuScanPro/internal/model"
	"SecuScanPro/internal/security"
	"SecuScanPro/internal/storage"
)


func RunGUI() {
    myApp := app.New()
    window := myApp.NewWindow("SecuScanPro")
    window.Resize(fyne.NewSize(400, 200))

    // Création des composants principaux
    urlEntry := widget.NewEntry()
    urlEntry.SetPlaceHolder("Entrez l'URL du site (http:// ou https://)")

    // Bouton d'analyse de site
    analyzeButton := widget.NewButtonWithIcon("Analyser un site", theme.SearchIcon(), func() {
        handleSiteAnalysisGUI(window, urlEntry.Text)
    })

    // Bouton pour voir les rapports
    viewReportsButton := widget.NewButtonWithIcon("Voir les rapports", theme.FolderOpenIcon(), func() {
        showReportsList(window)
    })

    // Bouton pour les tests d'injection SQL
    sqlTestButton := widget.NewButtonWithIcon("Test d'injection SQL", theme.WarningIcon(), func() {
        showSQLInjectionReportsList(window)
    })

    // Layout principal
    content := container.NewVBox(
        widget.NewLabel("SecuScanPro - Scanner de sécurité web"),
        urlEntry,
        analyzeButton,
        viewReportsButton,
        sqlTestButton,
    )

    window.SetContent(content)
    window.ShowAndRun()
}

func handleSiteAnalysisGUI(window fyne.Window, url string) {
    if url == "" || (!strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://")) {
        dialog.ShowError(fmt.Errorf("URL invalide. Veuillez entrer une URL commençant par http:// ou https://"), window)
        return
    }

    // Lancer l'analyse dans une goroutine
    go func() {
        elements, err := crawler.CrawlAndExtract(url)
        if err != nil {
            dialog.ShowError(err, window)
            return
        }

        report := models.SecurityReport{
            ID:      generateID(),
            URL:     url,
            Date:    time.Now().Format("2006-01-02 15:04:05"),
            Results: elements,
        }

        err = storage.SaveReport(report)
        if err != nil {
            dialog.ShowError(err, window)
            return
        }

        dialog.ShowInformation("Succès", 
            fmt.Sprintf("Analyse terminée avec succès.\nID du scan : %s\nNombre d'éléments analysés : %d", 
                report.ID, len(elements)), window)
    }()
}


func generateID() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}


func showReportsList(window fyne.Window) {
    reports, err := storage.ListReports()
    if err != nil {
        dialog.ShowError(err, window)
        return
    }

    // Créer une nouvelle fenêtre pour la liste des rapports
    reportsWindow := fyne.CurrentApp().NewWindow("Rapports disponibles")
    reportsWindow.Resize(fyne.NewSize(800, 400)) // Fenêtre plus grande

    list := widget.NewList(
        func() int { return len(reports) },
        func() fyne.CanvasObject {
            return container.NewHBox(
                widget.NewLabel("Template"),
                layout.NewSpacer(),
            )
        },
        func(id widget.ListItemID, object fyne.CanvasObject) {
            box := object.(*fyne.Container)
            label := box.Objects[0].(*widget.Label)
            report := reports[id]
            label.SetText(fmt.Sprintf("Scan ID: %s - Date: %s - URL: %s", 
                report.ID, report.Date, report.URL))
        },
    )

    list.OnSelected = func(id widget.ListItemID) {
        showReportDetails(reportsWindow, reports[id])
    }

    // Ajouter un bouton de fermeture
    closeButton := widget.NewButton("Fermer", func() {
        reportsWindow.Close()
    })

    content := container.NewBorder(
        nil, 
        container.NewHBox(layout.NewSpacer(), closeButton, layout.NewSpacer()), 
        nil, 
        nil, 
        container.NewScroll(list),
    )

    reportsWindow.SetContent(content)
    reportsWindow.Show()
}

func showReportDetails(_ fyne.Window, report models.SecurityReport) {
    window := fyne.CurrentApp().NewWindow("Détails du rapport")
    window.Resize(fyne.NewSize(800, 600))

    header := container.NewVBox(
        widget.NewLabelWithStyle("Informations du Rapport", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
        widget.NewLabel(fmt.Sprintf("ID: %s", report.ID)),
        widget.NewLabel(fmt.Sprintf("URL: %s", report.URL)),
        widget.NewLabel(fmt.Sprintf("Date: %s", report.Date)),
    )

    secureSQL := 0
    insecureSQL := 0
    toTestSQL := 0
    secureCSRF := 0
    insecureCSRF := 0

    resultsList := container.NewVBox()
    
    for _, result := range report.Results {
        hasInsecure := false
        
        if result.InjectionSQL == "Sécurisé" {
            secureSQL++
        } else if result.InjectionSQL == "A tester" {
            toTestSQL++
            hasInsecure = true
        } else if result.InjectionSQL != "" {
            insecureSQL++
            hasInsecure = true
        }
        
        if result.CSRFStatus == "Sécurisé" {
            secureCSRF++
        } else if result.CSRFStatus != "" {
            insecureCSRF++
            hasInsecure = true
        }

        buttonIcon := theme.MoreVerticalIcon()
        if result.InjectionSQL == "A tester" {
            buttonIcon = theme.QuestionIcon()
        } else if hasInsecure {
            buttonIcon = theme.WarningIcon()
        }
        
        expandBtn := widget.NewButtonWithIcon(
            fmt.Sprintf("Type: %s", result.ElementType),
            buttonIcon,
            nil,
        )
        
        details := container.NewVBox(
            widget.NewLabel(fmt.Sprintf("Attribut: %s", result.Attribute)),
            widget.NewLabel(fmt.Sprintf("Contenu: %s", result.Content)),
        )
        
        if result.InjectionSQL != "" {
            securityStatus := container.NewHBox(
                widget.NewLabel("Injection SQL:"),
                widget.NewIcon(theme.WarningIcon()),
                widget.NewLabel(result.InjectionSQL),
            )
            if result.InjectionSQL == "Sécurisé" {
                securityStatus.Objects[1] = widget.NewIcon(theme.ConfirmIcon())
            } else if result.InjectionSQL == "A tester" {
                securityStatus.Objects[1] = widget.NewIcon(theme.QuestionIcon())
            }
            details.Add(securityStatus)
        }

        if result.CSRFStatus != "" {
            csrfStatus := container.NewHBox(
                widget.NewLabel("CSRF Status:"), 
                widget.NewIcon(theme.WarningIcon()),
                widget.NewLabel(result.CSRFStatus),
            )
            if result.CSRFStatus == "Sécurisé" {
                csrfStatus.Objects[1] = widget.NewIcon(theme.ConfirmIcon())
            }
            details.Add(csrfStatus)
        }

        details.Hide()
        
        expandBtn.OnTapped = func() {
            if details.Visible() {
                details.Hide()
                if result.InjectionSQL == "A tester" {
                    expandBtn.SetIcon(theme.QuestionIcon())
                } else if hasInsecure {
                    expandBtn.SetIcon(theme.WarningIcon())
                } else {
                    expandBtn.SetIcon(theme.MoreVerticalIcon())
                }
            } else {
                details.Show()  
                expandBtn.SetIcon(theme.MenuDropDownIcon())
            }
        }

        resultBox := container.NewVBox(expandBtn, details)
        resultsList.Add(container.NewVBox(resultBox, widget.NewSeparator()))
    }

    statsContainer := container.NewGridWithColumns(2,
        container.NewVBox(
            widget.NewLabelWithStyle("CSRF Protection", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
            widget.NewLabel(fmt.Sprintf("Total: %d", secureCSRF + insecureCSRF)),
            container.NewHBox(
                widget.NewIcon(theme.ConfirmIcon()),
                widget.NewLabel(fmt.Sprintf("Sécurisé: %d", secureCSRF)),
            ),
            container.NewHBox(
                widget.NewIcon(theme.WarningIcon()),
                widget.NewLabel(fmt.Sprintf("Non sécurisé: %d", insecureCSRF)),
            ),
        ),
        container.NewVBox(
            widget.NewLabelWithStyle("Protection Injection SQL", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
            widget.NewLabel(fmt.Sprintf("Total: %d", secureSQL + insecureSQL + toTestSQL)),
            container.NewHBox(
                widget.NewIcon(theme.ConfirmIcon()),
                widget.NewLabel(fmt.Sprintf("Sécurisé: %d", secureSQL)),
            ),
            container.NewHBox(
                widget.NewIcon(theme.WarningIcon()),
                widget.NewLabel(fmt.Sprintf("Non sécurisé: %d", insecureSQL)),
            ),
            container.NewHBox(
                widget.NewIcon(theme.QuestionIcon()),
                widget.NewLabel(fmt.Sprintf("A tester: %d", toTestSQL)),
            ),
        ),
    )

    content := container.NewBorder(
        container.NewVBox(header, widget.NewSeparator(), statsContainer, widget.NewSeparator()),
        widget.NewButton("Fermer", func() { window.Close() }),
        nil, nil,
        container.NewScroll(resultsList),
    )
    window.SetContent(content)
    window.Show()
}

func showSQLInjectionReportsList(window fyne.Window) {
    reports, err := storage.ListReports()
    if err != nil {
        dialog.ShowError(err, window)
        return
    }

    // Créer une nouvelle fenêtre pour la liste des rapports
    sqlReportsWindow := fyne.CurrentApp().NewWindow("Tests d'injection SQL - Sélection du rapport")
    sqlReportsWindow.Resize(fyne.NewSize(800, 400))

    list := widget.NewList(
        func() int { return len(reports) },
        func() fyne.CanvasObject {
            return container.NewHBox(
                widget.NewLabel("Template"),
                layout.NewSpacer(),
            )
        },
        func(id widget.ListItemID, object fyne.CanvasObject) {
            box := object.(*fyne.Container)
            label := box.Objects[0].(*widget.Label)
            report := reports[id]
            label.SetText(fmt.Sprintf("Scan ID: %s - Date: %s - URL: %s", 
                report.ID, report.Date, report.URL))
        },
    )

    list.OnSelected = func(id widget.ListItemID) {
        launchSQLInjectionTest(sqlReportsWindow, reports[id])
    }

    // Ajouter un bouton de fermeture
    closeButton := widget.NewButton("Fermer", func() {
        sqlReportsWindow.Close()
    })

    content := container.NewBorder(
        nil,
        container.NewHBox(layout.NewSpacer(), closeButton, layout.NewSpacer()),
        nil,
        nil,
        container.NewScroll(list),
    )

    sqlReportsWindow.SetContent(content)
    sqlReportsWindow.Show()
}

func launchSQLInjectionTest(_ fyne.Window, report models.SecurityReport) {
    testWindow := fyne.CurrentApp().NewWindow("Test d'injection SQL")
    testWindow.Resize(fyne.NewSize(800, 600))

    resultsText := widget.NewTextGrid()
    progress := widget.NewProgressBar()
    progress.Max = 100
    
    progressChan := make(chan float64)

    go func() {
        resultsText.SetText(fmt.Sprintf("Début des tests d'injection SQL pour le scan %s...\n", report.ID))
        
        // Goroutine pour la mise à jour de la progression
        go func() {
            for percentage := range progressChan {
                progress.SetValue(percentage)
                resultsText.SetText(fmt.Sprintf("Tests en cours... %.0f%%", percentage))
            }
        }()

        updatedElements, err := security.InjectionBDDTest(report.Results, progressChan)
        close(progressChan)

        if err != nil {
            resultsText.SetText(fmt.Sprintf("Erreur lors des tests : %v", err))
            return
        }

        // Mise à jour et sauvegarde du rapport
        report.Results = updatedElements
        if err := storage.SaveReport(report); err != nil {
            resultsText.SetText(fmt.Sprintf("Erreur lors de la sauvegarde : %v", err))
            return
        }

        resultsText.SetText(fmt.Sprintf("Tests terminés avec succès\nID: %s\nURL: %s\nDate: %s\nRapport mis à jour.", 
            report.ID, report.URL, report.Date))
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
