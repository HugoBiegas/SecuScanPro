package main

import (
	"SecuScanPro/internal/storage"
	"SecuScanPro/internal/ui"
	"log"
)

func main() {
    // Initialize storage
    if err := storage.Initialize(); err != nil {
        log.Fatalf("Erreur d'initialisation: %v", err)
    }

    ui.RunGUI()
}