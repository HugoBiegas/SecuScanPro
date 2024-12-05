// internal/models/models.go
package models

// PageElement représente un élément de page HTML avec ses attributs de sécurité
type PageElement struct {
    ElementType  string   `json:"element_type"` // "form", "link", "input", "textarea", etc.
    Attribute    string   `json:"attribute"`    // Attribut de l'élément, par ex. action pour les forms
    Content      string   `json:"content"`      // Contenu de l'attribut
    Inputs       []string `json:"inputs,omitempty"` // Champs input pour chaque formulaire
    CSRFStatus   string   `json:"csrf_status,omitempty"` // Statut CSRF : Sécurisé ou Non sécurisé
    InjectionSQL string   `json:"injection_sql,omitempty"` // Statut de vulnérabilité aux injections SQL
}

// SecurityReport représente un rapport complet de scan de sécurité
type SecurityReport struct {
    ID      string        `json:"id"`      // Identifiant unique du rapport
    URL     string        `json:"url"`     // URL scannée
    Date    string        `json:"date"`    // Date du scan
    Results []PageElement `json:"results"` // Résultats du scan
}