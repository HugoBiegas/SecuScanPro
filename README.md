# SecuScanPro - Analyseur de Sécurité Web Professionnel

SecuScanPro est un outil d'analyse de sécurité web avancé développé en Go, conçu pour identifier automatiquement les vulnérabilités dans les applications web. Il met l'accent sur la détection des injections SQL et la vérification des protections CSRF, tout en offrant une interface graphique moderne et intuitive.

## Caractéristiques Principales

SecuScanPro intègre des fonctionnalités essentielles pour l'analyse de sécurité web :

- Analyse automatique des structures web et détection des points d'entrée sensibles
- Tests d'injection SQL pour MySQL, PostgreSQL, MSSQL et Oracle
- Vérification automatique des protections CSRF dans les formulaires
- Interface graphique moderne développée avec Fyne
- Système de rapports détaillés avec stockage persistant
- Suivi en temps réel de la progression des analyses

## Installation

Pour installer SecuScanPro, assurez-vous d'avoir Go 1.16 ou supérieur installé sur votre système.

```bash
# Cloner le repository
git clone https://github.com/votre-username/SecuScanPro.git

# Accéder au répertoire
cd SecuScanPro

# Installer les dépendances
go mod download

# Compiler le projet
go build
```

## Utilisation

Pour lancer SecuScanPro :

```bash
./SecuScanPro
```

L'interface graphique vous permet de :

1. Analyser un site web en entrant son URL
2. Visualiser les rapports d'analyse précédents
3. Effectuer des tests d'injection SQL spécifiques
4. Consulter les statistiques de sécurité détaillées

## Structure du Projet

```
SecuScanPro/
├── cmd/                    # Point d'entrée de l'application
├── internal/              # Code interne
│   ├── config/           # Configuration et constantes
│   ├── crawler/          # Module d'analyse web
│   ├── model/            # Structures de données
│   ├── security/         # Tests de sécurité
│   ├── storage/          # Gestion des rapports
│   └── ui/              # Interface utilisateur
├── reports/              # Stockage des rapports
└── .gitignore
```

## Dépendances Principales

- [Fyne](https://fyne.io/) - Framework GUI
- golang.org/x/net/html - Parsing HTML
- encoding/json - Gestion des rapports

## Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Forkez le projet
2. Créez votre branche de fonctionnalités
3. Committez vos modifications
4. Poussez vers la branche
5. Ouvrez une Pull Request

## License

Ce projet est sous licence MIT - voir le fichier [LICENSE.md](LICENSE.md) pour plus de détails.

## Contact

Pour toute question ou suggestion, n'hésitez pas à :
- Ouvrir une issue
- Me contacter par email : [votre-email]
- Consulter la documentation complète

## Remerciements

Un grand merci à tous les contributeurs qui ont participé à ce projet, ainsi qu'à la communauté Go pour ses excellentes ressources.