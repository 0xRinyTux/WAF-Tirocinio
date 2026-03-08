# Proof of Concept
- Ho realizzato un esempio step by step di come si utilizza il tool
## Startup
- Ho implementato un docker compose per eseguire sia firegex che un servizio vulnerabile tramite XSS e SQLi
![Startup](./immagini/PoC/Startup.JPG)
## Esecuzione script per PoC delle vulnerabilità
![PoC vulns](./immagini/PoC/VulnScript.JPG)
## Come si presenta l'app
- Ora segue una guida Step-by-Step di come creare un filtro regex per bloccare le richieste in entrata
![Index](./immagini/PoC/Index.JPG)
![Settings porta e nome servizio](./immagini/PoC/RegexSettings.JPG)
![Creazione regex](./immagini/PoC/RegexSettings2.JPG)
![Regex per XSS](./immagini/PoC/RegexSettings3.JPG)
## Esecuzione script dopo il blocco XSS
- Ciò che accade all'esecuzione dello script è un blocco della richiesta fino allo scattare del timeout
![XSS Block](./immagini/PoC/VulnXSSBlocked.JPG)
## Implementare una regola tramite script python
- Firegex permette di filtrare il traffico tramite script in python
- Guida step-by-step sul filtraggio su pattern
![Netfilter Proxy](./immagini/PoC/PythonFilter.JPG)
![Settings porta e nome servizio](./immagini/PoC/PythonFilter2.JPG)
![Add Filter](./immagini/PoC/PythonFilter3.JPG)
![Upload Filter](./immagini/PoC/PythonFilter4.JPG)
![Upload File](./immagini/PoC/PythonFilter5.JPG)
![Show code committed](./immagini/PoC/PythonFilter6.JPG)
![PoC SQLi Blocked](./immagini/PoC/VulnSQLIBlocked.JPG)