Phishing – Wprowadzenie i Tło Techniczne
1. Czym jest phishing?

Phishing to technika socjotechniczna polegająca na podszywaniu się pod zaufaną instytucję (np. bank, Microsoft, kurier, operator płatności) w celu:

wyłudzenia danych logowania

przejęcia konta

wyłudzenia danych karty płatniczej

dostarczenia złośliwego oprogramowania

Phishing atakuje człowieka, nie system.
Nie wymaga exploita ani podatności – wymaga kliknięcia.

2. Najczęstsze wektory phishingu
2.1 Link w wiadomości e-mail

Najpopularniejszy scenariusz:

Użytkownik otrzymuje wiadomość.

Kliknięcie prowadzi do fałszywej strony logowania.

Dane trafiają do atakującego.

3. Na co zwracać uwagę przy analizie URL
3.1 Podejrzane domeny

Przykłady:

http://bank-secure-login.com
http://secure-microsoft-update.com
http://192.168.1.235:8080/login

3.2 Typowe wskaźniki phishingu

Literówki w domenie (microso0ft, paypa1)

Dodatkowe słowa: secure, login, update, verify

Użycie bezpośredniego adresu IP zamiast domeny

Brak HTTPS

Nietypowy port (8080, 8443, 4444)

Podejrzane subdomeny:

microsoft.security-login-update.com
paypal.verify-account-secure.com

4. Niebezpieczne załączniki

Phishing nie zawsze kończy się na stronie WWW
. Często zawiera pliki:

Wysokiego ryzyka:

.exe

.js

.vbs

.bat

.ps1

.scr

Często wykorzystywane w atakach:

.zip

.iso

.img

.docm

.xlsm

.pdf (z linkiem)

ZIP i ISO są szczególnie niebezpieczne, ponieważ:

omijają podstawową analizę AV

mogą zawierać plik wykonywalny

mogą maskować rozszerzenia

5. Co analizujemy po kliknięciu (SOC L1 Checklista)

Po kliknięciu w link analizujemy w logach:

Procesy (Event ID 4688)

Czy uruchomiono przeglądarkę?

Czy pojawił się proces potomny?

Czy wystąpiły podejrzane procesy (cmd, powershell, mshta)?

Połączenia sieciowe (Sysmon Event ID 3)

Czy przeglądarka połączyła się z adresem IP?

Czy użyto niestandardowego portu?

Czy połączenie było HTTP zamiast HTTPS?

Artefakty systemowe

Czy zapisano plik w AppData / Temp?

Czy zmodyfikowano rejestr?

Czy utworzono zadanie harmonogramu?

Czy utworzono nowe konto lokalne?

6. Brak artefaktów – co to oznacza?

Jeżeli w logach nie ma:

nowych procesów

zapisu plików

modyfikacji systemu

może to oznaczać:

phishing credentialowy (wyłącznie kradzież login/hasło)

brak payloadu malware

wyłącznie fałszywą stronę HTML

7. Phishing vs Malware – różnica
Phishing	Malware
Kradzież danych	Instalacja złośliwego kodu
Fałszywa strona	Wykonanie pliku
Często brak artefaktów systemowych	Widoczne artefakty w logach
Atakuje użytkownika	Atakuje system
8. Dlaczego phishing jest skuteczny?

Bazuje na presji czasu

Wykorzystuje znane marki

Nie wymaga exploita

Często nie generuje alertów AV

Użytkownik sam podaje dane
