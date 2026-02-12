# Phishing – Wprowadzenie i Tło Techniczne

---

## 1. Czym jest phishing?

Phishing to technika socjotechniczna polegająca na podszywaniu się pod zaufaną instytucję (np. bank, Microsoft, kurier, operator płatności) w celu:

- wyłudzenia danych logowania
- przejęcia konta
- wyłudzenia danych karty płatniczej
- dostarczenia złośliwego oprogramowania

Phishing atakuje **człowieka**, nie system, jest atakiem na użytkownika, nie na podatność systemową.
Nie wymaga exploita ani podatności – wymaga kliknięcia.

---

## 2. Najczęstsze wektory phishingu

### 2.1 Link w wiadomości e-mail

Najpopularniejszy scenariusz:

1. Użytkownik otrzymuje wiadomość.
2. Kliknięcie prowadzi do fałszywej strony logowania.
3. Wprowadzone dane trafiają do atakującego.

---

## 3. Analiza URL – na co zwracamy uwagę

### 3.1 Przykłady podejrzanych adresów

- http://bank-secure-login.com
- http://secure-microsoft-update.com
- http://192.168.1.235:8080/login

---

### 3.2 Typowe wskaźniki phishingu

- literówki w domenie (np. microso0ft, paypa1)
- dodatkowe słowa: secure, login, update, verify
- użycie bezpośredniego adresu IP zamiast domeny
- brak HTTPS
- niestandardowy port (8080, 8443, 4444)
- podejrzane subdomeny:


---

## 4. Niebezpieczne załączniki

Phishing nie zawsze kończy się na stronie WWW.  
Często zawiera pliki o wysokim ryzyku.

### 4.1 Wysokiego ryzyka

- .exe  
- .js  
- .vbs  
- .bat  
- .ps1  
- .scr  

### 4.2 Często wykorzystywane w atakach

- .zip  
- .iso  
- .img  
- .docm  
- .xlsm  
- .pdf (z osadzonym linkiem)

ZIP i ISO są szczególnie niebezpieczne, ponieważ:

- omijają podstawową analizę AV
- mogą zawierać pliki wykonywalne
- mogą maskować rozszerzenia

---

## 5. Co analizujemy po kliknięciu (SOC L1 – Checklista)

### 5.1 Procesy – Event ID 4688

Sprawdzamy:

- czy uruchomiono przeglądarkę
- czy pojawił się proces potomny
- czy wystąpiły podejrzane procesy:
  - cmd.exe
  - powershell.exe
  - mshta.exe
  - wscript.exe
  - rundll32.exe
  - certutil.exe

---

### 5.2 Połączenia sieciowe – Sysmon Event ID 3

Sprawdzamy:

- czy przeglądarka połączyła się z adresem IP
- czy użyto niestandardowego portu
- czy połączenie było HTTP zamiast HTTPS
- czy domena jest nietypowa

---

### 5.3 Artefakty systemowe

- zapis pliku w AppData / Temp
- modyfikacja rejestru
- utworzenie zadania harmonogramu
- utworzenie nowego konta lokalnego

---

## 6. Brak artefaktów – co to oznacza?

Jeżeli w logach nie ma:

- nowych procesów
- zapisu plików
- modyfikacji systemu

Może to oznaczać:

- phishing credentialowy (wyłącznie kradzież login/hasło)
- brak payloadu malware
- wyłącznie fałszywą stronę HTML

---

## 7. Phishing vs Malware – różnice

| Phishing | Malware |
|----------|----------|
| Kradzież danych | Instalacja złośliwego kodu |
| Fałszywa strona | Wykonanie pliku |
| Często brak artefaktów systemowych | Widoczne artefakty w logach |
| Atakuje użytkownika | Atakuje system |

---

## 8. Dlaczego phishing jest skuteczny?

- bazuje na presji czasu
- wykorzystuje znane marki
- nie wymaga exploita
- często nie generuje alertów AV
- użytkownik sam podaje dane
  ---

## 9. Weryfikacja domeny i infrastruktury (OSINT)

Analiza phishingu nie ogranicza się do logów endpoint.  
W realnym SOC weryfikujemy również warstwę domenową i infrastrukturę.

### 9.1 Analiza WHOIS

Sprawdzamy:

- datę rejestracji domeny
- kraj rejestracji
- czy dane właściciela są ukryte (privacy protection)
- czy domena została zarejestrowana niedawno

Nowo zarejestrowane domeny (< 30 dni) są częstym wskaźnikiem phishingu.

---

### 9.2 Certyfikat SSL

Sprawdzamy:

- czy certyfikat istnieje
- kto go wystawił
- czy jest self-signed
- czy domena w certyfikacie zgadza się z adresem

Phishing często używa darmowych certyfikatów lub HTTP bez TLS.

---

### 9.3 SPF / DKIM / DMARC

W przypadku phishingu e-mail analizujemy:

- wynik SPF
- wynik DKIM
- wynik DMARC

Możliwe scenariusze:

- SPF fail
- DKIM fail
- DMARC fail
- 3x pass przy domenie podobnej do oryginalnej (lookalike domain)

---

### 9.4 Reputacja IP i domeny

Sprawdzamy:

- czy IP znajduje się w blacklistach
- czy domena była zgłaszana jako phishing
- czy IP należy do podejrzanego ASN

---

Weryfikacja infrastruktury pozwala ocenić poziom ryzyka nawet bez obecności malware.


