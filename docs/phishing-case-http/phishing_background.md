Phishing – Wprowadzenie i Tło Techniczne
1. Czym jest phishing

Phishing to technika socjotechniczna polegająca na podszywaniu się pod zaufaną instytucję (bank, Microsoft, kurier, operator płatności) w celu:

wyłudzenia danych logowania

przejęcia konta

wyłudzenia danych karty płatniczej

dostarczenia złośliwego oprogramowania

Phishing atakuje człowieka, nie system.

Nie wymaga exploita ani podatności – wymaga kliknięcia.

2. Najczęstsze wektory phishingu
2.1 Link w wiadomości e-mail

Przykłady podejrzanych adresów:

http://bank-secure-login.com
http://secure-microsoft-update.com
http://192.168.1.235:8080/login


Na co zwracamy uwagę:

literówki w domenie (micr0soft, paypa1)

dodatkowe słowa: secure, login, update, verify

użycie bezpośredniego adresu IP

brak HTTPS

nietypowy port (8080, 8443, 4444)

podejrzane subdomeny:

microsoft.security-login-update.com

2.2 Złośliwe załączniki

Najczęściej spotykane rozszerzenia:

.docm

.xlsm

.pdf

.zip

.iso

.img

.js

.hta

.lnk

Dlaczego są groźne:

DOCM/XLSM – makra mogą uruchamiać PowerShell

ISO/IMG – po zamontowaniu użytkownik widzi „fałszywy dysk” z plikiem wykonywalnym

ZIP – ukryty dropper lub skrypt

JS/HTA – wykonywane bezpośrednio przez Windows

LNK – skrót wywołujący polecenie w tle

ISO i IMG są szczególnie niebezpieczne, ponieważ:

często omijają filtry pocztowe

po otwarciu wyglądają jak lokalny dysk

realne rozszerzenie pliku bywa ukryte

3. Weryfikacja domeny – Checklista SOC

Podczas analizy sprawdzamy:

czy domena zawiera literówki

czy wygląda podejrzanie marketingowo

czy używa bezpośredniego IP

czy domena została niedawno zarejestrowana

czy certyfikat SSL jest prawidłowy

czy domena nie jest subdomeną maskującą markę

4. Analiza adresu URL

Sprawdzamy:

czy użyto HTTP zamiast HTTPS

czy występuje niestandardowy port

czy w URL są podejrzane parametry:

?session=verify&id=update


czy występują znaki kodowane:

%2F%3D%40


Czerwone flagi:

IP zamiast domeny

port 8080

brak szyfrowania

długie losowe parametry

5. Co sprawdzamy w logach endpoint (SOC L1)
5.1 Event ID 4688 – Process Creation

Analizujemy:

czy uruchomiono przeglądarkę

czy ParentProcessName = explorer.exe

czy pojawiły się podejrzane procesy:

powershell.exe

cmd.exe

mshta.exe

wscript.exe

rundll32.exe

certutil.exe

Jeżeli po kliknięciu strony pojawia się PowerShell – to poważna czerwona flaga.

5.2 Sysmon Event ID 3 – Network Connection

Sprawdzamy:

Destination IP

Destination Port

Protocol

czy połączenie było wychodzące

czy użyto HTTP

Czerwone flagi:

bezpośredni adres IP

niestandardowy port

połączenie do nieznanego hosta

brak szyfrowania

6. Sprawdzenie dalszej kompromitacji

Po kliknięciu strony analizujemy, czy:

uruchomiono proces potomny przeglądarki

pobrano plik

zapisano plik w AppData lub Temp

zmodyfikowano rejestr

utworzono zadanie harmonogramu

utworzono nowe konto lokalne

Brak powyższych artefaktów może oznaczać:

wyłącznie phishing credentialowy (kradzież login/hasło)

brak payloadu malware

7. Phishing vs Malware – Różnica
Phishing	Malware
Kradzież danych	Instalacja złośliwego kodu
Fałszywa strona	Wykonanie pliku
Często brak artefaktów systemowych	Widoczne artefakty w logach
Skupiony na użytkowniku	Skupiony na systemie
8. Dlaczego phishing jest skuteczny

bazuje na presji czasu

wykorzystuje znaną markę

nie wymaga exploita

często nie generuje alertów AV

użytkownik sam podaje dane
