# AntiPhish – postavljanje na Hostinger VPS (test sa prijateljima)

Ovo uputstvo podiže web aplikaciju na `https://antiphish.TVOJADOMENA.com`, sa
HTTPS-om, nalozima, kreditima, feedbackom i (opcionalno) adresom za
prosljeđivanje `scan@TVOJADOMENA.com`.

---

## 0. Provjeri da li imaš VPS (najvažnije)

Python aplikacije na Hostingeru rade **samo na VPS-u**. Obični *Web Hosting* /
*Cloud Hosting* (gdje ti je web stranica) nema root pristup i **ne može** pokrenuti
ovaj program.

hPanel → lijevi meni: ako vidiš **VPS** sa svojim serverom – super. Ako ne:

| Plan | RAM | Dovoljno za |
|---|---|---|
| KVM 1 | 4 GB | web + prosljeđivanje, **bez** lokalnog Qwen AI |
| KVM 2 | 8 GB | + Qwen `qwen2.5:3b` lokalno (sporo na CPU) |
| KVM 4+ | 16 GB | + Qwen `qwen2.5:7b` lokalno |

Web stranica ostaje gdje jeste – AntiPhish ide na **poddomen**.

Pri postavljanju VPS-a izaberi OS template **Ubuntu 24.04 with Docker**
(ili čisti Ubuntu 24.04 pa korak 2).

---

## 1. DNS: poddomen → VPS

hPanel → **Domains** → tvoja domena → **DNS / Nameservers** → *Add record*:

| Type | Name | Points to | TTL |
|---|---|---|---|
| A | `antiphish` | IP adresa VPS-a (hPanel → VPS → Overview) | 3600 |

Provjera (može potrajati do sat vremena): `ping antiphish.TVOJADOMENA.com` mora
pokazati IP VPS-a.

---

## 2. Spoji se na VPS i instaliraj Docker (ako nije već)

Sa Windowsa (PowerShell):
```powershell
ssh root@IP_VPS_A
```
Na serveru:
```bash
docker --version || curl -fsSL https://get.docker.com | sh
# firewall: samo SSH, HTTP, HTTPS
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable
```
(Hostinger ima i firewall u hPanel → VPS → Security – ako ga koristiš, otvori 22, 80, 443.)

---

## 3. Prebaci program na server

**Opcija A – zip sa svog računara** (PowerShell, iz foldera gdje je zip):
```powershell
scp Antiphish_v0.9.zip root@IP_VPS_A:/opt/
```
Na serveru:
```bash
apt-get install -y unzip
cd /opt && unzip Antiphish_v0.9.zip && mv Antiphish antiphish && cd antiphish
```

**Opcija B – GitHub:** `git clone https://github.com/TVOJ_NALOG/Antiphish /opt/antiphish`
⚠️ Tvoj repo je trenutno **javan** – prebaci ga u *Private* (Settings → Danger zone)
prije nego što staviš produkcijske stvari, i **nikad** ne commitaj `.env`.

---

## 4. Podesi `.env`

```bash
cd /opt/antiphish
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # kopiraj rezultat
nano .env
```
Obavezno popuni:
```
DOMAIN=antiphish.TVOJADOMENA.com
BASE_URL=https://antiphish.TVOJADOMENA.com
SECRET_KEY=<zalijepi generisani string>
```
Za prvi test ostavi AI isključen: `WEB_ALLOW_LLM=0` (vidi korak 8).
Sačuvaj: `Ctrl+O`, Enter, `Ctrl+X`. Zaštiti fajl: `chmod 600 .env`

---

## 5. Pokreni

```bash
docker compose up -d --build
```
Prvi build traje nekoliko minuta: preuzima javne korpuse (~110 MB) i trenira ML
model **unutar** image-a. U logu builda traži red
`wrote /app/data/corpus.csv: 7203 emails` – ako umjesto toga vidiš
`WARNING: corpus download failed`, model je samo početni (slabiji) – ponovi build kasnije.

Provjera:
```bash
docker compose ps                 # web: healthy, caddy: running
docker compose logs -f web        # Ctrl+C za izlaz
```
Otvori `https://antiphish.TVOJADOMENA.com` – Caddy sam pribavi HTTPS certifikat
(prvi put ~30 s). Ako certifikat ne radi: DNS još nije propagiran ili su portovi 80/443 zatvoreni.

> **Već imaš nginx/Apache na tom VPS-u na portovima 80/443?** Onda pokreni bez Caddyja:
> `docker compose up -d --build web` i koristi `deploy/nginx-antiphish.conf` + `certbot`.

---

## 6. Napravi naloge

```bash
docker compose exec -u app web python -m webapp.manage create-admin TI@email.com
docker compose exec -u app web python -m webapp.manage create-user DRUG@email.com --credits 100
docker compose exec -u app web python -m webapp.manage list
```
(Lozinku upisuješ skriveno, min 10 znakova. Uvijek koristi `-u app`.)
Naloge, kredite i deaktivaciju možeš raditi i u web **Admin** panelu.

---

## 7. (Opcionalno) Adresa za prosljeđivanje `scan@TVOJADOMENA.com`

1. hPanel → **Emails** → tvoja domena → *Create email account* → `scan@...` (jaka lozinka).
2. U `.env`:
   ```
   INTAKE_USER=scan@TVOJADOMENA.com
   INTAKE_PASSWORD=<lozinka tog maila>
   ```
3. `docker compose --profile intake up -d` → `docker compose logs -f intake`
4. Test: sa adrese koja je registrovana kao korisnik, proslijedi sumnjiv mail
   **kao prilog** na `scan@...`. Izvještaj stiže za ~20–40 s.
   - Gmail: otvori mail → ⋮ → *Forward as attachment* (ili označi mail u listi → ⋮ → *Forward as attachment*).
   - Obično prosljeđivanje radi, ali bez zaglavlja originala (slabija analiza – izvještaj to i napiše).
   - Mailovi sa neregistrovanih adresa se tiho ignorišu.

---

## 8. (Opcionalno) Qwen AI

**a) Lokalno na VPS-u** (treba RAM – vidi tabelu u koraku 0; na CPU je sporo, 20–90 s po mailu):
```bash
docker compose --profile llm up -d
docker compose exec ollama ollama pull qwen2.5:3b     # ili qwen2.5:7b na 16 GB
```
`.env`: `WEB_ALLOW_LLM=1`, `QWEN_PROVIDER=ollama`, `QWEN_BASE_URL=http://ollama:11434`,
`QWEN_MODEL=qwen2.5:3b`, zatim `docker compose up -d`.

**b) DashScope (cloud, brže, plaća se po upotrebi):** `QWEN_PROVIDER=dashscope`,
`DASHSCOPE_API_KEY=...`, `QWEN_MODEL=qwen-plus`. ⚠️ Sadržaj mailova ide na Alibaba Cloud
– testeri to moraju znati.

Admin panel pokazuje da li je Qwen dostupan; "AI provjera" je na stranici aktivna samo tada.

---

## 9. Svakodnevno održavanje

| Šta | Komanda |
|---|---|
| Logovi | `docker compose logs -f web` (ili `intake`, `caddy`) |
| Restart | `docker compose restart web` |
| Update programa | prebaci novi kod u `/opt/antiphish` (zadrži `.env` i `data/`), pa `docker compose up -d --build` |
| Backup baze | `docker compose exec -u app web python -c "import sqlite3; s=sqlite3.connect('/app/data/antiphish.db'); d=sqlite3.connect('/app/data/backup.db'); s.backup(d)"` → fajl `data/backup.db` (preuzmi ga sa `scp`) |
| Učenje iz feedbacka | Admin → *Izvezi u feedback.csv*, zatim `docker compose exec -u app web python -m antiphish.learn` (~1–2 min) i `docker compose restart web intake` |
| Krediti | Admin panel ili `... python -m webapp.manage credits DRUG@email.com 200` |
| Mjerenje modela | `docker compose exec -u app web python evaluate.py` |

Sve što treba sačuvati je u **`/opt/antiphish/data/`** (baza, model, feedback) i **`.env`**.

---

## 10. Plan testiranja (ti + drug)

1. **Prijava/odjava**, promjena lozinke (druge sesije se odjave).
2. **Legitimni mailovi** (Gmail → ⋮ → *Download message* → upload .eml): newsletteri, računi,
   obavještenja. Očekivano: LOW. Svaki pogrešan → dugme *Ovo je legitiman mail*.
3. **Phishing iz spam foldera** – isto, očekivano HIGH/CRITICAL; promašaje označi *Ovo je phishing*.
4. **Prilozi:** zip sa `login.html` (forma sa lozinkom) i `faktura.pdf.exe` (običan tekst preimenovan) → CRITICAL.
5. **Samo tekst** (zalijepi bez zaglavlja) → upozorenje da je analiza ograničena.
6. **Prosljeđivanje** na `scan@` (kao prilog i obično).
7. **Limiti:** 0 kredita → poruka; 8 pogrešnih lozinki → blokada 15 min.
8. Nakon par dana: izvezi feedback → `antiphish.learn` → uporedi rezultate.

Zapisujte: šta je bilo sporo, šta nejasno na stranici, svaku pogrešnu ocjenu.

---

## Rješavanje problema

| Simptom | Uzrok / rješenje |
|---|---|
| `Permission denied` u logu | stara verzija entrypointa – rebuild: `docker compose up -d --build` |
| Stranica ne otvara, Caddy log: `challenge failed` | DNS A record još ne pokazuje na VPS, ili portovi 80/443 zatvoreni |
| `502 Bad Gateway` | web kontejner još starta / pao: `docker compose logs web` |
| "Server je trenutno zauzet" | povećaj `SCAN_CONCURRENCY` (ako ima RAM-a) |
| Odjavljuje vas nakon restarta | `SECRET_KEY` nije postavljen u `.env` |
| Intake ne odgovara | `docker compose logs intake`; lozinka scan@ maila; pošiljalac mora biti registrovan korisnik |
| AI provjera sivo/nedostupna | Ollama nije pokrenuta ili model nije `pull`-ovan; vidi Admin panel |
