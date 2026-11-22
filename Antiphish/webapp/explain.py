"""Human-friendly explanations of detector signals (shown to end users)."""
from __future__ import annotations

_HELP = {
    # authentication / sender
    "auth_dmarc_fail": "Domen pošiljaoca ne potvrđuje da je ovaj mail poslan sa njegovih servera (DMARC pao). Tipično za lažiranje adrese.",
    "auth_spf_fail": "Server koji je poslao mail nije ovlašten za domen pošiljaoca (SPF pao).",
    "auth_dkim_fail": "Digitalni potpis maila nije ispravan (DKIM pao) – mail je možda izmijenjen ili lažan.",
    "auth_all_pass": "SPF, DKIM i DMARC su prošli – pošiljalac je tehnički provjeren. (Napomena: i napadači koriste vlastite, ispravno podešene domene.)",
    "legit_bulk_sender": "Provjeren newsletter: autentifikovan pošiljalac, link za odjavu i bez znakova phishinga.",
    "reply_to_mismatch": "Odgovor na ovaj mail ide na drugi domen od pošiljaoca – čest trik za prevaru.",
    "sender_displayname_spoof": "Ime pošiljaoca glumi poznati brend, ali adresa nije sa domena tog brenda.",
    "sender_mixed_alphabet": "Adresa pošiljaoca miješa pisma (npr. ćirilična slova koja izgledaju kao latinična).",
    "sender_freemail_role": "Mail se predstavlja kao IT/računovodstvo/direktor, a poslan je sa besplatne adrese (Gmail i sl.).",
    "sender_generic_role": "Generička adresa (noreply, support...) umjesto osobe – samo blagi signal.",
    # text
    "text_credential_ask": "Tekst traži da se prijaviš, potvrdiš nalog ili uneseš lozinku.",
    "text_urgency_high": "Jak pritisak hitnosti (rok, prijetnja zatvaranjem) – klasična taktika manipulacije.",
    "text_urgency_low": "Blagi pritisak hitnosti.",
    "text_money_pressure": "Spominje plaćanje, fakture, povrat novca ili nagrade.",
    "text_threat": "Prijetnja blokadom, tužbom ili neovlaštenim pristupom.",
    "text_generic_greeting": "Generičko obraćanje ('Dear customer') umjesto tvog imena.",
    "text_excessive_caps": "Mnogo riječi VELIKIM SLOVIMA.",
    # urls
    "url_ip_host": "Link vodi na IP adresu umjesto na ime domena – legitimne firme to gotovo nikad ne rade.",
    "url_brand_spoof": "Link sadrži ime poznatog brenda, ali nije na zvaničnom domenu tog brenda.",
    "url_punycode": "Link koristi znakove koji izgledaju kao obična slova (homograf napad, npr. 'pаypal' sa ćiriličnim 'а').",
    "url_at_symbol": "Link koristi trik sa '@' koji skriva pravu odredište.",
    "url_suspicious_tld": "Link je na domenu sa ekstenzijom koju napadači često koriste (.tk, .top, .xyz ...).",
    "url_shortener": "Skraćeni link – prava odredište je skrivena.",
    "url_no_https": "Link nije šifrovan (http umjesto https).",
    "url_vt_malicious": "VirusTotal: više antivirusnih servisa označava ovaj link kao maliciozan.",
    "url_vt_flagged": "VirusTotal: neki servisi označavaju ovaj link kao opasan.",
    "url_urlscan_malicious": "urlscan.io označava ovu stranicu kao malicioznu.",
    # attachments
    "attachment_executable": "Prilog (ili fajl unutar arhive) je program/skripta – NIKAD ga ne pokreći.",
    "attachment_double_extension": "Dvostruka ekstenzija (npr. faktura.pdf.exe) skriva pravi tip fajla.",
    "attachment_type_mismatch": "Ekstenzija laže: fajl izgleda kao dokument, a zapravo je program.",
    "attachment_rtlo_trick": "Ime fajla koristi skriveni znak koji obrće tekst da sakrije pravu ekstenziju.",
    "attachment_disk_image": "Prilog je disk image (.iso/.img) – često se koristi za zaobilaženje Windows zaštite.",
    "attachment_risky": "Tip priloga se često koristi za širenje malvera.",
    "archive_encrypted": "Arhiva zaštićena lozinkom – sadržaj nije moguće provjeriti (čest trik za zaobilaženje filtera).",
    "archive_encrypted_opened": "Arhiva zaštićena lozinkom iz teksta maila – otvorena i provjerena.",
    "archive_zip_bomb": "Arhiva je napravljena da 'eksplodira' pri raspakivanju (zip bomba).",
    "office_macro": "Office dokument sadrži makroe – ne klikaj 'Enable content'.",
    "office_remote_template": "Word dokument preuzima šablon sa interneta – poznata tehnika napada.",
    "office_dde": "Dokument sadrži DDE polje koje može pokrenuti komande.",
    "pdf_active_content": "PDF sadrži JavaScript ili automatske akcije.",
    "pdf_phishing_content": "Tekst u PDF prilogu liči na phishing.",
    "html_credential_form": "Prilog je lažna stranica za prijavu sa poljem za lozinku.",
    "html_smuggling": "HTML prilog sadrži skriveni kod koji gradi maliciozni fajl u pregledniku.",
    "html_redirect": "HTML prilog te automatski preusmjerava na drugu stranicu.",
    "svg_script": "SVG 'slika' sadrži JavaScript – sve češći trik napadača.",
    "qr_code_url": "QR kod vodi na link – provjeri ga prije skeniranja telefonom (quishing).",
    "calendar_invite_links": "Pozivnica za kalendar sadrži linkove.",
    "attachment_scan_timeout": "Prilog je zaglavio skener – fajlovi napravljeni da zbune skenere su sumnjivi.",
    # ai / overrides
    "llm_phishing_judged": "AI (Qwen) procjena: phishing.",
    "llm_clean_judged": "AI (Qwen) procjena: legitimno.",
    "hard_evidence_override": "Pronađen je tvrdi dokaz napada – ocjena je podignuta na KRITIČNO.",
}


def explain_signal(name: str) -> str:
    if name in _HELP:
        return _HELP[name]
    if name.startswith("attachment_vt"):
        return "VirusTotal: antivirusni servisi označavaju ovaj prilog."
    if name.startswith("pdf_ml") or name.startswith("attachment_ml"):
        return "ML model ocjenjuje tekst priloga kao phishing."
    if name.startswith("archive_"):
        return "Problem sa arhivom u prilogu."
    return ""


_LEVELS = {
    "LOW": ("Nizak rizik", "low", "Nema jakih znakova phishinga. Normalan oprez."),
    "SUSPICIOUS": ("Sumnjivo", "susp", "Provjeri pošiljaoca drugim kanalom prije klika na linkove ili otvaranja priloga."),
    "HIGH": ("Visok rizik", "high", "Vjerovatno phishing. Ne klikaj linkove, ne otvaraj priloge, ne odgovaraj."),
    "CRITICAL": ("KRITIČNO", "crit", "Gotovo sigurno phishing/malver. Obriši ili prijavi mail i ništa ne otvaraj."),
}


def level_info(level: str) -> tuple[str, str, str]:
    return _LEVELS.get(level, (level, "low", ""))
