#!/usr/bin/env python3
"""S4-K5: IAM (Keycloak + oauth2-proxy) dogrulamasi. Yalnizca kendi lab'imiz.

Kontroller:
  1. Korumasiz yollar etkilenmedi (ana sayfa, arama 200).
  2. Korumali yollar (/ftp, /metrics) girissiz Keycloak'a yonlendiriyor.
  3. Atlatma denemeleri (buyuk harf, //, %xx) da yonlendiriliyor ya da engelleniyor.
  4. Ic kontrol adresi (/oauth2/auth) disaridan erisilemiyor; I-4 istisnasi
     yalnizca bizim Keycloak adresimizi kabul ediyor.
  5. Gercek giris akisi: personel (ops rolu) /ftp/'ye ulasiyor, misafir 403 aliyor.

Yalnizca standart kutuphane. Cikis kodu: hepsi beklenen sonuctaysa 0, degilse 1.
Kullanim: python test-iam.py [http://localhost:8080]
"""
import html
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8080"
KEYCLOAK = "http://localhost:8081/realms/lab/"
KULLANICILAR = {
    "personel": ("Personel-Lab-2026!", 200),   # ops rolu var
    "misafir": ("Misafir-Lab-2026!", 403),     # Keycloak girisi var, ops rolu yok
}

sonuc = {"ok": 0, "hata": 0}


class LocalhostPolitikasi(http.cookiejar.DefaultCookiePolicy):
    """Tarayicilar gibi: localhost'ta Secure cerezleri HTTP uzerinden de gonder.
    Keycloak oturum cerezlerini Secure isaretliyor; bu olmadan giris formu 400 verir."""
    def return_ok_secure(self, cookie, request):
        host = urllib.parse.urlparse(request.get_full_url()).hostname
        return host in ("localhost", "127.0.0.1") or super().return_ok_secure(cookie, request)


class Yonlendirme(urllib.request.HTTPRedirectHandler):
    """Yonlendirmeleri takip etmez; 30x yanitini oldugu gibi dondurur."""
    def redirect_request(self, *args, **kwargs):
        return None


def yaz(etiket, durum, beklenen, basarili, ek=""):
    sonuc["ok" if basarili else "hata"] += 1
    print(f"[{'OK ' if basarili else 'HATA'}] {durum!s:>3}  (beklenen {beklenen})  {etiket}{'  ' + ek if ek else ''}")


def tek_istek(yol):
    """Yonlendirme takip etmeden tek istek: (durum, Location)."""
    acici = urllib.request.build_opener(Yonlendirme)
    try:
        y = acici.open(BASE + yol, timeout=10)
        return y.status, y.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")
    except urllib.error.URLError as e:
        return f"ERR {e.reason}", ""


def korumasiz(etiket, yol):
    durum, _ = tek_istek(yol)
    yaz(etiket, durum, 200, durum == 200)


def keycloaka_gider(etiket, yol):
    durum, konum = tek_istek(yol)
    basarili = durum == 302 and konum.startswith(KEYCLOAK)
    yaz(etiket, durum, "302 -> Keycloak", basarili, konum[:60] if not basarili else "")


def ulasmaz(etiket, yol):
    """Atlatma denemesi: icerige ulasmamali (200 disinda her sey kabul)."""
    durum, konum = tek_istek(yol)
    basarili = isinstance(durum, int) and durum != 200   # baglanti hatasi gecmis sayilmaz
    ek ="Keycloak'a yonlendirdi" if konum.startswith(KEYCLOAK) else ""
    yaz(etiket, durum, "200 disi", basarili, ek)


def giris_akisi(kullanici, sifre, beklenen):
    """Tarayici gibi: /ftp/ -> Keycloak giris formu -> callback -> /ftp/."""
    kavanoz = http.cookiejar.CookieJar(policy=LocalhostPolitikasi())
    acici = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(kavanoz))
    etiket = f"giris akisi: {kullanici} -> /ftp/"
    try:
        sayfa = acici.open(BASE + "/ftp/", timeout=15)
        govde = sayfa.read().decode("utf-8", "replace")
        if not sayfa.url.startswith(KEYCLOAK):
            yaz(etiket, sayfa.status, beklenen, False, f"Keycloak'a gitmedi: {sayfa.url[:60]}")
            return
        m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', govde) \
            or re.search(r'action="([^"]+login-actions/authenticate[^"]*)"', govde)
        if not m:
            yaz(etiket, "?", beklenen, False, "giris formu bulunamadi")
            return
        hedef = html.unescape(m.group(1))
        veri = urllib.parse.urlencode({"username": kullanici, "password": sifre,
                                       "credentialId": ""}).encode()
        son = acici.open(hedef, data=veri, timeout=15)
        durum, url = son.status, son.url
    except urllib.error.HTTPError as e:
        durum, url = e.code, e.url
    except urllib.error.URLError as e:
        yaz(etiket, f"ERR", beklenen, False, str(e.reason))
        return
    # Yetkili kullanici /ftp/'ye ulasir. Yetkisiz kullanici (ops rolu yok) icin
    # oauth2-proxy rolu geri donuste kontrol eder ve oturum acmadan 403 verir;
    # bu yuzden 403 /oauth2/callback adresinde de gelebilir.
    if beklenen == 200:
        basarili = durum == 200 and url.startswith(BASE + "/ftp")
    else:
        basarili = durum == beklenen and (url.startswith(BASE + "/ftp")
                                          or url.startswith(BASE + "/oauth2/callback"))
    ek = ""
    if not basarili:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        if "error" in q:   # Keycloak/oauth2-proxy hatasi: tam aciklamayi goster
            ek = f"hata: {q['error'][0]} - {q.get('error_description', [''])[0]}"
        else:
            ek = f"son adres: {url}"
    yaz(etiket, durum, beklenen, basarili, ek)


print("== Korumasiz yollar (etkilenmemeli) ==")
korumasiz("ana sayfa", "/")
korumasiz("urun arama", "/rest/products/search?q=apple")

print("== Korumali yollar, girissiz ==")
keycloaka_gider("/ftp/ (V009)", "/ftp/")
keycloaka_gider("/ftp", "/ftp")
keycloaka_gider("/ftp/legal.md", "/ftp/legal.md")
keycloaka_gider("/metrics", "/metrics")

print("== Atlatma denemeleri (icerige ulasmamali) ==")
ulasmaz("/FTP/ (buyuk harf)", "/FTP/")
ulasmaz("/Ftp/legal.md", "/Ftp/legal.md")
ulasmaz("//ftp/ (cift egik cizgi)", "//ftp/")
ulasmaz("/%66tp/ (kodlanmis)", "/%66tp/")
ulasmaz("/./ftp/", "/./ftp/")
ulasmaz("/METRICS", "/METRICS")

print("== Ic kontrol adresi ==")
durum, _ = tek_istek("/oauth2/auth")
yaz("/oauth2/auth disaridan", durum, "404", durum == 404)

print("== I-4 istisnasinin siniri (WAF 934110 ile 403 beklenir) ==")
# Dogrulama: audit.log'da bu iki istek icin 934110 gorunmeli (oauth2-proxy'nin
# kendi 403'u ile karistirilmasin).
durum, _ = tek_istek("/oauth2/callback?iss=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data")
yaz("callback, iss = bulut metadata adresi", durum, 403, durum == 403)
durum, _ = tek_istek("/oauth2/callback?iss=http%3A%2F%2Flocalhost%3A8081%2Frealms%2Flab"
                     "&iss=http%3A%2F%2Flocalhost%3A9999%2F")
yaz("callback, iki iss (bizimki + baska)", durum, 403, durum == 403)

print("== Giris akisi (Keycloak) ==")
for ad, (sifre, beklenen) in KULLANICILAR.items():
    giris_akisi(ad, sifre, beklenen)

toplam = sonuc["ok"] + sonuc["hata"]
print(f"\nToplam {toplam} kontrol, {sonuc['hata']} beklenmeyen sonuc.")
sys.exit(0 if sonuc["hata"] == 0 else 1)
