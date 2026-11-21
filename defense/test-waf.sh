#!/usr/bin/env bash
# Kendi lab ortamımıza (localhost:8080) WAF doğrulama istekleri gönderir.
# Engelleme modunda (MODSEC_RULE_ENGINE=On): normal trafik geçer, test payload'ları 403 alır.
# DetectionOnly modunda payload'lar uygulamaya ULAŞIR (ör. arama SQLi -> 500,
# login SQLi -> admin token, V003 -> başka kullanıcıların siparişleri); bu yüzden
# "beklenen" sütunu engelleme moduna göredir.
#
# Envanter eşlemesi (K2): her saldırı satırı bir zafiyete (Vxxx) bağlıdır ve
# yanında aynı uç noktaya giden zararsız bir kontrol isteği vardır; kontrol isteği
# uç noktanın kendisinin engellenmediğini (yanlış pozitif olmadığını) gösterir.
# Çıkış kodu: tüm satırlar beklenen kodu verirse 0, aksi halde 1.
BASE="${1:-http://localhost:8080}"
gecen=0; kalan=0

WAF_MODE="${WAF_MODE:-blocking}"
if [ "$WAF_MODE" = "detection" ] || [ "$WAF_MODE" = "DetectionOnly" ]; then
  SQLI_OK=500
  XSS_OK=200
  PATH_OK=200
  SCANNER_OK=200
  LOGIN_SQLI_OK=200
  V003_OK=200
  V005_OK=404
  V008_OK=201
  V013_OK=302
  V010_OK=410
  V012_OK=302
else
  SQLI_OK=403
  XSS_OK=403
  PATH_OK=403
  SCANNER_OK=403
  LOGIN_SQLI_OK=403
  V003_OK=403
  V005_OK=403
  V008_OK=403
  V013_OK=403
  V010_OK=403
  V012_OK=403
fi

req() {  # etiket, beklenen kod, curl argümanları...
  local label="$1" bek="$2"; shift 2
  local code; code=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  if [ "$code" = "$bek" ]; then gecen=$((gecen+1)); durum="OK"; else kalan=$((kalan+1)); durum="HATA"; fi
  printf '%-34s -> HTTP %s  (beklenen %s) %s\n' "$label" "$code" "$bek" "$durum"
}
JSON=(-H 'Content-Type: application/json')

echo "== Normal trafik =="
req "ana sayfa"                        200 "$BASE/"
req "ürün listesi"                     200 "$BASE/rest/products/search?q=apple"

echo "== Test payload'ları (kendi lab'ımız) =="
req "SQLi"                             "$SQLI_OK" -G "$BASE/rest/products/search" --data-urlencode "q=' OR 1=1--"
req "XSS"                              "$XSS_OK" -G "$BASE/rest/products/search" --data-urlencode "q=<script>alert(1)</script>"
req "Path traversal"                   "$PATH_OK" "$BASE/?file=../../../../etc/passwd"
req "Scanner UA"                       "$SCANNER_OK" -A "sqlmap/1.7" "$BASE/"

echo "== V001: giriş, JSON POST gövdesinde SQLi =="
req "V001 kontrol: yanlış şifre"       401 -X POST "${JSON[@]}" --data '{"email":"ayse@ornek.com","password":"yanlis-sifre"}' "$BASE/rest/user/login"
req "V001 SQLi (email alanı)"          "$LOGIN_SQLI_OK" -X POST "${JSON[@]}" --data "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}" "$BASE/rest/user/login"
req "V001 SQLi (form gövdesi)"         "$LOGIN_SQLI_OK" -X POST --data-urlencode "email=' OR 1=1--" --data-urlencode "password=x" "$BASE/rest/user/login"

echo "== V002: ürün araması (SY-6) =="
# Saldırı satırı yukarıdaki "SQLi" satırı; burada tırnaklı ama zararsız arama.
req "V002 kontrol: çift tırnaklı ad"   200 -G "$BASE/rest/products/search" --data-urlencode 'q="King of the Hill"'

echo "== V003: sipariş takibi (envanter: reflected XSS, yol içinde) =="
req "V003 kontrol: geçerli biçim"      200 "$BASE/rest/track-order/5267-f9cd5882f54c75a3"
req "V003 XSS (yol içinde iframe)"     "$V003_OK" "$BASE/rest/track-order/%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E"
# Aynı uç noktadaki ikinci açık (envanterde ayrı kayıt değil): $where NoSQL enjeksiyonu
req "V003 yolu NoSQLi (' || true || ')" "$V003_OK" "$BASE/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27"

echo "== V005: PUT /api/Products (I-1 ile açılan yol), gövdede XSS =="
# Var olmayan ürün (999999): WAF kapalı olsa bile lab verisi değişmez.
req "V005 kontrol: zararsız açıklama"  404 -X PUT "${JSON[@]}" --data '{"description":"Taze elma suyu"}' "$BASE/api/Products/999999"
req "V005 XSS (description alanı)"     "$V005_OK" -X PUT "${JSON[@]}" --data '{"description":"<iframe src=\"javascript:alert(`xss`)\">"}' "$BASE/api/Products/999999"

echo "== V008: kayıt, gövdede rol alanı (mass assignment, SY-2) =="
# Her çalıştırmada yeni bir e-posta: kayıt aynı adresle ikinci kez yapılamaz.
V008_ID="$(date +%s)$RANDOM"
req "V008 kontrol: normal kayıt"       201 -X POST "${JSON[@]}" --data "{\"email\":\"v008-kontrol-$V008_ID@ornek.com\",\"password\":\"Kontrol-Lab-2026!\",\"passwordRepeat\":\"Kontrol-Lab-2026!\"}" "$BASE/api/Users/"
req "V008 rol alanı (role=admin)"      "$V008_OK" -X POST "${JSON[@]}" --data "{\"email\":\"v008-test-$V008_ID@ornek.com\",\"password\":\"Kontrol-Lab-2026!\",\"passwordRepeat\":\"Kontrol-Lab-2026!\",\"role\":\"admin\"}" "$BASE/api/Users/"

echo "== V013: yönlendirme izin listesi (SY-3) =="
req "V013 kontrol: izinli adres"       302 "$BASE/redirect?to=https://github.com/juice-shop/juice-shop"
req "V013 eskimiş adres (kripto)"      "$V013_OK" "$BASE/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm"
req "V013 izinli adresi içeren hedef"  "$V013_OK" -G "$BASE/redirect" --data-urlencode "to=https://ornek.invalid/?x=https://github.com/juice-shop/juice-shop"

echo "== V010: dosya yükleme, XML (SY-4) =="
# İçerik zararsız; kural dosya adına bakıyor (uygulama da XML'i adına göre işliyor).
req "V010 kontrol: PDF yükleme"        204 -F "file=@-;filename=sikayet.pdf;type=application/pdf" "$BASE/file-upload" <<< "%PDF-1.4 kontrol"
req "V010 XML yükleme"                 "$V010_OK" -F "file=@-;filename=sikayet.xml;type=text/xml" "$BASE/file-upload" <<< "<?xml version=\"1.0\"?><sikayet>kontrol</sikayet>"

echo "== V012: profil güncelleme, başka siteden (CSRF, SY-5) =="
# V008 kontrol kullanıcısıyla giriş yapılıp oturum çerezi alınır.
V012_TOKEN=$(curl -s -X POST "${JSON[@]}" --data "{\"email\":\"v008-kontrol-$V008_ID@ornek.com\",\"password\":\"Kontrol-Lab-2026!\"}" "$BASE/rest/user/login" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
req "V012 kontrol: kendi sitemizden"   302 -X POST -H "Cookie: token=$V012_TOKEN" -H "Origin: http://localhost:8080" --data "username=kontrol$V008_ID" "$BASE/profile"
req "V012 başka siteden (Origin)"      "$V012_OK" -X POST -H "Cookie: token=$V012_TOKEN" -H "Origin: http://kotu-site.invalid" --data "username=csrf$V008_ID" "$BASE/profile"

# --- Ek savunma: nginx başlıkları ve hata sayfası (WAF modundan bağımsız) ---
sonuc() {  # etiket, koşul (0 = sağlandı), açıklama
  if [ "$2" = 0 ]; then gecen=$((gecen+1)); durum="OK"; else kalan=$((kalan+1)); durum="HATA"; fi
  printf '%-34s -> %s %s\n' "$1" "$3" "$durum"
}
baslik() {  # etiket, başlık adı, var|yok, curl argümanları...
  local label="$1" ad="$2" bek="$3"; shift 3
  local h; h=$(curl -s -o /dev/null -D - "$@" | tr -d '\r' | grep -i "^$ad:" | head -1)
  if [ "$bek" = var ]; then [ -n "$h" ]; else [ -z "$h" ]; fi
  sonuc "$label" $? "$(cut -c1-60 <<< "${h:-($ad yok)}")"
}
yigin_yok() {  # etiket, beklenen kod, curl argümanları...: kod tutmalı, gövdede yığın izi olmamalı
  local label="$1" bek="$2"; shift 2
  local govde code; govde=$(curl -s -w '\n%{http_code}' "$@"); code="${govde##*$'\n'}"
  if [ "$code" = "$bek" ] && ! grep -qE 'node_modules|at [^ ]+ \(|"stack"' <<< "$govde"; then r=0; else r=1; fi
  sonuc "$label" $r "HTTP $code, yığın izi $( [ $r = 0 ] && echo yok || echo VAR/kod farklı)"
}

echo "== V017, V021: güvenlik başlıkları =="
baslik "V017 CSP (ana sayfa)"             Content-Security-Policy      var "$BASE/"
baslik "V017 CSP (WAF 403 yanıtı)"        Content-Security-Policy      var "$BASE/?x=<script>"
baslik "V021 COOP"                         Cross-Origin-Opener-Policy   var "$BASE/"
baslik "V021 COEP"                         Cross-Origin-Embedder-Policy var "$BASE/"
baslik "V021 CORP"                         Cross-Origin-Resource-Policy var "$BASE/"
# CSP'deki sha256 özetleri bu iki sayfanın gövdesine bağlı (Juice Shop v20.2.0).
# Burada HATA çıkarsa imaj değişmiştir: özetler nginx/default.conf.template'te yenilenir.
oz=$(curl -s "$BASE/" | sha256sum | cut -c1-16);          [ "$oz" = aa97229042ece5a3 ]; sonuc "V017 CSP özetleri: index.html" $? "$oz"
oz=$(curl -s "$BASE/promotion" | sha256sum | cut -c1-16); [ "$oz" = 413043c1ccddc833 ]; sonuc "V017 CSP özetleri: /promotion" $? "$oz"

echo "== V018: CORS =="
baslik "V018 ACAO yok (GET)"              Access-Control-Allow-Origin yok -H "Origin: http://kotu-site.invalid" "$BASE/rest/languages"
baslik "V018 ACAO yok (OPTIONS)"          Access-Control-Allow-Origin yok -X OPTIONS -H "Origin: http://kotu-site.invalid" -H "Access-Control-Request-Method: GET" "$BASE/rest/languages"

echo "== V016: hata sayfası =="
yigin_yok "V016 bilinmeyen yol (500)"      500 "$BASE/rest/qwertz"
yigin_yok "V016 bilinmeyen yol, JSON (500)" 500 -H "Accept: application/json" "$BASE/api/qwertz"
# 406/410: yönlendirme ve XML yüklemeyi SY-3/SY-4 403 ile kesiyor; 410'a YAML yükleme ulaşır
yigin_yok "V016 YAML yükleme (410)"        410 -F "file=@-;filename=sikayet.yml;type=application/x-yaml" "$BASE/file-upload" <<< "sikayet: kontrol"
req       "V016 kontrol: giriş hatası 401" 401 -X POST "${JSON[@]}" --data '{"email":"ayse@ornek.com","password":"yanlis-sifre"}' "$BASE/rest/user/login"

echo
echo "Toplam $((gecen+kalan)) istek, $kalan beklenmeyen sonuç."
[ "$kalan" -eq 0 ]
