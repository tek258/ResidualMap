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
req "SQLi"                             403 -G "$BASE/rest/products/search" --data-urlencode "q=' OR 1=1--"
req "XSS"                              403 -G "$BASE/rest/products/search" --data-urlencode "q=<script>alert(1)</script>"
req "Path traversal"                   403 "$BASE/?file=../../../../etc/passwd"
req "Scanner UA"                       403 -A "sqlmap/1.7" "$BASE/"

echo "== V001: giriş, JSON POST gövdesinde SQLi =="
req "V001 kontrol: yanlış şifre"       401 -X POST "${JSON[@]}" --data '{"email":"ayse@ornek.com","password":"yanlis-sifre"}' "$BASE/rest/user/login"
req "V001 SQLi (email alanı)"          403 -X POST "${JSON[@]}" --data "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}" "$BASE/rest/user/login"

echo "== V003: sipariş takibi, yol içinde NoSQL enjeksiyonu =="
req "V003 kontrol: geçerli biçim"      200 "$BASE/rest/track-order/5267-f9cd5882f54c75a3"
req "V003 NoSQLi (' || true || ')"     403 "$BASE/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27"

echo "== V005: PUT /api/Products (I-1 ile açılan yol), gövdede XSS =="
# Var olmayan ürün (999999): WAF kapalı olsa bile lab verisi değişmez.
req "V005 kontrol: zararsız açıklama"  404 -X PUT "${JSON[@]}" --data '{"description":"Taze elma suyu"}' "$BASE/api/Products/999999"
req "V005 XSS (description alanı)"     403 -X PUT "${JSON[@]}" --data '{"description":"<iframe src=\"javascript:alert(`xss`)\">"}' "$BASE/api/Products/999999"

echo
echo "Toplam $((gecen+kalan)) istek, $kalan beklenmeyen sonuç."
[ "$kalan" -eq 0 ]
