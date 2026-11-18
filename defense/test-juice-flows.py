#!/usr/bin/env python3
"""Juice Shop'un normal kullanici akislarini WAF uzerinden oynatir.

Amac: WAF engelleme modundayken (MODSEC_RULE_ENGINE=On) mesru trafigin
yanlislikla 403 alip almadigini gormek. Saldiri payload'u YOKTUR; tarayicinin
gonderdigi isteklerin aynisi (basliklar, JSON govdeler, cerezler) gonderilir.

Kullanim:  python3 test-juice-flows.py [http://localhost:8080]
Cikis kodu: tum adimlar beklenen kodu donerse 0, aksi halde 1.
Sadece standart kutuphane kullanir.
"""
import json
import sys
import time
import uuid
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")

cookies = {"language": "en", "welcomebanner_status": "dismiss",
           "cookieconsent_status": "dismiss"}
token = None
results = []


def call(label, method, path, body=None, ctype="application/json", ok=(200, 201)):
    headers = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Referer": BASE + "/",
        "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items()),
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode() if ctype == "application/json" else body.encode()
        headers["Content-Type"] = ctype if ctype != "application/json" else "application/json"
        headers["Origin"] = BASE
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            code, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read()
    status = "OK " if code in ok else "HATA"
    results.append((status, code, method, path, label))
    print(f"[{status}] {code} {method:6} {path[:60]:60} {label}")
    try:
        return json.loads(raw)
    except Exception:
        return None


uid = uuid.uuid4().hex[:8]
email = f"ayse.{uid}@ornek.com.tr"
password = "Gizli!Sifre#2026"

print("== Vitrin ve arama ==")
call("ana sayfa", "GET", "/", ok=(200,))
call("uygulama ayari", "GET", "/rest/admin/application-configuration")
call("dil listesi", "GET", "/rest/languages")
call("bos arama (vitrin)", "GET", "/rest/products/search?q=")
for q in ["apple", "apple juice", "Juice (1000ml)", "elma suyu", "çilek",
          "T-Shirt", "Owasp Juice Shop Sticker", "green smoothie 500ml"]:
    call(f"arama: {q}", "GET", "/rest/products/search?q=" + urllib.request.quote(q))
call("urun yorumlari", "GET", "/rest/products/1/reviews")
hs = urllib.request.urlopen(urllib.request.Request(
    f"{BASE}/socket.io/?EIO=4&transport=polling&t={uid}a", headers={"User-Agent": UA}),
    timeout=15).read().decode(errors="replace")
call("socket.io polling (GET)", "GET", f"/socket.io/?EIO=4&transport=polling&t={uid}")
sid = json.loads(hs[hs.find("{"):]).get("sid") if "{" in hs else None
if sid:
    # Tarayici polling modunda govdeyi text/plain olarak POST eder
    call("socket.io polling (POST text/plain)", "POST",
         f"/socket.io/?EIO=4&transport=polling&t={uid}b&sid={sid}", "40",
         ctype="text/plain;charset=UTF-8")

print("== Kayit ve giris ==")
call("guvenlik sorulari", "GET", "/api/SecurityQuestions/")
call("kayit", "POST", "/api/Users/", {
    "email": email, "password": password, "passwordRepeat": password,
    "securityQuestion": {"id": 2, "question": "Your eldest siblings middle name?",
                         "createdAt": "2026-11-17T10:00:00.000Z",
                         "updatedAt": "2026-11-17T10:00:00.000Z"},
    "securityAnswer": "Mehmet"})
login = call("giris", "POST", "/rest/user/login", {"email": email, "password": password})
if not login or "authentication" not in login:
    print("Giris basarisiz, akisin geri kalani atlaniyor.")
    sys.exit(1)
auth = login["authentication"]
token, bid = auth["token"], auth["bid"]
cookies["token"] = token
call("whoami", "GET", "/rest/user/whoami")
call("yanlis sifreyle giris (401 beklenir)", "POST", "/rest/user/login",
     {"email": email, "password": "yanlis-sifre"}, ok=(401,))

print("== Sepet ==")
call("sepeti gor", "GET", f"/rest/basket/{bid}")
call("stok bilgisi", "GET", "/api/Quantitys/")
item = call("sepete ekle", "POST", "/api/BasketItems/",
            {"ProductId": 1, "BasketId": str(bid), "quantity": 1})
item2 = call("sepete ikinci urun", "POST", "/api/BasketItems/",
             {"ProductId": 6, "BasketId": str(bid), "quantity": 1})
iid = (item or {}).get("data", {}).get("id")
iid2 = (item2 or {}).get("data", {}).get("id")
if iid:
    call("adet artir (PUT)", "PUT", f"/api/BasketItems/{iid}", {"quantity": 2})
if iid2:
    call("urunu sil (DELETE)", "DELETE", f"/api/BasketItems/{iid2}")
call("sepeti tekrar gor", "GET", f"/rest/basket/{bid}")

print("== Yorum ==")
call("urun yorumu yaz (PUT)", "PUT", "/rest/products/1/reviews",
     {"message": "Taze ve lezzetli, tavsiye ederim!", "author": email})

print("== Adres, kart, odeme ==")
addr = call("adres ekle", "POST", "/api/Addresss/", {
    "country": "Türkiye", "fullName": "Ayşe Yılmaz", "mobileNum": 5551234567,
    "zipCode": "06690", "streetAddress": "Atatürk Bulvarı No:12 D:3",
    "city": "Ankara", "state": "Çankaya"})
call("adresleri listele", "GET", "/api/Addresss/")
card = call("kart ekle", "POST", "/api/Cards/", {
    "fullName": "Ayse Yilmaz", "cardNum": 4111111111111111,
    "expMonth": 12, "expYear": 2090})
call("teslimat secenekleri", "GET", "/api/Deliverys/")
call("cuzdan bakiyesi", "GET", "/rest/wallet/balance")
aid = (addr or {}).get("data", {}).get("id")
cid = (card or {}).get("data", {}).get("id")
if aid and cid:
    call("siparisi tamamla", "POST", f"/rest/basket/{bid}/checkout", {
        "couponData": "bnVsbA==",
        "orderDetails": {"paymentId": str(cid), "addressId": str(aid),
                         "deliveryMethodId": "1"}})
call("siparis gecmisi", "GET", "/rest/order-history")

print("== Sepet ek islemleri ==")
call("kupon uygula (PUT, gecersiz kupon 404 beklenir)", "PUT",
     f"/rest/basket/{bid}/coupon/" + urllib.request.quote("WMNSDY2026"), {}, ok=(200, 404))
call("cuzdana para yukle (PUT)", "PUT", "/rest/wallet/balance",
     {"balance": 50, "paymentId": str(cid or 1)})
yorumlar = call("yorumlari tekrar oku", "GET", "/rest/products/1/reviews") or {}
rid = next((r.get("_id") for r in yorumlar.get("data", [])
            if r.get("author") == email), None)
if rid:
    call("yorumu duzenle (PATCH)", "PATCH", "/rest/products/reviews",
         {"id": rid, "message": "Guncelleme: hala cok begeniyorum."})
    call("yorumu begen (POST)", "POST", "/rest/products/reviews", {"id": rid})

print("== Adres ve kart yonetimi ==")
if aid:
    call("adresi duzenle (PUT)", "PUT", f"/api/Addresss/{aid}", {
        "country": "Türkiye", "fullName": "Ayşe Yılmaz", "mobileNum": 5551234567,
        "zipCode": "34710", "streetAddress": "Bağdat Cad. No:5/7",
        "city": "İstanbul", "state": "Kadıköy"})
    call("adresi sil (DELETE)", "DELETE", f"/api/Addresss/{aid}")
if cid:
    call("karti sil (DELETE)", "DELETE", f"/api/Cards/{cid}")

print("== Destek ve takip ==")
cap = call("captcha al", "GET", "/rest/captcha/") or {}
call("iletisim formu", "POST", "/api/Feedbacks/", {
    "captchaId": cap.get("captchaId"),
    "captcha": cap.get("answer"), "comment": "Siparisim cok hizli geldi, tesekkurler! (***)",
    "rating": 5})
orders = call("siparisleri listele", "GET", "/rest/order-history") or {}
oid = next((o.get("orderId") for o in orders.get("data", [])), None)
if oid:
    call("siparis takibi", "GET", "/rest/track-order/" + urllib.request.quote(oid))
boundary = "----WebKitFormBoundary" + uid
pdf = "%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
form = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        f"filename=\"fatura.pdf\"\r\nContent-Type: application/pdf\r\n\r\n{pdf}\r\n"
        f"--{boundary}--\r\n")
call("sikayet dosyasi yukle (multipart)", "POST", "/file-upload", form,
     ctype=f"multipart/form-data; boundary={boundary}", ok=(200, 204))
call("veri disa aktarma captcha", "GET", "/rest/image-captcha/")

print("== Ozel karakterli sifreler ==")
for i, pw in enumerate(["Ayşe'nin-Sifresi1", "kedi&kopek=2026", "P@ss w0rd; <3",
                        "Sifre\"123\"!", "1q2w3e4r--", "admin123#"]):
    e2 = f"sifre{i}.{uid}@ornek.com.tr"
    call(f"kayit, sifre: {pw}", "POST", "/api/Users/", {
        "email": e2, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "Pamuk"})
    call(f"giris, sifre: {pw}", "POST", "/rest/user/login", {"email": e2, "password": pw})

print("== Profil ==")
call("sifre degistir", "GET",
     "/rest/user/change-password?current=" + urllib.request.quote(password)
     + "&new=" + urllib.request.quote("Yeni!Sifre#2026")
     + "&repeat=" + urllib.request.quote("Yeni!Sifre#2026"))

print("== Istisnalarin siniri (403 beklenir) ==")
# Istisnalar dar mi? Listede olmayan yol/metod ve whoami'deki saldiri hala engellenmeli.
call("PUT listede olmayan yol", "PUT", "/api/Users/1", {"role": "admin"}, ok=(403,))
call("DELETE listede olmayan yol", "DELETE", "/api/Products/1", ok=(403,))
call("PATCH listede olmayan yol", "PATCH", "/api/BasketItems/1", {"quantity": 1}, ok=(403,))
call("PUT yol sonuna ek", "PUT", "/api/BasketItems/1/../../Users/1", {}, ok=(403,))
call("TRACE metodu", "TRACE", "/", ok=(403, 405))
call("whoami + komut parametresi", "GET",
     "/rest/user/whoami?cb=" + urllib.request.quote(";cat /etc/passwd"), ok=(403,))
call("text/plain baska yolda", "POST", "/rest/user/login", "email=a&password=b",
     ctype="text/plain;charset=UTF-8", ok=(403,))
# Not: socket.io govdesi (text/plain) icerik olarak denetlenmez; bu bir WAF
# sinirlamasidir, istisna kaynakli degildir. Ayrinti: docs/waf-engelleme-notu.md, I-3.
call("whoami baska yolda", "GET", "/rest/products/search?q=" + urllib.request.quote(";whoami"),
     ok=(403,))

bad = [r for r in results if r[0] != "OK "]
print(f"\nToplam {len(results)} istek, {len(bad)} beklenmeyen sonuc.")
for _, code, m, p, label in bad:
    print(f"  {code} {m} {p}  ({label})")
sys.exit(1 if bad else 0)
