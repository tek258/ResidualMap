"""Arka plan işleri: uzun süren işler (tarama, AI skorlama, AI önerisi, savunma testi, plan
açıklaması) sayfa değişince yarıda kalmasın diye ayrı bir iş parçacığında çalışır.

Streamlit her tıklamada betiği baştan çalıştırır; başka bir adıma geçmek de bir tıklamadır ve
o sırada betikte çalışan iş kesilir. Burada iş, Streamlit sunucusunun içinde ayrı bir iş
parçacığına verilir. Sayfa yalnızca işin durumunu okur:
  - İşi başlatan adım ilerlemeyi gösterir (iki saniyede bir güncellenen parça).
  - Yan menüde süren işler her adımdan görünür.
  - İş bitince sayfa bir kez yenilenir, sonuç işi başlatan adımda gösterilir.
İş sunucu kapanana kadar sürer; tarayıcı sekmesi kapansa ya da yenilense de devam eder.

İş fonksiyonu Streamlit çağırmaz (st.* yalnızca sayfanın iş parçacığında çalışır); ilerlemeyi
`is_.ilerle()` ve `is_.satir()` ile bildirir, iptal isteğini `is_.iptal_mi()` ile denetler.
"""

import threading
import time
import traceback

import streamlit as st

CALISIYOR, BITTI, HATA, IPTAL = "çalışıyor", "bitti", "hata", "iptal edildi"


class Is:
    def __init__(self, anahtar, baslik):
        self.anahtar, self.baslik = anahtar, baslik
        self.durum, self.ilerleme, self.mesaj = CALISIYOR, None, "Başlıyor…"
        self.gunluk, self.sonuc, self.hata = [], None, ""
        self.baslangic, self.bitis = time.time(), None
        self._iptal = threading.Event()
        self.goruldu = False          # sonuç işi başlatan adımda bir kez gösterildi mi

    # --- iş fonksiyonunun kullandıkları ---
    def ilerle(self, oran=None, mesaj=None):
        if oran is not None:
            self.ilerleme = max(0.0, min(1.0, oran))
        if mesaj:
            self.mesaj = mesaj

    def satir(self, metin, en_fazla=200):
        if metin:
            self.gunluk.append(metin)
            del self.gunluk[:-en_fazla]

    def iptal_mi(self):
        return self._iptal.is_set()

    # --- sayfanın kullandıkları ---
    @property
    def suruyor(self):
        return self.durum == CALISIYOR

    def iptal_et(self):
        self._iptal.set()
        self.mesaj = "İptal ediliyor (sıradaki adımdan önce durur)…"

    def sure(self):
        return (self.bitis or time.time()) - self.baslangic


@st.cache_resource
def _kayit():
    """Sunucu genelinde tek kayıt: yeniden çalıştırmalarda ve oturumlar arasında aynı kalır."""
    return {"isler": {}, "kilit": threading.Lock()}


def bul(anahtar):
    return _kayit()["isler"].get(anahtar)


def suruyor_mu(anahtar):
    i = bul(anahtar)
    return bool(i and i.suruyor)


def baslat(anahtar, baslik, fonk):
    """fonk(is_) ayrı iş parçacığında çalışır; dönüş değeri is_.sonuc olur. Aynı anahtarla
    süren bir iş varsa yenisi başlatılmaz, süren iş döner."""
    k = _kayit()
    with k["kilit"]:
        eski = k["isler"].get(anahtar)
        if eski and eski.suruyor:
            return eski
        is_ = Is(anahtar, baslik)
        k["isler"][anahtar] = is_

    def _calis():
        try:
            is_.sonuc = fonk(is_)
            is_.durum = IPTAL if is_.iptal_mi() else BITTI
        except Exception as e:      # iş parçacığındaki hata sayfaya taşınır
            is_.hata = f"{type(e).__name__}: {e}"
            is_.satir(traceback.format_exc())
            is_.durum = HATA
        finally:
            is_.bitis = time.time()
            if is_.durum != HATA:
                is_.ilerleme = 1.0

    threading.Thread(target=_calis, name=f"is-{anahtar}", daemon=True).start()
    return is_


def temizle(anahtar):
    i = bul(anahtar)
    if i and not i.suruyor:
        _kayit()["isler"].pop(anahtar, None)


def aktifler():
    return [i for i in _kayit()["isler"].values() if i.suruyor]


def _cubuk(i, gunluk_satir=0):
    oran = i.ilerleme if i.ilerleme is not None else min(0.95, i.sure() / 120)
    st.progress(oran, text=f"{i.mesaj} · {i.sure():.0f} sn")
    if gunluk_satir and i.gunluk:
        st.code("\n".join(i.gunluk[-gunluk_satir:]), language=None)


def ilerleme(anahtar, gunluk_satir=0, iptal=True):
    """İşi başlatan adımda ilerleme. İş sürerken iki saniyede bir kendini yeniler; bitince bütün
    sayfayı bir kez yeniler. Dönüş: iş sürüyorsa True (sayfa buna göre düğmeleri kapatabilir)."""
    i = bul(anahtar)
    if not i or not i.suruyor:
        return False

    @st.fragment(run_every=2)
    def _parca():
        j = bul(anahtar)
        if not j or not j.suruyor:
            st.rerun()             # bütün sayfa: sonuç gösterilsin, düğmeler açılsın
        with st.container(border=True):
            st.markdown(f"**{j.baslik}** · arka planda çalışıyor, başka adımlara geçebilirsiniz.")
            _cubuk(j, gunluk_satir)
            if iptal and st.button("İptal et", key=f"iptal_{anahtar}", disabled=j.iptal_mi()):
                j.iptal_et()
    _parca()
    return True


def sonuc(anahtar):
    """İş bittiyse (ve sonucu daha önce gösterilmediyse) işi döndürür; sayfa sonucu gösterir."""
    i = bul(anahtar)
    if not i or i.suruyor or i.goruldu:
        return None
    i.goruldu = True
    return i


def yan_menu():
    """Yan menüde süren işler; her adımdan görünür. Biten iş sayfayı bir kez yeniler."""
    if not aktifler():
        return

    @st.fragment(run_every=2)
    def _parca():
        suren = aktifler()
        if not suren:
            st.rerun()
        st.caption("Arka planda")
        for i in suren:
            oran = i.ilerleme if i.ilerleme is not None else min(0.95, i.sure() / 120)
            st.progress(oran, text=f"{i.baslik}: {i.mesaj}")
    _parca()
