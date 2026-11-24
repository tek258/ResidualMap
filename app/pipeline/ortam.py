"""Uygulamanın arkada ihtiyaç duyduğu ortamı başlatma: Docker Desktop, lab (defense/
docker-compose.yml, savunma panosu dahil) ve Ollama + model v2'nin modeli.

Çalıştırılan komutların hepsi sabittir; kullanıcının yazdığı hiçbir şey komuta girmez.
Yalnızca yerel bileşenler başlatılır. Docker Desktop'ın ve Ollama'nın kurulumu (WSL, yönetici
izni) burada yapılmaz: kurulu değilse ne yapılacağı söylenir (KURULUM.md).
"""

import json
import os
import platform
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from config import OLLAMA_URL, REPO_ROOT

DEFENSE_DIR = REPO_ROOT / "defense"
SISTEM = platform.system()            # "Windows", "Darwin", "Linux"
EV = Path.home()


def _ilk_var(adaylar):
    for a in adaylar:
        if a and Path(a).is_file():
            return str(a)
    return None


def _windows_docker_klasorleri():
    """Docker Desktop'ın kurulu olabileceği klasörler: makine geneli (Program Files), kullanıcıya
    özel kurulum (%LOCALAPPDATA%\\Programs\\DockerDesktop) ve Windows'un kayıtlı kurulum yeri."""
    klasorler = []
    try:
        import winreg
        for kok in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(kok, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop") as k:
                    klasorler.append(Path(winreg.QueryValueEx(k, "InstallLocation")[0]))
            except OSError:
                pass
    except ImportError:
        pass
    yerel = os.environ.get("LOCALAPPDATA")
    if yerel:
        klasorler.append(Path(yerel) / "Programs" / "DockerDesktop")
    klasorler.append(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker")
    return klasorler


def docker_desktop_exe():
    if SISTEM != "Windows":
        return None
    return _ilk_var([k / "Docker Desktop.exe" for k in _windows_docker_klasorleri()])


def docker_yolu():
    """docker komutu. PATH'te yoksa Docker Desktop'ın bilinen kurulum yerlerine bakılır
    (Mac'te uygulama Finder'dan açılınca /usr/local/bin ya da ~/.docker/bin PATH'te olmayabilir)."""
    if SISTEM == "Windows":
        return shutil.which("docker") or _ilk_var(
            [k / "resources" / "bin" / "docker.exe" for k in _windows_docker_klasorleri()])
    return shutil.which("docker") or _ilk_var([
        "/usr/local/bin/docker", "/opt/homebrew/bin/docker", EV / ".docker" / "bin" / "docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
        EV / "Applications" / "Docker.app" / "Contents" / "Resources" / "bin" / "docker"])


def docker_komutu():
    """Her seferinde yeniden bakılır: Mac'te komut Docker Desktop'ın ilk açılışında kurulabiliyor.
    Komut PATH dışında bulunursa klasörü bu sürecin PATH'ine eklenir; docker compose ve imaj
    indirirken kullanılan yardımcı komutlar (docker-credential-desktop gibi) aynı klasördedir."""
    yol = docker_yolu()
    if not yol:
        return "docker"
    klasor = str(Path(yol).parent)
    if klasor not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = klasor + os.pathsep + os.environ.get("PATH", "")
    return yol


def _compose():
    return [docker_komutu(), "compose", "--profile", "siem"]


def _mac_uygulamasi(ad):
    """Mac'te uygulama kurulu mu? (/Applications, ~/Applications ya da LaunchServices'in bildiği başka bir yer)"""
    if Path(f"/Applications/{ad}.app").exists() or (EV / "Applications" / f"{ad}.app").exists():
        return True
    r = _calistir(["open", "-Ra", ad], timeout=10)
    return bool(r and r.returncode == 0)


@dataclass
class Sonuc:
    ok: bool
    mesaj: str


def _calistir(args, timeout=20, cwd=None):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                              encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "zaman aşımı")


def _arka_planda(args, cwd=None):
    """Süreci uygulamadan bağımsız başlatır (uygulama kapansa da çalışmaya devam eder)."""
    ek = {}
    if SISTEM == "Windows":
        ek["creationflags"] = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                               | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    else:
        ek["start_new_session"] = True
    subprocess.Popen(args, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, **ek)


def _bekle(kosul, sure, aralik=3):
    son = time.time() + sure
    while time.time() < son:
        if kosul():
            return True
        time.sleep(aralik)
    return kosul()


# --- Docker ---
def docker_kurulu():
    return (docker_yolu() is not None or (SISTEM == "Windows" and docker_desktop_exe() is not None)
            or (SISTEM == "Darwin" and _mac_uygulamasi("Docker")))


def docker_hazir():
    r = _calistir([docker_komutu(), "info", "--format", "{{.ServerVersion}}"], timeout=10)
    return bool(r and r.returncode == 0 and r.stdout.strip())


def docker_desktop_baslat():
    if SISTEM == "Windows":
        yol = docker_desktop_exe()
        if not yol:
            return Sonuc(False, "Docker Desktop bulunamadı (Program Files ve %LOCALAPPDATA%\\Programs\\DockerDesktop "
                                "denendi). Kurulum: KURULUM.md")
        _arka_planda([yol])
    elif SISTEM == "Darwin":
        if not _mac_uygulamasi("Docker"):
            return Sonuc(False, "Docker Desktop bulunamadı (Uygulamalar klasöründe Docker.app yok). Kurulum: KURULUM.md")
        _arka_planda(["open", "-g", "-a", "Docker"])   # -g: arka planda, öne gelmeden
    else:
        r = _calistir(["systemctl", "--user", "start", "docker-desktop"], timeout=20)
        if not r or r.returncode != 0:
            return Sonuc(False, "Docker başlatılamadı. Linux'ta Docker servisini başlatın: "
                                "`sudo systemctl start docker`")
    return Sonuc(True, "Docker Desktop başlatıldı.")


# --- Lab (defense/docker-compose.yml) ---
def lab_durumu():
    """{servis: durum} ya da Docker hazır değilse None."""
    r = _calistir([*_compose(), "ps", "--all", "--format", "json"], timeout=20, cwd=DEFENSE_DIR)
    if not r or r.returncode != 0:
        return None
    metin = r.stdout.strip()
    if not metin:
        return {}
    try:   # compose sürümüne göre tek bir dizi ya da satır başına bir nesne
        kayitlar = json.loads(metin) if metin.startswith("[") else [json.loads(s) for s in metin.splitlines() if s.strip()]
    except ValueError:
        return {}
    return {k.get("Service", k.get("Name", "?")): (k.get("State") or "").lower() for k in kayitlar}


def lab_servisleri():
    r = _calistir([*_compose(), "config", "--services"], timeout=20, cwd=DEFENSE_DIR)
    return [s for s in (r.stdout.split() if r and r.returncode == 0 else []) if s]


def lab_baslat(satir_cb=None, timeout=1800):
    """`docker compose --profile siem up -d`. İlk seferde imajları indirir (birkaç GB)."""
    try:
        p = subprocess.Popen([*_compose(), "up", "-d"], cwd=DEFENSE_DIR, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return Sonuc(False, "Docker komutu bulunamadı.")
    son, t0 = "", time.time()
    for satir in p.stdout:
        son = satir.strip() or son
        if satir_cb and son:
            satir_cb(son)
        if time.time() - t0 > timeout:
            p.kill()
            return Sonuc(False, "Lab başlatma zaman aşımına uğradı.")
    p.wait()
    return Sonuc(p.returncode == 0, "Lab başlatıldı." if p.returncode == 0 else f"Lab başlatılamadı: {son}")


def lab_durdur():
    r = _calistir([*_compose(), "stop"], timeout=180, cwd=DEFENSE_DIR)
    return Sonuc(bool(r and r.returncode == 0), "Lab durduruldu." if r and r.returncode == 0
                 else "Lab durdurulamadı: " + ((r.stderr or r.stdout).strip()[-200:] if r else "Docker yok."))


def http_hazir(url, timeout=3):
    try:
        with urllib.request.urlopen(url.replace("://localhost", "://127.0.0.1"), timeout=timeout) as y:
            return y.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


# --- Ollama ---
def ollama_calisiyor():
    return http_hazir(f"{OLLAMA_URL}/api/tags", timeout=2)


def _ollama_yolu():
    yol = shutil.which("ollama")
    if yol:
        return yol
    if SISTEM == "Windows":
        return _ilk_var([Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe"])
    return _ilk_var(["/opt/homebrew/bin/ollama", "/usr/local/bin/ollama",          # Homebrew (Apple Silicon / Intel)
                     "/Applications/Ollama.app/Contents/Resources/ollama"])


def ollama_kurulu():
    return bool(_ollama_yolu() or (SISTEM == "Darwin" and _mac_uygulamasi("Ollama")))


def ollama_baslat():
    if SISTEM == "Darwin" and _mac_uygulamasi("Ollama"):
        _arka_planda(["open", "-g", "-a", "Ollama"])   # menü çubuğu uygulaması sunucuyu kendisi açar
        return Sonuc(True, "Ollama başlatıldı.")
    yol = _ollama_yolu()
    if not yol:
        return Sonuc(False, "Ollama bulunamadı. Kurulum: KURULUM.md (isteğe bağlı, yalnızca AI için).")
    _arka_planda([yol, "serve"])
    return Sonuc(True, "Ollama başlatıldı.")


def model_yuklu(model):
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3) as y:
            return model in {m["name"] for m in json.loads(y.read().decode("utf-8")).get("models", [])}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def model_indir(model, ilerleme_cb=None):
    """`ollama pull` ile aynı: /api/pull akışı, ilerleme (0-1) ve durum metni bildirilir."""
    istek = urllib.request.Request(f"{OLLAMA_URL}/api/pull", data=json.dumps({"model": model}).encode(),
                                   headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(istek, timeout=3600) as y:
            for satir in y:
                veri = json.loads(satir.decode("utf-8") or "{}")
                if "error" in veri:
                    return Sonuc(False, f"Model indirilemedi: {veri['error']}")
                if ilerleme_cb:
                    tam, top = veri.get("completed"), veri.get("total")
                    ilerleme_cb(tam / top if tam and top else None, veri.get("status", ""))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return Sonuc(False, f"Model indirilemedi: {e}")
    return Sonuc(True, f"{model} indirildi.")


def model_isit(model):
    """Modeli belleğe yükler (ilk AI çağrısındaki 10-20 sn bekleme demodan önceye alınır)."""
    istek = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate", headers={"Content-Type": "application/json"},
        data=json.dumps({"model": model, "prompt": "ok", "stream": False, "keep_alive": "60m",
                         "options": {"num_predict": 1}}).encode())
    t0 = time.time()
    try:
        with urllib.request.urlopen(istek, timeout=180) as y:
            y.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return Sonuc(False, f"Model yüklenemedi: {e}")
    return Sonuc(True, f"{model} belleğe yüklendi ({time.time() - t0:.0f} sn), 60 dk açık kalır.")
