"""Dosyaya bütün olarak yazma: arka plandaki bir iş dosyayı yazarken sayfa yarım dosya okumasın."""

import os
import time
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def atomik(path, **acma):
    """`with atomik(yol, newline="") as f:` geçici dosyaya yazar, bitince yerine koyar."""
    path = Path(path)
    gecici = path.with_name(f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    try:
        with open(gecici, "w", encoding="utf-8", **acma) as f:
            yield f
        for deneme in range(10):   # Windows: dosya o an okunuyorsa kısa bir süre kilitli olabilir
            try:
                os.replace(gecici, path)
                break
            except PermissionError:
                if deneme == 9:
                    raise
                time.sleep(0.05)
    finally:
        gecici.unlink(missing_ok=True)
