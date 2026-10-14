"""Show the default ladder with candidate counts and estimated seconds."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifi_tool import auto
from wifi_tool.options import ASSETS_DIR, find_extra_wordlist

stages = auto.build_ladder(
    quick=str(ASSETS_DIR / "probable-wpa.txt"),
    rockyou=str(ASSETS_DIR / "rockyou-wpa.txt"),
    rules=str(ASSETS_DIR / "hashcat-7.1.2" / "rules" / "best66.rule"),
    extra=find_extra_wordlist(ASSETS_DIR),
)
rate = auto.Rate()
total = 0.0
print(f"{'#':<3}{'ключ':<11}{'этап':<40}{'кандидатов':>15}{'секунд':>10}")
for i, s in enumerate(stages, 1):
    secs = s.seconds(rate)
    total += secs
    print(f"{i:<3}{s.key:<11}{s.title:<40}{int(s.candidates()):>15,}{secs:>10.1f}")
print(f"{'':<54}{'':>15}{total:>10.1f}")