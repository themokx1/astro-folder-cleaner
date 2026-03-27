# Astro Drive Audit v4

Ez a verzió már nem csak duplikátumot keres, hanem kifejezetten nagy astro / photo workflow drive-okhoz ad használható riportokat és biztonságosabb takarítási opciókat.

## Új dolgok ebben a verzióban

- védett útvonalak és mappanevek
    - elemezhetőek, de automatikusan nem mozgatja és nem hardlinkeli őket
- szabályfájl alapú kizárás és védelem
    - `--exclude-from-file`
    - `--protect-from-file`
- package tartalom kihagyása
    - pl. `.lrlibrary`, `.lrdata`, `.fcpbundle`
    - `--skip-package-content`
- hotspot riportok
    - top mappák mélységenként
    - top kiterjesztések
    - top kategóriák
    - top duplikátumcsoportok
- üres mappák riportja és opcionális törlése
    - `--prune-empty-dirs`
- inode-aware duplikátum kezelés
    - a már hardlinkelt példányokat külön kezeli, nem úgy tekinti, mintha még egyszer ugyanannyi helyet lehetne nyerni rajtuk
- hardlinkes duplikátumcsere továbbra is támogatott
    - preferált kanonikus útvonalakkal
    - opcionális karanténos móddal

## Különösen hasznos opciók nálad

### Pictures teljes kihagyása
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive --exclude-dir-name Pictures
```

### Pictures elemzése, de automatikus módosítás tiltása
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive --protect-dir-name Pictures
```

### Kizárások külön fájlból
`exclude_rules.txt`
```txt
Pictures
Videos
Astro/tools
```

Futtatás:
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive --exclude-from-file exclude_rules.txt
```

### Védett útvonalak külön fájlból
`protect_rules.txt`
```txt
Pictures
Astro/stacks
Astro/processed
```

Futtatás:
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive --protect-from-file protect_rules.txt
```

### Package tartalmak kihagyása
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive --skip-package-content
```

### Hardlinkes dedup calibration library preferálással
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive \
  --protect-dir-name Pictures \
  --apply-duplicate-hardlinks \
  --canonical-prefer-path Astro/calibration_library
```

### Hardlink + karantén
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive \
  --protect-dir-name Pictures \
  --apply-duplicate-hardlinks \
  --hardlink-with-quarantine \
  --canonical-prefer-path Astro/calibration_library
```

### Üres mappák törlése apply után
```bash
python3 astro_drive_audit_v4.py /Volumes/Archive \
  --apply-duplicate-hardlinks \
  --canonical-prefer-path Astro/calibration_library \
  --prune-empty-dirs
```

## Főbb riportok

- `summary.json`
- `all_findings.csv`
- `safe_candidates.csv`
- `review_candidates.csv`
- `duplicates.csv`
- `duplicate_groups.csv`
- `top_extensions.csv`
- `top_categories.csv`
- `top_directories_depth_1.csv`
- `top_directories_depth_2.csv`
- `top_directories_depth_3.csv`
- `empty_dirs.csv`
- `hardlink_log.json` ha volt hardlink csere
- `restore_hardlinks_from_quarantine.sh` ha karanténos hardlink mód volt és van mit visszaállítani

## Fontos megjegyzés

- A `--hardlink-with-quarantine` biztonságosabb, de nem ad teljes azonnali helynyereséget, mert a régi példány a karanténban még megmarad.
- A sima hardlink csere ad valódi deduplikációt.
- A `protect` nem ugyanaz, mint az `exclude`:
    - `exclude` = ne is elemezze
    - `protect` = elemezze, de ne nyúljon hozzá automatikusan
