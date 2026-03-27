# Astro drive audit script

Ez a script asztrofotós / képes külső drive-ok auditálására és takarítás-előkészítésére készült.

## Fő funkciók

- egzakt duplikátumok keresése SHA256 hash alapján
- Siril / stacking / process / collected_* jellegű köztes fájlok és mappák jelölése
- safe / review kategóriák szétválasztása
- progress bar és `--verbose`
- SQLite state DB a cache-elt hash-ekhez és a futások összehasonlításához
- opcionális karanténba mozgatás
- opcionális hard linkes duplikátumcsere

## Alap futás

```bash
python3 astro_drive_audit.py /Volumes/Archive
```

## Pictures mappa kizárása

```bash
python3 astro_drive_audit.py /Volumes/Archive --exclude-dir-name Pictures
```

## Verbose mód

```bash
python3 astro_drive_audit.py /Volumes/Archive --verbose
```

## Biztosabb találatok karanténba

```bash
python3 astro_drive_audit.py /Volumes/Archive --apply-safe --apply-duplicates
```

## Hardlinkes deduplikáció calibration library preferenciával

Ez a mód a KEEP példányt preferált útvonalról választja ki, majd a duplikált fájl helyére hard linket rak.

```bash
python3 astro_drive_audit.py /Volumes/Archive \
  --apply-duplicate-hardlinks \
  --canonical-prefer-path Astro/calibration_library \
  --exclude-dir-name Pictures
```

## Hardlink + karantén

Ebben a módban a duplikált külön példány előbb karanténba kerül, majd az eredeti helyére hard link jön vissza.

```bash
python3 astro_drive_audit.py /Volumes/Archive \
  --apply-duplicate-hardlinks \
  --hardlink-with-quarantine \
  --canonical-prefer-path Astro/calibration_library
```

Megjegyzés: ez rendezettebb és biztonságosabb, de a karanténban megmaradó régi példányok miatt nem ad maximális azonnali helynyereséget.

## Hardlinkelhető mappatípusok

Alapértelmezésben ezek engedettek:

- `dark`
- `darks`
- `bias`
- `biases`
- `flat`
- `flats`

Bővíthető például így:

```bash
python3 astro_drive_audit.py /Volumes/Archive \
  --apply-duplicate-hardlinks \
  --canonical-prefer-path Astro/calibration_library \
  --hardlink-dir-name lights \
  --hardlink-dir-name collected_lights
```

Ezt csak akkor használd, ha biztos vagy benne, hogy ezek a fájlok immutábilisak és semmilyen workflow nem ír vissza beléjük.

## Fontos

- a hard link **nem shortcut**, hanem ugyanarra az inode-ra mutató másik név
- ugyanazon a volume-on működik
- először mindig riporttal vagy kisebb mintán próbáld ki
- Lightroom / Final Cut / PixInsight project jellegű fájlokra ne ereszd rá vakon
