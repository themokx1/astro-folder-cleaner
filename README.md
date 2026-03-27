# Astro drive audit script

Ez a script asztrofotós / képes külső drive-ok auditálására készült.

## Mit tud?

- egzakt duplikátumok keresése `SHA256` alapján
- Siril / stacking köztes fájlok felismerése
- tipikus cache / temp / preview / log szemét jelölése
- `SAFE_QUARANTINE` / `REVIEW_BEFORE_DELETE` szétválasztás
- progress bar
- `--verbose` mód
- SQLite state DB:
  - hash cache
  - félbehagyott futás utáni gyorsabb folytatás
  - előző futással összehasonlítás

## Fontos változás az előző verzióhoz képest

A script most már állapotot ment:
- alapértelmezett DB helye:  
  `<root>/.astro_audit_state/astro_audit_state.sqlite`

Ez alapján a következő futás:
- nem hash-eli újra a változatlan fájlokat
- tud az előző runhoz hasonlítani
- megszakítás után is értelmesen folytatható

## Alap használat

```bash
python3 astro_drive_audit.py /Volumes/Archive
```

## Pictures mappa kizárása

Bárhol a fa alatt minden `Pictures` nevű mappa kizárása:

```bash
python3 astro_drive_audit.py /Volumes/Archive --exclude-dir-name Pictures
```

Konkrét útvonal kizárása:

```bash
python3 astro_drive_audit.py /Volumes/Archive --exclude-path Pictures
```

vagy

```bash
python3 astro_drive_audit.py /Volumes/Archive --exclude-path /Volumes/Archive/Pictures
```

## Verbose mód

```bash
python3 astro_drive_audit.py /Volumes/Archive --verbose
```

Ilyenkor minden fontosabb lépést kiír, és a hash-elésnél minden fájlt külön logol.

## Progress bar kikapcsolása

```bash
python3 astro_drive_audit.py /Volumes/Archive --no-progress
```

## Karanténba mozgatás

```bash
python3 astro_drive_audit.py /Volumes/Archive --apply-safe --apply-duplicates
```

## Saját state DB hely megadása

```bash
python3 astro_drive_audit.py /Volumes/Archive --state-db ~/astro_audit_state.sqlite
```

## Riport fájlok

A riport mappában több fájl keletkezik:

- `summary.json`
- `compare_to_previous_run.json`
- `all_findings.csv`
- `safe_candidates.csv`
- `review_candidates.csv`
- `duplicates.csv`
- `safe_quarantine_paths.txt`
- `review_first_paths.txt`
- `move_log.json` (ha volt mozgatás)

## Mit jelent a félbehagyott futás utáni folytatás?

A drága rész jellemzően a hash-elés.  
Ha a script megszakad, a már hash-elt, változatlan fájlok hash-e megmarad az SQLite DB-ben.  
A következő futás ezeknél cache hitet kap, így onnan folytatja érdemben, nem nulláról.

## Mire figyelj?

- Nem töröl véglegesen automatikusan.
- A `REVIEW_BEFORE_DELETE` találatokat nézd át kézzel.
- Először mindig riporttal futtasd.

