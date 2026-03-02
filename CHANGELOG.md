# Commission Tracker — Refactor Changelog

## What Changed

### Bug Fix
- **Fixed `UnboundLocalError: vol_amt`** — the milestones section no longer references variables that only exist in one branch of an if/else.

### New: `app/payplan.py` — Unified Commission Engine
Replaced the old `payplan.py` (which only handled hardcoded product booleans for flat/gross/hybrid pay types) with a `CommissionEngine` class that handles everything:

- **`calc_deal()`** — commission for a single deal using dynamic `DealerProduct` add-ons instead of hardcoded `permaplate`/`nitro_fill`/etc. boolean fields. Supports all three pay types (flat, gross, hybrid).
- **`calc_bonuses()`** — bonus calculation from `DealerBonus` table. One code path, not two.
- **`calc_closing_rates()`** — dynamic closing rates for ALL products the dealership has configured, not just the hardcoded 4 (Pulse, Nitro, PermaPlate, Aim). Aim is still included as a special presentation metric.
- **`milestones()`** — generates milestone strings from bonus results.
- **`share_payload()`** — builds the community payplan sharing payload from dynamic products and bonuses instead of hardcoded Settings fields.

### Changed: `app/main.py`

**Dashboard (`async def dashboard`):**
- Removed the dual-path bonus calculation (legacy `if not custom_bonuses:` / `else:` fork). Now always uses the engine's `calc_bonuses()`.
- Removed hardcoded closing rates (Pulse, Nitro, PermaPlate, Aim). Now queries `DealProduct` join table and calculates closing rates for all dealer-defined products dynamically.
- Removed `_tiered()`, `_tiered_spot()`, `_next_tier()`, `_next_spot()` helper functions — replaced by the engine.
- `bonus_breakdown` always contains `custom_list` — the template no longer needs a legacy fallback.

**Deal Save (`async def deal_save`):**
- Products are now parsed from form BEFORE commission calculation (not after as a second pass).
- Commission is calculated once by the engine, including product add-ons, instead of being calculated then overwritten.
- Eliminates the double-commit pattern where commission was computed, committed, then re-computed with products and committed again.

**Inline Edit (`async def deal_inline_edit`):**
- Uses engine for commission recalculation, loading the deal's attached products.

**CSV Import (`async def import_csv`):**
- Uses engine for commission calculation (no products attached during import — those are added post-import via the deal form).

**Community Payplan Sharing:**
- Uses `engine.share_payload()` which includes dynamic products and bonuses instead of hardcoded Settings fields.

### Changed: Templates

**`dashboard.html`:**
- Closing rates section now iterates a list of `ClosingRate` objects (dynamic length) instead of a hardcoded dict of 4 keys. Grid columns adapt to the number of products.
- "Next Milestones" section removed the legacy fallback branch — always uses `custom_list`.
- Bonus breakdown modal removed the legacy fallback table rows.

**`deal_form.html`:**
- Live commission calculator JS now reads from a dynamic `PRODUCTS` map (product_id → commission) populated from the server, instead of hardcoded `SETTINGS.permaplate`, `SETTINGS.nitro_fill`, etc.
- Supports all pay types in the live calculator (flat, gross, hybrid) — was previously flat-only in JS.
- Watches all `product_*` checkboxes for recalculation.

### NOT Changed (backward compatible)
- **Database schema** — no migrations needed. The legacy boolean columns on `Deal` (`permaplate`, `nitro_fill`, etc.) and the legacy bonus fields on `Settings` still exist. Historical data is preserved. The payplan seeding logic still auto-creates `DealerProduct`/`DealerBonus` rows from legacy Settings values on first visit.
- **CSV Import** still reads legacy columns (permaplate, nitro, etc.) from imports and maps them. The DealIn schema still has these fields for backward compatibility.
- **CSV Export** still writes legacy column headers. Products attached via `DealProduct` are not yet included in exports (future enhancement).
- **The `api/` directory** is kept in sync. All files copied over.

## What's Left (Future)

1. **CSV Export enhancement** — include dynamic product columns instead of hardcoded 6.
2. **CSV Import enhancement** — match imported product columns to `DealerProduct` names and auto-create `DealProduct` rows.
3. **Remove legacy Settings bonus fields** — once all dealerships have been migrated to `DealerBonus`, the 13+ hardcoded bonus fields on Settings can be removed from the payplan form.
4. **Remove legacy Deal product booleans** — stop writing to `Deal.permaplate`, `Deal.nitro_fill`, etc. Keep columns for historical data but don't populate on new deals.
5. **Consolidate `app/` and `api/`** — these are near-identical copies. Should be one codebase.
