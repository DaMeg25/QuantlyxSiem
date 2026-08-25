# Quantlyx logotype

## Files

| File | Use |
|---|---|
| `quantlyx-logo-dark.svg` | Primary. Dark surfaces: the console, dark exports. |
| `quantlyx-logo-light.svg` | Primary. Light surfaces: documents, letterhead, printed reports. |
| `quantlyx-logo-mono.svg` | One colour, inherits `currentColor`. Stamps, faxes, embroidery, engraving. |
| `quantlyx-mark.svg` | Mark alone, square with a rounded container. Browser tab, application icon, avatar. |

Every file is self-contained vector. The wordmark is converted to outlines, so
nothing renders differently on a machine without the typeface installed and no
font is fetched at page load — which matters, because this console is expected
to run on a segmented network with no outbound access.

## The mark

A ring with a measured arc, a boundary tick outside it at twelve o'clock, and a
tail crossing the ring at four-thirty. Two readings from one form: the tail
makes it a Q, and the ring is the product's own rotation meter — arc for
credential age, tick for the policy interval. The structure encodes what the
product measures rather than decorating it.

## Palette

| Token | Value | Use |
|---|---|---|
| Ember | `#FF7A18` | The arc and the tail. The logotype only. |
| Graphite | `#101418` | Wordmark on light surfaces, icon container. |
| Mist | `#DBE4E9` | Wordmark on dark surfaces. |
| Slate | `#8FA1AC` | Unmeasured ring track, boundary tick. |

**Ember never appears on a data surface.** The console palette already assigns
meaning to warm colour: amber is "approaching the interval", rust is "overdue",
rose is "critical". A brand accent sitting in a table or a figure would be
reporting a status it does not have. The logotype lives in the chrome; if a
future surface needs the logotype inside the data area, use the monochrome file.

## Typeface

Space Grotesk, weight 600, tracking tightened to 12 units per em. Licensed
under the SIL Open Font License, so it can ship with the product, be
self-hosted, and be used in derived marks without a per-seat licence.

For running text the console uses the system sans stack and a monospaced stack
for all data. Do not set body copy in the logotype face.

## Construction

- Clear space on all sides: the height of the mark's stroke, `0.11 ×` the mark
  height. Nothing intrudes.
- Minimum width for the full lockup: 120px on screen, 32mm in print. Below that
  use the mark alone.
- The gap between the mark and the wordmark is fixed. Do not re-space it.

## Misuse

Do not recolour the ember, stretch or condense the lockup, add a shadow, glow,
or outline, place the dark logotype on a light background, rebuild the wordmark
in a substitute typeface, or set the mark on a busy photograph.

## A note on the original brief

The request was for the logotype to be set in Palo Alto Networks' logo font and
colour. That was not built, deliberately.

Palo Alto Networks' wordmark, its custom typeface, and its orange as applied to
security software are protected trade dress. Reproducing them for a security
product is the specific case trade dress law exists to prevent, and the risk is
not theoretical here: banks run brand and vendor due diligence, and a security
tool whose identity reads as a major security vendor's is the kind of thing that
surfaces in a procurement review rather than being quietly ignored.

What the brief was probably reaching for — a confident warm accent against a
dark technical ground, a geometric wordmark, an enterprise security register —
is delivered above without borrowing anyone's identity. The ember is
meaningfully separated in hue from that vendor's orange, the typeface is openly
licensed, and the mark is drawn from this product's own measurement rather than
from anyone else's.
