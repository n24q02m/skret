"""Generate skret branding assets via Gemini Imagen + Pillow compositing.

Usage:
    GEMINI_API_KEY=... python scripts/gen-branding.py

Outputs (written to docs/public/):
    banner.png        1280x640 (GitHub social preview + marketing banner)
    og-image.png      1200x630 (OpenGraph / Twitter card)
    logo.png          512x512 rasterized from logo.svg
    logo-32.png       32x32 for favicon.ico composition
    logo-16.png       16x16 for favicon.ico composition
    favicon.ico       multi-size icon
    apple-touch-icon.png 180x180

Raw Imagen outputs land in docs/public/raw/ for audit + iteration.

Design brief (locked per chat2.txt + spec 2026-04-18 §4 Q6):
    - Palette: navy #0F172A bg, purple #7C3AED/#A78BFA (lock), cyan #06B6D4/#22D3EE (terminal)
    - Concept 1: padlock outline + terminal >_ prompt inside keyhole
    - Clean, modern cybersecurity aesthetic, NO watermark, NO text in logo itself
    - Banner: wide dark navy with subtle cyan circuit lines, brand text composed on top
"""

import os
import time
from pathlib import Path

from google import genai
from google.genai import errors, types
from PIL import Image, ImageDraw, ImageFont
from resvg_py import svg_to_bytes

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "docs" / "public"
RAW = PUBLIC / "raw"
RAW.mkdir(parents=True, exist_ok=True)

API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
if not API_KEY:
    raise SystemExit("Set GEMINI_API_KEY env var before running this script.")

client = genai.Client(api_key=API_KEY)

# Imagen 4 (Google's latest as of 2026). Try highest quality first, fall back
# to standard then fast if the server returns 5xx (decode timeouts are common
# on the Ultra endpoint for complex prompts).
IMAGE_MODELS = [
    os.environ.get("IMAGEN_MODEL") or "imagen-4.0-ultra-generate-001",
    "imagen-4.0-generate-001",
    "imagen-4.0-fast-generate-001",
]

PROMPTS = {
    "banner": (
        "Professional wide GitHub banner, 1280x640 aspect, dark navy background "
        "(hex #0F172A). Subtle thin cyan circuit board traces (hex #06B6D4) forming "
        "an abstract grid network pattern across the full canvas, with faint node "
        "dots at intersections. Flat modern cyber-security aesthetic. "
        "NO text, NO logo, NO watermark, NO signatures, NO characters of any kind — "
        "this is a background plate only. Negative space preserved on the left 40% "
        "so a logo and brand text can be composited on top later."
    ),
    "og": (
        "Professional 1200x630 social share card, dark navy (#0F172A) background "
        "with subtle diagonal cyan circuit traces (#06B6D4) fading toward the edges. "
        "Clean flat cyber-security aesthetic. "
        "NO text, NO logo, NO watermark, NO signatures — background plate only, "
        "soft vignette, leave center open for composited brand text."
    ),
    "logo_hero": (
        "Minimalist vector-style flat logo icon on transparent background. "
        "A stylized padlock whose keyhole has been replaced by a small "
        "terminal command prompt '>_'. Padlock outline in deep purple (#7C3AED), "
        "terminal prompt symbol in cyan (#06B6D4), body filled with slightly lighter "
        "purple, no shading, no 3D, no gradients. Symmetric, centered, geometric, "
        "suitable for scaling down to 16x16 favicon. NO text, NO letters, NO "
        "watermark. Square aspect."
    ),
}


def imagen_to_file(prompt: str, out: Path, aspect: str = "1:1") -> Path:
    last_err: Exception | None = None
    for model in IMAGE_MODELS:
        for attempt in range(3):
            print(f"[imagen] {model:<36} -> {out.name}  aspect={aspect}  "
                  f"attempt={attempt + 1}")
            try:
                resp = client.models.generate_images(
                    model=model,
                    prompt=prompt,
                    config=types.GenerateImagesConfig(
                        number_of_images=1,
                        aspect_ratio=aspect,
                        safety_filter_level="BLOCK_LOW_AND_ABOVE",
                        person_generation="DONT_ALLOW",
                    ),
                )
                if not resp.generated_images:
                    raise RuntimeError(f"Imagen returned no images for {out.name}")
                img_bytes = resp.generated_images[0].image.image_bytes
                out.write_bytes(img_bytes)
                print(f"[imagen]    ok, wrote {len(img_bytes) / 1024:.1f} KB")
                return out
            except errors.ServerError as exc:
                last_err = exc
                code = getattr(exc, "code", None) or exc.args[0] if exc.args else "?"
                print(f"[imagen]    server {code}, retrying in {2 ** attempt}s")
                time.sleep(2 ** attempt)
            except errors.ClientError as exc:
                last_err = exc
                print(f"[imagen]    client error {exc!r}, skipping to next model")
                break
    raise RuntimeError(f"Imagen failed for {out.name}: {last_err!r}")


def rasterize_svg(svg_path: Path, size: int, out: Path) -> Path:
    """Render SVG to PNG at given size using resvg (pure Rust, no native deps)."""
    print(f"[svg2png] resvg -> {out.name} @ {size}px")
    png_bytes = bytes(svg_to_bytes(svg_path=str(svg_path), width=size, height=size))
    out.write_bytes(png_bytes)
    return out


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        ("JetBrainsMono-Bold.ttf" if bold else "JetBrainsMono-Regular.ttf"),
        ("C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf"),
        ("/System/Library/Fonts/Menlo.ttc"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold
         else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def compose_banner(bg_path: Path, logo_png: Path, out: Path) -> None:
    print(f"[compose] banner -> {out.name}")
    bg = Image.open(bg_path).convert("RGBA").resize((1280, 640), Image.LANCZOS)
    logo = Image.open(logo_png).convert("RGBA").resize((180, 180), Image.LANCZOS)
    bg.paste(logo, (100, 230), logo)
    draw = ImageDraw.Draw(bg)
    draw.text((320, 250), "skret", font=load_font(104, bold=True), fill="#FFFFFF")
    draw.text((320, 380), "Secrets without the server.",
              font=load_font(32), fill="#22D3EE")
    draw.text((320, 430), "Cloud-provider secret manager CLI",
              font=load_font(26), fill="#94A3B8")
    bg.convert("RGB").save(out, "PNG", optimize=True)


def compose_og(bg_path: Path, logo_png: Path, out: Path) -> None:
    print(f"[compose] og-image -> {out.name}")
    bg = Image.open(bg_path).convert("RGBA").resize((1200, 630), Image.LANCZOS)
    logo = Image.open(logo_png).convert("RGBA").resize((160, 160), Image.LANCZOS)
    bg.paste(logo, (380, 140), logo)
    draw = ImageDraw.Draw(bg)
    title_font = load_font(92, bold=True)
    tagline_font = load_font(32)
    title = "skret"
    tx = (1200 - draw.textlength(title, font=title_font)) / 2
    draw.text((tx, 320), title, font=title_font, fill="#FFFFFF")
    tagline = "Secrets without the server."
    tx = (1200 - draw.textlength(tagline, font=tagline_font)) / 2
    draw.text((tx, 440), tagline, font=tagline_font, fill="#22D3EE")
    sub = "Cloud-provider secret manager CLI"
    sub_font = load_font(24)
    tx = (1200 - draw.textlength(sub, font=sub_font)) / 2
    draw.text((tx, 490), sub, font=sub_font, fill="#94A3B8")
    bg.convert("RGB").save(out, "PNG", optimize=True)


def build_favicon_ico(logo512: Path, out: Path) -> None:
    print(f"[favicon] -> {out.name}")
    src = Image.open(logo512).convert("RGBA")
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    src.save(out, format="ICO", sizes=sizes)


def main() -> None:
    # 1. Gen raw backgrounds + concept logo
    imagen_to_file(PROMPTS["banner"], RAW / "banner-bg.png", aspect="16:9")
    imagen_to_file(PROMPTS["og"], RAW / "og-bg.png", aspect="16:9")
    imagen_to_file(PROMPTS["logo_hero"], RAW / "logo-concept.png", aspect="1:1")

    # 2. Rasterize canonical hand-coded SVG logo
    rasterize_svg(PUBLIC / "logo.svg", 512, PUBLIC / "logo.png")
    rasterize_svg(PUBLIC / "favicon.svg", 180, PUBLIC / "apple-touch-icon.png")
    rasterize_svg(PUBLIC / "favicon.svg", 512, PUBLIC / "favicon-512.png")

    # 3. Compose marketing assets
    compose_banner(RAW / "banner-bg.png", PUBLIC / "logo.png", PUBLIC / "banner.png")
    compose_og(RAW / "og-bg.png", PUBLIC / "logo.png", PUBLIC / "og-image.png")

    # 4. favicon.ico multi-size from favicon-512.png
    build_favicon_ico(PUBLIC / "favicon-512.png", PUBLIC / "favicon.ico")
    (PUBLIC / "favicon-512.png").unlink()

    print("\nDone. Final assets in docs/public/:")
    for name in ["logo.svg", "logo-dark.svg", "logo.png", "favicon.svg",
                 "favicon.ico", "apple-touch-icon.png", "banner.png", "og-image.png"]:
        p = PUBLIC / name
        if p.exists():
            size = p.stat().st_size
            print(f"  {name:<25} {size/1024:8.1f} KB")
        else:
            print(f"  {name:<25} MISSING")


if __name__ == "__main__":
    main()
