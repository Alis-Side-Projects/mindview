"""
MindView video generator — turns a script (sections with narration + slide text) into an mp4.
Each section gets a slide (PNG) + voiceover (mp3); ffmpeg stitches them.
"""
import asyncio, os, subprocess, sys, json, shlex
from pathlib import Path
import edge_tts
from PIL import Image, ImageDraw, ImageFont

FFMPEG = r"C:\Users\humay\AppData\Local\Microsoft\WinGet\Links\ffmpeg.exe"
VOICE = "en-US-AndrewMultilingualNeural"  # warm tutor voice
RATE = "-5%"   # slightly slow for clarity
W, H = 1920, 1080

# Try to load a nice font (Segoe UI is on every Windows machine)
def _font(size, bold=False):
    name = "segoeuib.ttf" if bold else "segoeui.ttf"
    candidates = [Path("C:/Windows/Fonts") / name, Path("C:/Windows/Fonts/segoeui.ttf")]
    for p in candidates:
        if p.exists():
            return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()

def render_slide(out_path, title, body_lines, footer, accent="#059669"):
    """Render a 1080p slide as PNG."""
    img = Image.new("RGB", (W, H), "#0f172a")  # dark slate background
    d = ImageDraw.Draw(img)
    # Top accent bar
    d.rectangle([(0, 0), (W, 12)], fill=accent)
    # Brand strip
    d.text((60, 40), "MindView Academy", font=_font(28, bold=True), fill="#94a3b8")
    d.text((60, 80), footer, font=_font(22), fill="#64748b")
    # Title
    d.text((60, 160), title, font=_font(72, bold=True), fill="#ffffff")
    # Title underline
    d.rectangle([(60, 250), (320, 256)], fill=accent)
    # Body
    y = 320
    for line in body_lines:
        prefix_size = 36
        if line.startswith("# "):  # section header
            d.text((60, y), line[2:], font=_font(48, bold=True), fill=accent); y += 80
        elif line.startswith("- "):  # bullet
            d.ellipse([(70, y+16), (86, y+32)], fill=accent)
            d.text((110, y), line[2:], font=_font(prefix_size), fill="#e2e8f0"); y += 60
        elif line.startswith("> "):  # callout / formula
            d.rounded_rectangle([(60, y), (W-60, y+90)], radius=12, fill="#1e293b", outline=accent, width=3)
            d.text((90, y+24), line[2:], font=_font(40, bold=True), fill="#fbbf24"); y += 110
        elif line == "":
            y += 30
        else:
            d.text((60, y), line, font=_font(prefix_size), fill="#cbd5e1"); y += 56
    img.save(out_path, "PNG")

async def synth(text, out_mp3):
    """Generate voiceover with Edge TTS."""
    com = edge_tts.Communicate(text, VOICE, rate=RATE)
    await com.save(out_mp3)

def section_to_clip(idx, section, build_dir, accent, course_label):
    """Render slide, synth audio, combine into a per-section mp4."""
    png = build_dir / f"s{idx:02d}.png"
    mp3 = build_dir / f"s{idx:02d}.mp3"
    mp4 = build_dir / f"s{idx:02d}.mp4"
    render_slide(png, section["title"], section.get("slide", []), course_label, accent)
    asyncio.run(synth(section["narration"], str(mp3)))
    # Combine: still image + audio -> mp4
    cmd = [
        FFMPEG, "-y", "-loop", "1", "-i", str(png), "-i", str(mp3),
        "-c:v", "libx264", "-tune", "stillimage", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "192k", "-shortest", "-r", "25",
        str(mp4)
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    return mp4

def build_video(script_json, output_mp4, accent="#059669", course_label="MindView · SCH4U Chemistry"):
    """Build a full video from a JSON script."""
    script = json.loads(Path(script_json).read_text(encoding="utf-8"))
    build_dir = Path(output_mp4).parent / "_build" / Path(output_mp4).stem
    build_dir.mkdir(parents=True, exist_ok=True)

    clips = []
    for i, sec in enumerate(script["sections"]):
        print(f"  [{i+1}/{len(script['sections'])}] {sec['title']}")
        clips.append(section_to_clip(i, sec, build_dir, accent, course_label))

    # Concat list — paths must be relative to the concat.txt file's directory
    list_file = build_dir / "concat.txt"
    list_file.write_text("\n".join(f"file '{c.name}'" for c in clips), encoding="utf-8")
    out_abs = str(Path(output_mp4).resolve())
    cmd = [FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(list_file), "-c", "copy", out_abs]
    subprocess.run(cmd, check=True, capture_output=True)
    print(f"  -> {output_mp4}")

if __name__ == "__main__":
    script_json = sys.argv[1]
    output_mp4 = sys.argv[2]
    accent = sys.argv[3] if len(sys.argv) > 3 else "#059669"
    label = sys.argv[4] if len(sys.argv) > 4 else "MindView Academy"
    build_video(script_json, output_mp4, accent, label)
