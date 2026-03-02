# make_node_icons.py
from PIL import Image, ImageFilter, ImageEnhance, ImageDraw
import numpy as np

SRC = {
    "entry": "icon_entry.png",
    "weakness": "icon_weakness.png",
    "technique": "icon_technique.png",
    "impact": "icon_impact.png",
}

OUT = {
    "entry": "icon_entry_node.png",
    "weakness": "icon_weakness_node.png",
    "technique": "icon_technique_node.png",
    "impact": "icon_impact_node.png",
}

COLORS = {
    "entry": (120, 255, 120),      # green
    "weakness": (255, 232, 120),   # yellow
    "technique": (255, 176, 95),   # orange
    "impact": (255, 110, 110),     # red
}

def tight_bbox_alpha(img, thresh=18):
    a = np.array(img.split()[-1])
    ys, xs = np.where(a > thresh)
    if len(xs) == 0:
        return None
    return (xs.min(), ys.min(), xs.max() + 1, ys.max() + 1)

def recolor_intensity(img, color, gamma=2.5):
    """Remove 'fundo preto' residual e preserva só pixels realmente brilhantes."""
    arr = np.array(img.convert("RGBA")).astype(np.float32)
    rgb = arr[..., :3]
    a = arr[..., 3]
    intensity = rgb.max(axis=2) / 255.0
    weight = np.power(intensity, gamma)  # mata o escuro e mantém o neon
    new_a = (a * weight).clip(0, 255).astype(np.uint8)

    solid = Image.new("RGBA", img.size, (color[0], color[1], color[2], 0))
    solid.putalpha(Image.fromarray(new_a))
    return solid

def make_ring(size, color, outer_radius=214, thickness=20, glow=30, glow_alpha=165):
    w, h = size
    cx, cy = w // 2, h // 2

    ring = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(ring)
    bbox = [cx - outer_radius, cy - outer_radius, cx + outer_radius, cy + outer_radius]
    draw.ellipse(bbox, outline=(color[0], color[1], color[2], 255), width=thickness)

    g1 = ring.filter(ImageFilter.GaussianBlur(radius=glow))
    a1 = ImageEnhance.Brightness(g1.split()[-1]).enhance(glow_alpha / 255.0)
    g1.putalpha(a1)

    g2 = ring.filter(ImageFilter.GaussianBlur(radius=int(glow * 1.7)))
    a2 = ImageEnhance.Brightness(g2.split()[-1]).enhance((glow_alpha * 0.55) / 255.0)
    g2.putalpha(a2)

    out = Image.new("RGBA", size, (0, 0, 0, 0))
    out = Image.alpha_composite(out, g2)
    out = Image.alpha_composite(out, g1)
    out = Image.alpha_composite(out, ring)
    return out

def add_glow(img, blur1=9, alpha1=150, blur2=22, alpha2=80):
    g1 = img.filter(ImageFilter.GaussianBlur(radius=blur1))
    a1 = ImageEnhance.Brightness(g1.split()[-1]).enhance(alpha1 / 255.0)
    g1.putalpha(a1)

    g2 = img.filter(ImageFilter.GaussianBlur(radius=blur2))
    a2 = ImageEnhance.Brightness(g2.split()[-1]).enhance(alpha2 / 255.0)
    g2.putalpha(a2)

    out = Image.new("RGBA", img.size, (0, 0, 0, 0))
    out = Image.alpha_composite(out, g2)
    out = Image.alpha_composite(out, g1)
    out = Image.alpha_composite(out, img)
    return out

def build_node_icon(base_icon_path, color, glyph_target=305, glyph_opacity=235):
    base = Image.open(base_icon_path).convert("RGBA")
    size = base.size

    # glyph recolor + remove escuro
    glyph = recolor_intensity(base, color, gamma=2.5)
    bbox = tight_bbox_alpha(glyph, thresh=18) or glyph.getbbox() or (0, 0, size[0], size[1])
    crop = glyph.crop(bbox)

    # escala pra não encostar no ring (aqui resolve o “pra dentro do círculo”)
    cw, ch = crop.size
    scale = min(glyph_target / cw, glyph_target / ch)
    new_size = (max(1, int(cw * scale)), max(1, int(ch * scale)))
    crop = crop.resize(new_size, Image.LANCZOS)

    # opacidade leve pra ficar “produto” sem machucar
    a = ImageEnhance.Brightness(crop.split()[-1]).enhance(glyph_opacity / 255.0)
    crop.putalpha(a)

    crop = add_glow(crop, blur1=9, alpha1=150, blur2=22, alpha2=80)

    ring = make_ring(size, color, outer_radius=214, thickness=20, glow=30, glow_alpha=165)

    out = Image.new("RGBA", size, (0, 0, 0, 0))
    out = Image.alpha_composite(out, ring)

    gx = (size[0] - crop.size[0]) // 2
    gy = (size[1] - crop.size[1]) // 2
    out.alpha_composite(crop, (gx, gy))
    return out

def main():
    for k, src in SRC.items():
        color = COLORS[k]
        # Entry é mais “alto”, então reduz um pouco mais pra não tocar no ring
        glyph_target = 290 if k == "entry" else 305
        icon = build_node_icon(src, color, glyph_target=glyph_target, glyph_opacity=235)
        icon.save(OUT[k])
        print("OK:", OUT[k])

if __name__ == "__main__":
    main()
