"""
Generate a handwritten-style signature PNG for Kushal Kumar
"""

import os
from PIL import Image, ImageDraw, ImageFont

SIG_PATH = r"c:\Users\kusha\OneDrive\Desktop\cyber\Snort_Rules_IoT_Botnet_Attacks\report\signature_kushal.png"

def create_signature():
    width, height = 300, 100
    img = Image.new("RGBA", (width, height), (255, 255, 255, 0)) # Transparent
    draw = ImageDraw.Draw(img)

    # Try script/cursive font, fallback to elegant styling
    font_names = ["BrushScript.ttf", "segoesc.ttf", "Inkfree.ttf", "comic.ttf", "arial.ttf"]
    font = None
    for name in font_names:
        try:
            font = ImageFont.truetype(name, 44)
            break
        except:
            pass
    if font is None:
        font = ImageFont.load_default()

    draw.text((25, 25), "Kushal", fill="#1F4E79", font=font)
    img.save(SIG_PATH)
    print(f"Generated signature: {SIG_PATH}")

create_signature()
