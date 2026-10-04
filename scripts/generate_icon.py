"""Prepare approved hexi + key artwork for Tk and Windows packaging."""
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]

def main():
    wordmark = Image.open(ROOT / 'assets' / 'hexikeys-wordmark.png').convert('RGBA')
    key = wordmark.crop((int(wordmark.width * .60), 0, wordmark.width, wordmark.height))
    image = Image.new('RGBA', (512, 512))
    key.thumbnail((448, 448), Image.Resampling.LANCZOS)
    image.alpha_composite(key, ((512-key.width)//2, (512-key.height)//2))
    for size in (58, 76):
        image.resize((size, size), Image.Resampling.LANCZOS).save(ROOT / 'assets' / f'hexikeys-{size}.png')
        width = 276 if size == 76 else 204
        height = max(1, round(wordmark.height * width / wordmark.width))
        wordmark.resize((width, height), Image.Resampling.LANCZOS).save(ROOT / 'assets' / f'hexikeys-wordmark-{size}.png')
    image.save(ROOT / 'assets' / 'hexikeys.ico', format='ICO', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
    print('Prepared approved HexiKeys wordmark and key-glyph icons.')

if __name__ == '__main__':
    main()
