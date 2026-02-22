from PIL import Image

# Open images
img1 = Image.open("lemur.png")
img2 = Image.open("flag.png")

# Ensure same mode and size
img1 = img1.convert("RGB")
img2 = img2.convert("RGB")

assert img1.size == img2.size

width, height = img1.size
result = Image.new("RGB", (width, height))

for x in range(width):
    for y in range(height):
        r1, g1, b1 = img1.getpixel((x, y))
        r2, g2, b2 = img2.getpixel((x, y))
        
        result.putpixel(
            (x, y),
            (r1 ^ r2, g1 ^ g2, b1 ^ b2)
        )

result.save("output.png")
