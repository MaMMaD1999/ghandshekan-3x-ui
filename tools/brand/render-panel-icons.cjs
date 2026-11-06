// Export the approved gold panel mark. Keep its aspect ratio and center the
// visible artwork, not the potentially asymmetric transparent source canvas.
// Usage: node render-panel-icons.cjs /absolute/path/to/sharp
const fs = require('node:fs');
const path = require('node:path');
const sharp = require(process.argv[2] || 'sharp');
const root = path.resolve(__dirname, '../..');
(async () => {
  const source = path.join(__dirname, 'ghand-panel-gold-original.png');
  const { data, info } = await sharp(source).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  let left = info.width, top = info.height, right = -1, bottom = -1;
  for (let y = 0; y < info.height; y++) for (let x = 0; x < info.width; x++) {
    if (data[(y * info.width + x) * 4 + 3] >= 32) {
      left = Math.min(left, x); right = Math.max(right, x);
      top = Math.min(top, y); bottom = Math.max(bottom, y);
    }
  }
  if (right < left) throw new Error('Panel mark has no visible artwork');
  const original = (await sharp(source).extract({ left, top, width: right - left + 1, height: bottom - top + 1 }).png().toBuffer()).toString('base64');
  function svg(background, maskable) {
    const extent = maskable ? 350 : 404;
    const inset = (512 - extent) / 2;
    return `<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">${background ? '<rect width="512" height="512" fill="#090c12"/>' : ''}<image href="data:image/png;base64,${original}" x="${inset}" y="${inset}" width="${extent}" height="${extent}" preserveAspectRatio="xMidYMid meet"/></svg>`;
  }
  const icons = path.join(root, 'frontend/public/icons');
  fs.mkdirSync(icons, { recursive: true });
  for (const size of [16, 24, 32, 64, 180, 192, 512]) {
    // iOS requires an opaque touch icon; other non-maskable exports retain alpha.
    await sharp(Buffer.from(svg(size === 180, false))).resize(size, size).png().toFile(path.join(icons, `ghandshekan-panel-${size}.png`));
  }
  await sharp(Buffer.from(svg(true, true))).png().toFile(path.join(icons, 'ghandshekan-panel-maskable-512.png'));
  await sharp(Buffer.from(svg(false, false))).resize(256, 256).webp({ quality: 92, alphaQuality: 100 }).toFile(path.join(root, 'frontend/src/assets/ghandshekan-panel-mark.webp'));
  fs.writeFileSync(path.join(__dirname, 'ghandshekan-panel.svg'), svg(false, false));
  await sharp(Buffer.from(svg(false, false))).resize(64, 64).png().toFile(path.join(root, 'frontend/public/ghandshekan-favicon.png'));
  console.log(JSON.stringify({ sourceBounds: { left, top, right, bottom }, extent: 404, badge: false, frame: false }));
})();
