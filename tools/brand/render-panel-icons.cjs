// Render the established logo with a vector server badge; never distort the G.
// Usage: node render-panel-icons.cjs /absolute/path/to/sharp
const fs = require('node:fs');
const path = require('node:path');
const sharp = require(process.argv[2] || 'sharp');
const root = path.resolve(__dirname, '../..');
const original = fs.readFileSync(path.join(__dirname, 'ghandshekan-original.png')).toString('base64');
const badge = `<rect x="340" y="342" width="106" height="104" rx="26" fill="#101827" stroke="#f5b942" stroke-width="5"/><g fill="none" stroke="#f5b942" stroke-width="7" stroke-linecap="round"><path d="M365 370h57M365 393h57M365 416h57"/></g><g fill="#fff1c7"><circle cx="370" cy="370" r="4"/><circle cx="370" cy="393" r="4"/><circle cx="370" cy="416" r="4"/></g>`;
function svg(background, maskable) {
  const transform = maskable ? 'translate(51.2 51.2) scale(.8)' : '';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">${background ? '<rect width="512" height="512" fill="#0d1420"/>' : ''}<g transform="${transform}"><image href="data:image/png;base64,${original}" x="60" y="38" width="392" height="422" preserveAspectRatio="xMidYMid meet"/>${badge}</g></svg>`;
}
(async () => {
  const icons = path.join(root, 'frontend/public/icons');
  fs.mkdirSync(icons, { recursive: true });
  for (const size of [16, 24, 32, 64, 180, 192, 512]) {
    await sharp(Buffer.from(svg(size >= 180, false))).resize(size, size).png().toFile(path.join(icons, `ghandshekan-panel-${size}.png`));
  }
  await sharp(Buffer.from(svg(true, true))).png().toFile(path.join(icons, 'ghandshekan-panel-maskable-512.png'));
  await sharp(Buffer.from(svg(false, false))).resize(256, 256).webp({ quality: 92, alphaQuality: 100 }).toFile(path.join(root, 'frontend/src/assets/ghandshekan-panel-mark.webp'));
  fs.writeFileSync(path.join(__dirname, 'ghandshekan-panel.svg'), svg(false, false));
})();
