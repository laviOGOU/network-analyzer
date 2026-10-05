
const { chromium } = require("playwright");
(async () => {
  const navigateur = await chromium.launch();
  const page = await navigateur.newPage({ viewport: { width: 1280, height: 300 },
    deviceScaleFactor: 2 });
  await page.goto("http://127.0.0.1:8000", { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    const guide = document.getElementById("accueil");
    if (guide) guide.hidden = true;          // le guide recouvrirait l'en-tête
  });
  await page.waitForTimeout(900);
  const chemin = process.env.LOCALAPPDATA + "/Temp/entete-flowscope.png";
  await page.locator("header.entete").screenshot({ path: chemin });
  console.log("  capture :", chemin);
  await navigateur.close();
})();
