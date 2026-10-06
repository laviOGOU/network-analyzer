
const { chromium } = require("playwright");
(async () => {
  const navigateur = await chromium.launch();
  // La fenêtre est assez haute pour montrer l'en-tête ET la bannière d'accueil : c'est
  // l'ensemble qu'on juge, pas l'un sans l'autre.
  const page = await navigateur.newPage({ viewport: { width: 1280, height: 620 },
    deviceScaleFactor: 1 });
  await page.goto("http://127.0.0.1:8000", { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    const guide = document.getElementById("accueil");
    if (guide) guide.hidden = true;          // le guide recouvrirait l'en-tête
  });
  await page.waitForTimeout(900);
  const chemin = process.env.LOCALAPPDATA + "/Temp/entete-flowscope.png";
  await page.screenshot({ path: chemin, clip: { x: 0, y: 0, width: 1280, height: 620 } });
  console.log("  capture :", chemin);
  await navigateur.close();
})();
