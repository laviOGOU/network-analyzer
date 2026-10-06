
const { chromium } = require("playwright");
(async () => {
  const navigateur = await chromium.launch();
  // La fenêtre est assez haute pour montrer l'en-tête ET la bannière d'accueil : c'est
  // l'ensemble qu'on juge, pas l'un sans l'autre.
  // Assez haute pour montrer l'en-tête, la bannière ET le premier titre de section : c'est
  // l'ensemble qu'on juge, et un titre de section ne se juge pas en dehors de sa page.
  const page = await navigateur.newPage({ viewport: { width: 1280, height: 1080 },
    deviceScaleFactor: 1 });
  await page.goto("http://127.0.0.1:8000", { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    const guide = document.getElementById("accueil");
    if (guide) guide.hidden = true;          // le guide recouvrirait l'en-tête
  });
  // On attend que la page ait fini de se connecter et de charger ses interfaces : sinon la
  // capture fige des etats transitoires - « Connexion… », « Chargement des interfaces… » -
  // et on juge un instantane au lieu du rendu. C'est ce qui m'a fait croire a une troncature.
  await page.waitForFunction(() => {
    const texte = document.getElementById("etat-connexion-texte");
    const choix = document.getElementById("choix-interface");
    return texte && !/Connexion…/.test(texte.textContent)
        && choix && choix.options.length > 1;
  }, { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(600);
  const chemin = process.env.LOCALAPPDATA + "/Temp/entete-flowscope.png";
  await page.screenshot({ path: chemin, clip: { x: 0, y: 0, width: 1280, height: 1080 } });
  console.log("  capture :", chemin);
  await navigateur.close();
})();
