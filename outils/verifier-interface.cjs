/* =============================================================================
   Vérification de l'interface — dans un vrai navigateur
   -----------------------------------------------------------------------------
   Ce que ce script vérifie, et qu'aucun test serveur ne peut voir :

     1. la page se charge sans erreur JavaScript ;
     2. la table des communications se remplit réellement ;
     3. le bouton « Expliquer » ouvre le détail, et ce détail contient bien les faits
        observés ET l'interprétation, dans deux blocs distincts ;
     4. la phrase de prudence est présente ;
     5. le panneau se ferme, et la touche Échap le ferme aussi.

   Il produit une capture d'écran à chaque étape, pour que le résultat soit visible et
   pas seulement affirmé.

   Usage :
       node outils/verifier-interface.cjs [http://127.0.0.1:8000]
   ============================================================================= */

const chemin = require("path");
const fs = require("fs");

// Le paquet Playwright est installé globalement sur cette machine : on le résout
// explicitement plutôt que de dépendre de l'endroit d'où le script est lancé.
const racinePlaywright = process.env.PLAYWRIGHT_DIR
  || "/d/PYTHON/tools/navigateur/node_modules/playwright";
let chromium;
try {
  ({ chromium } = require(racinePlaywright));
} catch (erreur) {
  ({ chromium } = require("playwright"));
}

const adresse = process.argv[2] || "http://127.0.0.1:8000";
const dossier = chemin.join(__dirname, "..", "docs", "captures-interface");
fs.mkdirSync(dossier, { recursive: true });

const resultats = [];
function verifier(intitule, condition, precision = "") {
  resultats.push({ intitule, ok: Boolean(condition), precision });
  console.log(`  ${condition ? "OK  " : "ÉCHEC"} ${intitule}${precision ? ` — ${precision}` : ""}`);
}

(async () => {
  const navigateur = await chromium.launch();
  const page = await navigateur.newPage({ viewport: { width: 1440, height: 1000 } });

  const erreurs = [];
  page.on("pageerror", (erreur) => erreurs.push(erreur.message));
  page.on("console", (message) => {
    if (message.type() === "error") erreurs.push(`console : ${message.text()}`);
  });

  await page.goto(adresse, { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);

  const lignes = await page.locator("#corps-communications tr").count();
  verifier("la table des communications se remplit", lignes > 0, `${lignes} ligne(s)`);
  // Capture de la section, et non de la page entière : la page complète fait plus de
  // dix-huit mille pixels de haut, illisible une fois réduite, et inutile comme preuve.
  // On ne garde que le haut du tableau : cent cinquante lignes donnent une image de
  // plusieurs mégaoctets, illisible et inutile comme preuve. Huit lignes suffisent.
  const boite = await page.locator("#tableau-communications").boundingBox();
  await page.screenshot({
    path: chemin.join(dossier, "01-connections.png"),
    clip: { x: boite.x, y: boite.y, width: boite.width, height: Math.min(boite.height, 640) },
  });

  if (lignes === 0) {
    console.log("\n  Aucune communication : lancez une capture avant de relancer ce script.");
    await navigateur.close();
    process.exit(1);
  }

  // La colonne « ce que l'on peut en dire » doit porter un titre d'explication, pas un
  // tiret : c'est la preuve que le moteur d'explication alimente bien la liste.
  const note = (await page.locator("#corps-communications tr").first()
    .locator(".col-note").textContent())?.trim();
  verifier("la liste affiche une explication", Boolean(note) && note !== "—",
    `« ${note} »`);

  await page.locator("#corps-communications .bouton-detail").first().click();
  await page.waitForSelector("#detail-communication:not([hidden])", { timeout: 5000 });
  await page.waitForTimeout(400);

  const faits = await page.locator(".bloc-faits").first().textContent();
  const interpretation = await page.locator(".bloc-interpretation").first().textContent();
  verifier("le détail montre les faits observés", /Faits observés/i.test(faits || ""));
  verifier("le détail montre l'interprétation", /Interprétation/i.test(interpretation || ""));
  verifier("faits et interprétation sont deux blocs distincts",
    (await page.locator(".bloc-faits").count()) > 0
    && (await page.locator(".bloc-interpretation").count()) > 0);

  // Le rappel de prudence : la phrase qui protège d'une conclusion trop rapide.
  verifier("le rappel de prudence est affiché",
    /jamais certaines/i.test(await page.locator(".jamais-certain").first().textContent() || ""));

  const duree = (await page.locator("#detail-resume").textContent()) || "";
  verifier("le résumé chiffré est présent", /\d/.test(duree), duree.trim().slice(0, 80));
  await page.locator("#detail-communication")
    .screenshot({ path: chemin.join(dossier, "02-detail.png") });

  // Fermeture au clavier : un panneau qui ne se ferme qu'à la souris est un panneau
  // inaccessible.
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  verifier("Échap ferme le détail", await page.locator("#detail-communication").isHidden());
  verifier("le focus revient sur le bouton d'origine",
    await page.evaluate(() => document.activeElement?.classList.contains("bouton-detail")));

  // Le cas défavorable : la table se reconstruit toutes les trois secondes. Le focus doit
  // survivre à la reconstruction, sinon un lecteur au clavier perd sa place sans rien
  // avoir fait. On laisse donc passer plus d'un cycle complet avant de vérifier à nouveau.
  await page.locator("#corps-communications .bouton-detail").nth(3).focus();
  await page.waitForTimeout(4000);
  verifier("le focus survit à un rafraîchissement de la table",
    await page.evaluate(() => document.activeElement?.classList.contains("bouton-detail")));

  verifier("aucune erreur JavaScript", erreurs.length === 0, erreurs.slice(0, 3).join(" | "));

  const reussis = resultats.filter((r) => r.ok).length;
  console.log(`\n  ${reussis}/${resultats.length} vérifications réussies`);
  console.log(`  captures : ${dossier}`);

  await navigateur.close();
  process.exit(reussis === resultats.length ? 0 : 1);
})().catch((erreur) => {
  console.error("  Échec du script :", erreur.message);
  process.exit(1);
});
