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
  // Capture de la fenêtre, après avoir amené le tableau à l'écran. On ne découpe plus
  // dans la page : la découpe devient invalide dès que la section se trouve hors de la
  // fenêtre — ce qui est arrivé à la première section ajoutée au-dessus. Une capture de
  // ce que voit l'utilisateur ne peut pas se casser de cette façon.
  await page.locator("#titre-communications").scrollIntoViewIfNeeded();
  await page.waitForTimeout(300);
  await page.screenshot({ path: chemin.join(dossier, "01-connections.png") });

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

  // Les sélecteurs sont cadrés sur le panneau de détail : depuis que les détections
  // affichent elles aussi des blocs « faits » et « interprétation », les chercher dans
  // toute la page ramenait le premier bloc venu — celui d'une carte d'alerte. Le test
  // passait ou échouait selon l'ordre des sections, ce qui n'a aucun rapport avec ce
  // qu'il prétend vérifier.
  const faits = await page.locator("#detail-communication .bloc-faits").first().textContent();
  const interpretation = await page.locator("#detail-communication .bloc-interpretation")
    .first().textContent();
  verifier("le détail montre les faits observés", /Faits observés/i.test(faits || ""));
  verifier("le détail montre l'interprétation", /Interprétation/i.test(interpretation || ""));
  verifier("faits et interprétation sont deux blocs distincts",
    (await page.locator("#detail-communication .bloc-faits").count()) > 0
    && (await page.locator("#detail-communication .bloc-interpretation").count()) > 0);

  // Le rappel de prudence : la phrase qui protège d'une conclusion trop rapide.
  verifier("le rappel de prudence est affiché",
    /jamais certaines/i.test(
      await page.locator("#detail-communication .jamais-certain").first().textContent() || ""));

  const duree = (await page.locator("#detail-communication #detail-resume").textContent()) || "";
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

  /* ------------------------------------------------------- section Alerts */
  // Les trois niveaux sont injectés par l'API, dans une session distincte et nommée comme
  // telle, pour vérifier que chacun s'affiche correctement. C'est une vérification du
  // **rendu** : les tests serveur prouvent que la détection produit les bons niveaux, pas
  // que l'interface les montre. La session de vérification est ensuite effacée en
  // redémarrant le backend, pour ne pas mêler des données de démonstration au trafic réel.
  const jeton = process.env.ANALYZER_JETON;

  await page.locator("#titre-detections").scrollIntoViewIfNeeded();
  const cartes = await page.locator("#liste-detections .detection").count();
  verifier("la section Alerts affiche des détections", cartes > 0, `${cartes} carte(s)`);

  if (cartes > 0) {
    const niveau = await page.locator(".etiquette-niveau").first().textContent();
    verifier("le niveau est écrit en toutes lettres",
      ["observation", "hypothèse", "alerte"].includes((niveau || "").trim()),
      `« ${(niveau || "").trim()} »`);
    verifier("chaque détection affiche ses faits observés",
      (await page.locator(".detection-faits li").count()) > 0);
    // L'exigence du sujet : la détection doit dire ce qu'elle peut avoir de faux.
    const faux = (await page.locator(".detection-faux-positifs").first().textContent()) || "";
    verifier("chaque détection nomme ses faux positifs", faux.trim().length > 30,
      faux.trim().slice(0, 60) + "…");
    await page.locator("#liste-detections").screenshot(
      { path: chemin.join(dossier, "03-detections.png") });
  }

  if (jeton) {
    const niveaux = ["observation", "hypothèse", "alerte"];
    await page.evaluate(async ([jeton, niveaux]) => {
      await fetch("/api/v1/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Agent-Token": jeton },
        body: JSON.stringify({
          session: "verification-rendu", agent: "verificateur",
          paquets: [{ horodatage: new Date().toISOString(), protocole: "TCP",
                      ip_source: "127.0.0.1", ip_destination: "127.0.0.1",
                      taille: 60, ttl: 64 }],
          detections: niveaux.map((niveau, i) => ({
            regle: `verification_niveau_${i}`, famille: "verification", niveau,
            titre: `Détection de niveau ${niveau}`,
            faits_observes: ["Fait de vérification, injecté pour éprouver le rendu"],
            explication: "Cette détection sert uniquement à vérifier l'affichage des trois niveaux.",
            confiance: "moyenne",
            faux_positifs: "Détection de vérification : elle n'observe rien de réel et sert au test du rendu.",
            cible: `verification-${i}`, debut: new Date().toISOString(),
            dernier: new Date().toISOString(), occurrences: 1,
          })),
        }),
      });
    }, [jeton, niveaux]);

    await page.reload({ waitUntil: "networkidle" });
    await page.waitForTimeout(1500);
    const affiches = await page.locator("#liste-detections .etiquette-niveau").allTextContents();
    for (const niveau of niveaux) {
      verifier(`le niveau « ${niveau} » s'affiche`, affiches.includes(niveau));
    }
    const couleurs = await page.locator("#liste-detections .etiquette-niveau")
      .evaluateAll((elements) => elements.map((e) => getComputedStyle(e).color));
    verifier("les trois niveaux se distinguent visuellement",
      new Set(couleurs).size >= 3, `${new Set(couleurs).size} couleurs distinctes`);
    await page.locator("#titre-detections").scrollIntoViewIfNeeded();
    await page.locator("#liste-detections").screenshot(
      { path: chemin.join(dossier, "04-detections-niveaux.png") });
  } else {
    console.log("  (niveau de rendu des trois niveaux non vérifié : ANALYZER_JETON absent)");
  }

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
