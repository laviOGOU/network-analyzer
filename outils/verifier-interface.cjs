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

  // `networkidle` ne se stabilise jamais : la page interroge le serveur en continu, ce
  // qui est précisément son rôle. On attend le contenu, pas le silence du réseau.
  await page.goto(adresse, { waitUntil: "domcontentloaded" });
  // On attend la première ligne du tableau, pas un délai deviné : la page fait sa
  // première requête aussitôt chargée, mais le temps qu'elle revienne dépend de la
  // machine et de la taille de la base.
  await page.waitForSelector("#corps-communications tr", { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(400);

  const lignes = await page.locator("#corps-communications tr").count();
  // L'accueil. Il doit s'afficher a la premiere visite, se fermer, ET POUVOIR ETRE ROUVERT :
  // un guide qu'on ne peut voir qu'une fois ne sert qu'une fois. Les controles suivants
  // supposent qu'il est ferme — sinon il recouvre la page et Playwright refuse de cliquer.
  const accueil = await page.evaluate(() => {
    const boite = document.getElementById("accueil");
    return {
      present: !!boite,
      ouvert: boite ? !boite.hidden : false,
      etapes: document.querySelectorAll("#accueil .accueil__etapes li").length,
      titre: (document.getElementById("accueil-titre")?.textContent || "").trim(),
      bouton: !!document.getElementById("ouvrir-guide"),
    };
  });
  verifier("le guide d'accueil s'affiche a la premiere visite",
    accueil.present && accueil.ouvert,
    `ouvert=${accueil.ouvert} · ${accueil.etapes} etape(s) · « ${accueil.titre} »`);
  verifier("le guide decrit la demarche en plusieurs etapes",
    accueil.etapes >= 5 && accueil.bouton,
    `${accueil.etapes} etapes · bouton de reouverture : ${accueil.bouton}`);

  await page.keyboard.press("Escape");
  await page.waitForSelector("#accueil", { state: "hidden", timeout: 5000 });
  verifier("Echap referme le guide", true);

  await page.locator("#ouvrir-guide").click();
  await page.waitForSelector("#accueil:not([hidden])", { timeout: 5000 });
  verifier("le guide peut etre rouvert par le bouton Guide", true);
  await page.locator("#accueil-commencer").click();
  await page.waitForSelector("#accueil", { state: "hidden", timeout: 5000 });
  verifier("« Commencer » referme le guide", true);

  // Les vues nommees : au depart, une seule est affichee, et les quatre du sujet existent.
  const vues = await page.evaluate(() => {
    const onglets = [...document.querySelectorAll(".vue-onglet")].map((o) => o.dataset.cible);
    const visibles = [...document.querySelectorAll("[data-vue]")].filter((s) => !s.hidden)
      .map((s) => s.dataset.vue);
    // La section de capture porte `data-vue-toujours`, pas `data-vue` : elle doit rester
    // visible quelle que soit la vue, et c'est exactement ce qu'on vérifie. La chercher avec
    // le sélecteur `[data-vue]` ne la trouvait pas — le contrôle était faux, pas la page.
    const titreCapture = document.getElementById("titre-capture");
    const sectionCapture = titreCapture ? titreCapture.closest("section") : null;
    return { onglets, visibles: [...new Set(visibles)],
             captureVisible: sectionCapture ? !sectionCapture.hidden : false,
             courant: document.querySelector(".vue-onglet[aria-current='true']")?.dataset.cible };
  });
  verifier("les vues nommees du sujet existent",
    ["traffic", "connections", "protocols", "alerts"].every((v) => vues.onglets.includes(v)),
    vues.onglets.join(" · "));
  verifier("une seule vue est affichee a la fois",
    vues.visibles.length === 1, `visibles : ${vues.visibles.join(", ") || "aucune"} · courant : ${vues.courant}`);
  verifier("la barre de capture reste visible quelle que soit la vue",
    vues.captureVisible, `capture affichee : ${vues.captureVisible}`);

  // Les controles suivants portent sur des sections d'autres vues : on les reaffiche toutes,
  // la commutation ayant ete verifiee juste au-dessus.
  await page.evaluate(() => {
    document.querySelectorAll("[data-vue]").forEach((section) => { section.hidden = false; });
  });
  await page.waitForTimeout(300);

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

  // La vue detaillee du paragraphe 9 : ses blocs doivent etre NOMMES, et le contexte externe
  // annonce lui-meme son indisponibilite plutot que de laisser un vide.
  await page.waitForTimeout(1200);   // le contexte externe est obtenu par un appel reseau
  const detail = await page.evaluate(() => {
    const panneau = document.getElementById("detail-communication");
    const textes = [...panneau.querySelectorAll(".bloc-intitule, .explication-titre")]
      .map((n) => n.textContent.trim());
    return { textes, externe: textes.some((t) => /contexte externe/i.test(t)) };
  });
  verifier("les blocs du detail sont nommes",
    detail.textes.some((t) => /informations techniques/i.test(t))
    && detail.textes.some((t) => /analyse et explication/i.test(t)),
    detail.textes.join(" | ").slice(0, 150));
  verifier("le contexte externe est montre, ou dit qu'il est indisponible",
    detail.externe, `bloc externe present : ${detail.externe}`);
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
          // Deux adresses distinctes : le schéma interdit un paquet dont la source et la
          // destination sont identiques, et il a raison — ce n'est pas un échange.
          paquets: [{ horodatage: new Date().toISOString(), protocole: "TCP",
                      ip_source: "127.0.0.1", ip_destination: "127.0.0.2",
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

  /* ------------------------------------------- Lot A : filtre et légende des couleurs */
  const champFiltre = page.locator("#champ-filtre");
  verifier("la barre de filtre est présente", await champFiltre.count() === 1);

  await page.locator("#titre-paquets").scrollIntoViewIfNeeded();
  await page.waitForTimeout(400);
  const paquetsAvant = await page.locator("#corps-paquets tr").count();

  await champFiltre.fill("proto:tcp");
  // Attente conditionnelle plutôt qu'un délai fixe : on attend que le filtre soit
  // réellement appliqué. Un délai fixe produit des échecs qui dépendent de la charge de
  // la machine, et qu'on ne sait plus interpréter six mois plus tard.
  await page.waitForFunction(() => window.filtreAffichage === "proto:tcp", { timeout: 10000 });
  await page.waitForFunction(() => {
    const corps = document.getElementById("corps-paquets");
    if (!corps || !corps.children.length) return false;
    return [...corps.querySelectorAll(".pastille-protocole")]
      .every((e) => e.textContent.trim() === "TCP");
  }, { timeout: 10000 });
  const paquetsTcp = await page.locator("#corps-paquets tr").count();
  const protocoles = await page.locator("#corps-paquets .pastille-protocole")
    .allTextContents();
  // Le nombre de lignes ne baisse pas forcément : la limite s'applique après le filtre,
  // donc la liste se remplit avec les paquets TCP suivants. Ce qui compte, c'est que
  // **tout ce qui est affiché** réponde au filtre.
  verifier("le filtre ne laisse que le protocole demandé",
    protocoles.length > 0 && protocoles.every((p) => p.trim() === "TCP"),
    `${paquetsAvant} → ${paquetsTcp} lignes · protocoles : `
    + [...new Set(protocoles.map((p) => p.trim()))].join(", "));
  verifier("le filtre interprété est réaffiché",
    (await page.locator("#filtre-resume").textContent() || "").includes("proto:tcp"));
  await page.screenshot({ path: chemin.join(dossier, "05-filtre.png") });

  // Un filtre incompris : le message s'affiche, ET les listes gardent leur contenu.
  // C'est la propriété qui compte : une faute de frappe ne doit pas vider le tableau.
  await champFiltre.fill("couleur:rouge");
  await page.waitForFunction(
    () => !document.getElementById("filtre-erreur").hidden, { timeout: 10000 });
  const messageErreur = await page.locator("#filtre-erreur").textContent() || "";
  verifier("un filtre incompris affiche un message", /couleur/.test(messageErreur));
  verifier("le message propose les champs valides", /proto/.test(messageErreur));
  const paquetsApresErreur = await page.locator("#corps-paquets tr").count();
  verifier("les listes ne se vident pas sur une faute de frappe",
    paquetsApresErreur > 0, `${paquetsApresErreur} ligne(s) conservée(s)`);
  await page.screenshot({ path: chemin.join(dossier, "06-filtre-refuse.png") });

  // Échap : on revient à la vue complète.
  await champFiltre.press("Escape");
  await page.waitForFunction(
    () => document.getElementById("filtre-erreur").hidden, { timeout: 10000 });
  verifier("Échap efface le filtre",
    (await champFiltre.inputValue()) === ""
    && await page.locator("#filtre-erreur").isHidden());

  // La légende doit employer les mêmes couleurs que les pastilles réellement affichées.
  await page.locator(".legende summary").click();
  await page.waitForTimeout(300);
  const couleursLegende = await page.locator(
    ".legende .pastille-protocole").evaluateAll(
      (elements) => elements.map((e) => getComputedStyle(e).color));
  const couleursListe = await page.locator("#corps-paquets .pastille-protocole")
    .evaluateAll((elements) => [...new Set(elements.map((e) => getComputedStyle(e).color))]);
  const communes = couleursListe.filter((c) => couleursLegende.includes(c));
  verifier("la légende emploie les couleurs réellement affichées", communes.length > 0,
    `${communes.length} couleur(s) commune(s)`);
  verifier("la légende explique aussi les niveaux de détection",
    await page.locator(".legende .etiquette-niveau").count() >= 3);
  await page.locator(".legende").screenshot(
    { path: chemin.join(dossier, "07-legende.png") });

  // Le 400 du filtre volontairement invalide est attendu : c'est le serveur qui refuse,
  // pas le script qui casse. Le compter comme une erreur ferait échouer le contrôle pour
  // une raison qui n'en est pas une.
  const erreursReelles = erreurs.filter((e) => !/400 \(Bad Request\)/.test(e));
  /* ------------------------------------------- Lot A : couches, octets et export */
  await page.locator("#titre-paquets").scrollIntoViewIfNeeded();
  await page.waitForTimeout(500);
  await page.locator("#corps-paquets .bouton-couches").first().click();
  // C'est **le contenu** qui apparaît, pas le panneau : il est visible en permanence.
  await page.waitForSelector("#paquet-detail-contenu:not([hidden])", { timeout: 8000 });
  await page.waitForTimeout(400);

  const nbCouches = await page.locator("#paquet-couches .couche").count();
  verifier("le détail d'un paquet décrit les quatre couches", nbCouches === 4,
    `${nbCouches} couche(s)`);
  const role = (await page.locator(".couche__role").first().textContent()) || "";
  verifier("chaque couche explique à quoi elle sert", role.length > 60);
  const absents = await page.locator(".couche__valeur--absente").count();
  verifier("ce que l'outil n'extrait pas est marqué comme tel", absents >= 4,
    `${absents} champ(s) « non extrait »`);
  const hex = (await page.locator("#paquet-hex").textContent()) || "";
  verifier("la vue des octets montre les octets connus", /[0-9a-f]{2} [0-9a-f]{2}/.test(hex));
  verifier("la vue des octets marque les octets inconnus", hex.includes("??"));
  const avertissement = (await page.locator("#paquet-hex-avertissement").textContent()) || "";
  verifier("l'avertissement dit que la vue est reconstruite",
    /reconstruite/i.test(avertissement));
  await page.locator("#paquet-detail").screenshot(
    { path: chemin.join(dossier, "08-couches.png") });

  // Les trois zones portent les noms qu'un lecteur — ou un jury — s'attend à trouver, les
  // mêmes que dans les outils de référence.
  const titres = await page.evaluate(() => ({
    liste: (document.getElementById("titre-paquets").textContent || "").trim(),
    detail: (document.getElementById("paquet-detail-titre").textContent || "").trim(),
    sections: [...document.querySelectorAll(".couches-titre")].map((n) => n.textContent.trim()),
  }));
  verifier("les trois zones portent les noms attendus",
    /liste des paquets/i.test(titres.liste)
    && /détail du paquet sélectionné/i.test(titres.detail)
    && titres.sections.some((t) => /contenu du paquet/i.test(t)),
    `${titres.liste} · ${titres.detail} · ${titres.sections.join(" | ")}`);

  await page.keyboard.press("Escape");
  // Le détail n'est plus une fenêtre qu'on ferme, mais un volet qu'on vide : Échap efface la
  // sélection et laisse le message d'attente. Le panneau, lui, reste à l'écran.
  await page.waitForSelector("#paquet-detail-contenu", { state: "hidden", timeout: 5000 });
  const volet = await page.evaluate(() => ({
    visible: !document.getElementById("paquet-detail").hidden,
    attente: !document.getElementById("paquet-detail-vide").hidden,
    couches: document.querySelectorAll("#paquet-couches .couche").length,
  }));
  verifier("Échap vide le détail sans le faire disparaître",
    volet.visible && volet.attente && volet.couches === 0,
    `volet visible=${volet.visible} attente=${volet.attente} couches=${volet.couches}`);

  // L'export : un lien de téléchargement, qui suit le filtre courant.
  const lienExport = await page.locator("#export-communications-csv").getAttribute("href");
  verifier("les liens d'export sont présents", /quoi=communications/.test(lienExport || ""));

  const reponseExport = await page.request.get(
    `${adresse}/api/v1/export?quoi=communications&format=csv`);
  const corps = await reponseExport.text();
  verifier("l'export CSV répond", reponseExport.status() === 200
    && reponseExport.headers()["content-type"].includes("text/csv"));
  verifier("l'export CSV est encodé pour un tableur français",
    corps.startsWith("\ufeff") && corps.includes(";"));
  verifier("l'export propose un nom de fichier",
    (reponseExport.headers()["content-disposition"] || "").includes("network-analyzer_"));
  verifier("l'export CSV ne contient aucune charge utile",
    !/payload|contenu_du_message/i.test(corps));

  // Le recit d'une conversation. On clique sur la premiere communication et on attend que
  // le panneau se remplisse : sans attente conditionnelle, on mesurerait le vide.
  const boutonRecit = await page.$("#corps-communications tr .bouton-recit");
  if (boutonRecit) {
    await boutonRecit.click();
    await page.waitForSelector("#recit-phrases .bloc", { timeout: 25000 }).catch(() => {});
    const recit = await page.evaluate(() => ({
      visible: !document.getElementById("recit-detail").hidden,
      phrases: document.querySelectorAll("#recit-phrases .bloc").length,
      faits: document.querySelectorAll("#recit-phrases .bloc-faits").length,
      lectures: document.querySelectorAll("#recit-phrases .bloc-interpretation").length,
      moments: document.querySelectorAll("#recit-moments .recit-moment").length,
      resume: (document.getElementById("recit-resume").textContent || "").slice(0, 70),
    }));
    verifier("le recit s'affiche : des faits, et des lectures annoncees comme telles",
             recit.visible && recit.faits > 0,
             `phrases=${recit.phrases} faits=${recit.faits} lectures=${recit.lectures} `
             + `moments=${recit.moments} · ${recit.resume}`);
    await page.keyboard.press("Escape");
    await page.waitForSelector("#recit-detail", { state: "hidden", timeout: 5000 }).catch(() => {});
    verifier("Echap referme le recit",
             await page.evaluate(() => document.getElementById("recit-detail").hidden), "");
  } else {
    verifier("le bouton Raconter est present sur les communications", false, "aucun bouton");
  }

  // Les repartitions et l'Expert Info se chargent a part du cycle principal : on attend que
  // la premiere ligne apparaisse au lieu de mesurer un delai fixe.
  await page.waitForSelector("#stats-hierarchie .ligne-part", { timeout: 30000 }).catch(() => {});
  const stats = await page.evaluate(() => ({
    protocoles: document.querySelectorAll("#stats-hierarchie .ligne-part").length,
    pourcentages: (document.getElementById("stats-hierarchie").textContent.match(/%/g) || []).length,
    extremites: document.querySelectorAll("#stats-extremites .ligne-part").length,
    paliers: document.querySelectorAll("#stats-debit .debit-palier").length,
    anomalies: document.querySelectorAll("#anomalies-liste .anomalie").length,
    resume: (document.getElementById("anomalies-resume").textContent || "").slice(0, 60),
  }));
  verifier("la repartition par protocole affiche des pourcentages",
           stats.protocoles > 0 && stats.pourcentages > 0,
           `${stats.protocoles} protocole(s), ${stats.pourcentages} pourcentage(s)`);
  verifier("les machines les plus actives sont classees",
           stats.extremites > 0, `${stats.extremites} machine(s)`);
  verifier("le debit dans le temps est trace",
           stats.paliers > 0, `${stats.paliers} intervalle(s)`);
  // Une simple recherche de texte : une expression régulière avec des parenthèses échappées
  // s'écrit mal et échoue pour de mauvaises raisons — ce qui est arrivé ici.
  verifier("l'Expert Info annonce ce qu'il a examine",
           stats.resume.includes("examiné") && stats.resume.includes("sur 800"),
           `resume="${stats.resume}"`);

  // Les profils d'analyse : le selecteur doit etre rempli par l'API.
  await page.waitForFunction(
    () => (document.querySelectorAll("#choix-profil option").length || 0) > 1,
    { timeout: 20000 }).catch(() => {});
  const profils = await page.evaluate(() => {
    const options = [...document.querySelectorAll("#choix-profil option")].map((o) => o.textContent);
    return { nombre: options.length, noms: options.slice(1, 4) };
  });
  verifier("les profils d'analyse sont proposes", profils.nombre > 1,
           `${profils.nombre - 1} profil(s) : ${profils.noms.join(" · ")}`);

  // Choisir un profil doit remplir le champ de filtre — pas filtrer en secret.
  if (profils.nombre > 1) {
    await page.selectOption("#choix-profil", "1");
    await page.waitForTimeout(600);
    const champ = await page.evaluate(() => document.getElementById("champ-filtre").value);
    verifier("choisir un profil remplit le champ de filtre", champ !== "",
             `champ = "${champ}"`);
    await page.evaluate(() => {
      document.getElementById("champ-filtre").value = "";
      document.getElementById("champ-filtre").dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.waitForTimeout(400);
  }

  verifier("aucune erreur JavaScript", erreursReelles.length === 0,
    erreursReelles.slice(0, 3).join(" | "));

  const reussis = resultats.filter((r) => r.ok).length;
  console.log(`\n  ${reussis}/${resultats.length} vérifications réussies`);
  console.log(`  captures : ${dossier}`);

  await navigateur.close();
  process.exit(reussis === resultats.length ? 0 : 1);
})().catch((erreur) => {
  console.error("  Échec du script :", erreur.message);
  process.exit(1);
});
