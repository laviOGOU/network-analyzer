/* =============================================================================
   Tableau de bord — rafraîchissement et mise en forme
   -----------------------------------------------------------------------------
   Trois règles, et elles ne sont pas décoratives :

   1. **Une seule requête en vol.** Si la précédente n'est pas revenue, on n'en lance
      pas d'autre. Sur un backend lent, la version naïve accumule les requêtes : chacune
      attend, le serveur ralentit encore, et le tableau finit par afficher un état vieux
      de plusieurs secondes sans que rien ne le signale.

   2. **Rien n'est demandé quand l'onglet est caché.** Un tableau de bord laissé ouvert
      dans un onglet en arrière-plan n'a personne à qui montrer quoi que ce soit.

   3. **Un échec n'efface pas les données affichées.** On garde les dernières connues et
      on signale l'état. Vider le tableau laisserait croire que le réseau s'est tu, alors
      que c'est la connexion qui est tombée.
   ============================================================================= */
(function () {
  "use strict";

  const PERIODE = 1000;              // une seconde entre deux rafraîchissements
  const LIMITE = 200;                // paquets demandés à chaque fois

  const el = {
    cartes: {
      paquets: document.getElementById("val-paquets"),
      conserves: document.getElementById("val-conserves"),
      octets: document.getElementById("val-octets"),
      sessions: document.getElementById("val-sessions"),
      partielles: document.getElementById("val-partielles"),
    },
    repartition: document.getElementById("repartition"),
    sources: document.getElementById("sources"),
    corps: document.getElementById("corps-paquets"),
    vide: document.getElementById("tableau-vide"),
    sessions: document.getElementById("liste-sessions"),
    gabarit: document.getElementById("gabarit-ligne"),
    connexion: document.getElementById("etat-connexion"),
    connexionTexte: document.getElementById("etat-connexion-texte"),
    filtreProtocole: document.getElementById("filtre-protocole"),
    filtreRecherche: document.getElementById("filtre-recherche"),
    pause: document.getElementById("bascule-pause"),
    theme: document.getElementById("bascule-theme"),
  };

  let enVol = false;
  let enPause = false;
  let protocolesConnus = new Set();

  /* ------------------------------------------------------------- mise en forme */

  // Les octets : on change d'unité à chaque palier de 1000 (et non 1024) parce que les
  // débits réseau se comptent en puissances de dix. Confondre les deux donne des
  // chiffres faux de 2,4 %, ce qui suffit à rendre un débit incomparable.
  function formaterOctets(octets) {
    if (octets === null || octets === undefined) return "—";
    const unites = ["o", "ko", "Mo", "Go", "To"];
    let valeur = Number(octets);
    let rang = 0;
    while (valeur >= 1000 && rang < unites.length - 1) { valeur /= 1000; rang += 1; }
    const arrondi = valeur >= 100 || rang === 0 ? Math.round(valeur) : valeur.toFixed(1);
    return `${String(arrondi).replace(".", ",")} ${unites[rang]}`;
  }

  function formaterNombre(nombre) {
    return nombre === null || nombre === undefined ? "—" : Number(nombre).toLocaleString("fr-FR");
  }

  // L'agent envoie un horodatage ISO avec fuseau. Le navigateur le convertit dans le
  // fuseau du lecteur : deux personnes à Abidjan et à Paris voient la même seconde.
  function formaterHeure(iso) {
    if (!iso) return "—";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso.slice(11, 19) || "—";
    return date.toLocaleTimeString("fr-FR", { hour12: false });
  }

  function detailLisible(paquet) {
    const detail = paquet.details || {};
    if (detail.dns_question) {
      return detail.dns_reponse
        ? `réponse DNS · ${detail.dns_question}`
        : `requête DNS · ${detail.dns_question}`;
    }
    if (detail.icmp_lisible) return detail.icmp_lisible;
    if (detail.operation_arp) return `ARP ${detail.operation_arp}`;
    if (paquet.flags_tcp) return `TCP ${paquet.flags_tcp}`;
    if (detail.tronque) return "paquet tronqué";
    return "";
  }

  /* ---------------------------------------------------------------- rendu */

  function majCartes(stats) {
    el.cartes.paquets.textContent = formaterNombre(stats.paquets_total);
    el.cartes.conserves.textContent = formaterNombre(stats.paquets_conserves);
    el.cartes.octets.textContent = formaterOctets(stats.octets_total);
    el.cartes.sessions.textContent = formaterNombre(stats.sessions);
    el.cartes.partielles.textContent = formaterNombre(stats.analyses_partielles);
  }

  // Une barre par entrée : la longueur est proportionnelle au maximum, jamais au total.
  // Rapporter chaque valeur au total donnerait des barres toutes minuscules dès qu'il y a
  // beaucoup de catégories.
  function majRepartition(cible, entrees, formateur) {
    cible.textContent = "";
    if (!entrees || !entrees.length) {
      const vide = document.createElement("li");
      vide.textContent = "Aucune donnée pour l'instant.";
      cible.appendChild(vide);
      return;
    }
    const maximum = Math.max(...entrees.map((e) => e.nombre));
    for (const entree of entrees) {
      const ligne = document.createElement("li");

      const nom = document.createElement("span");
      nom.className = "repartition__nom";
      nom.textContent = formateur ? formateur(entree.valeur) : String(entree.valeur);

      const nombre = document.createElement("span");
      nombre.className = "repartition__nombre";
      nombre.textContent = formaterNombre(entree.nombre);

      const jauge = document.createElement("span");
      jauge.className = "repartition__jauge";
      const remplissage = document.createElement("span");
      remplissage.style.width = `${maximum ? Math.max(3, (entree.nombre / maximum) * 100) : 0}%`;
      jauge.appendChild(remplissage);

      ligne.append(nom, nombre, jauge);
      cible.appendChild(ligne);
    }
  }

  function majTableau(paquets) {
    el.corps.textContent = "";
    if (!paquets.length) {
      el.vide.hidden = false;
      return;
    }
    el.vide.hidden = true;

    // `DocumentFragment` : les lignes sont assemblées hors du document, puis insérées en
    // une fois. Les ajouter une par une forcerait le navigateur à recalculer la mise en
    // page à chaque ligne — visible dès quelques centaines de paquets.
    const fragment = document.createDocumentFragment();
    for (const paquet of paquets) {
      const ligne = el.gabarit.content.firstElementChild.cloneNode(true);
      ligne.querySelector(".col-heure").textContent = formaterHeure(paquet.horodatage);

      const pastille = ligne.querySelector(".pastille-protocole");
      pastille.textContent = paquet.protocole || "inconnu";
      pastille.dataset.protocole = paquet.protocole || "inconnu";

      ligne.querySelector(".col-source").textContent =
        paquet.ip_source || paquet.mac_source || "—";
      ligne.querySelector(".col-destination").textContent =
        paquet.ip_destination || paquet.mac_destination || "—";
      ligne.querySelector(".col-port").textContent =
        paquet.port_destination !== null && paquet.port_destination !== undefined
          ? String(paquet.port_destination) : "—";
      ligne.querySelector(".col-taille").textContent = formaterOctets(paquet.taille);
      ligne.querySelector(".col-ttl").textContent =
        paquet.ttl !== null && paquet.ttl !== undefined ? String(paquet.ttl) : "—";

      const detail = ligne.querySelector(".col-detail");
      detail.textContent = detailLisible(paquet);
      if (paquet.analyse_partielle) {
        detail.textContent = "analyse partielle — " + (paquet.motif_partiel || "cause inconnue");
        detail.classList.add("detail-tronque");
      }

      fragment.appendChild(ligne);
    }
    el.corps.appendChild(fragment);
  }

  function majSessions(sessions) {
    el.sessions.textContent = "";
    if (!sessions || !sessions.length) {
      const vide = document.createElement("li");
      vide.textContent = "Aucune session reçue pour l'instant.";
      el.sessions.appendChild(vide);
      return;
    }
    for (const session of sessions) {
      const item = document.createElement("li");
      const identifiant = document.createElement("span");
      identifiant.className = "mono";
      identifiant.textContent = String(session.session || "").slice(0, 8);
      const agent = document.createElement("span");
      agent.textContent = session.agent || "agent inconnu";
      const volume = document.createElement("span");
      volume.textContent = `${formaterNombre(session.paquets)} paquets · ${formaterOctets(session.octets)}`;
      const periode = document.createElement("span");
      periode.textContent = `${formaterHeure(session.debut)} → ${formaterHeure(session.dernier)}`;
      item.append(identifiant, agent, volume, periode);
      el.sessions.appendChild(item);
    }
  }

  function majFiltreProtocoles(parProtocole) {
    for (const nom of Object.keys(parProtocole || {})) {
      if (protocolesConnus.has(nom)) continue;
      protocolesConnus.add(nom);
      const option = document.createElement("option");
      option.value = nom;
      option.textContent = nom;
      el.filtreProtocole.appendChild(option);
    }
  }

  function majEtat(etat, texte) {
    el.connexion.dataset.etat = etat;
    el.connexionTexte.textContent = texte;
  }

  /* ------------------------------------------------------------ chargement */

  async function charger() {
    if (enVol) return;                    // règle 1 : une seule requête en vol
    enVol = true;
    try {
      const parametres = new URLSearchParams({ limite: String(LIMITE) });
      if (el.filtreProtocole.value) parametres.set("protocole", el.filtreProtocole.value);
      if (el.filtreRecherche.value.trim()) parametres.set("recherche", el.filtreRecherche.value.trim());

      const reponse = await fetch(`/api/v1/packets?${parametres}`, {
        headers: { Accept: "application/json" },
      });
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);

      const donnees = await reponse.json();
      const stats = donnees.statistiques || {};

      majCartes(stats);
      majFiltreProtocoles(stats.par_protocole);
      majRepartition(el.repartition,
        Object.entries(stats.par_protocole || {}).map(([valeur, nombre]) => ({ valeur, nombre })));
      majRepartition(el.sources, stats.top_sources || []);
      majTableau(donnees.paquets || []);
      majSessions(donnees.sessions || []);

      majEtat("ok", `À jour · ${formaterNombre(donnees.affiches)} paquets affichés`);
    } catch (erreur) {
      // Règle 3 : on ne vide rien, on signale.
      majEtat("erreur", "Connexion interrompue — dernières données affichées");
      console.warn("Rafraîchissement impossible :", erreur.message);
    } finally {
      enVol = false;
    }
  }

  async function chargerSessions() {
    try {
      const reponse = await fetch("/api/v1/sessions", { headers: { Accept: "application/json" } });
      if (!reponse.ok) return;
      const donnees = await reponse.json();
      majSessions(donnees.sessions || []);
    } catch (erreur) { /* l'indicateur principal signale déjà la panne */ }
  }

  function boucle() {
    if (!enPause && !document.hidden) charger();     // règle 2 : rien si l'onglet est caché
    setTimeout(boucle, PERIODE);
  }

  /* ------------------------------------------------------------- commandes */

  el.pause.addEventListener("click", () => {
    enPause = !enPause;
    el.pause.setAttribute("aria-pressed", enPause ? "true" : "false");
    el.pause.textContent = enPause ? "Reprendre" : "Pause";
    majEtat(enPause ? "pause" : "attente",
            enPause ? "En pause — l'affichage est figé" : "Connexion…");
    if (!enPause) charger();
  });

  let minuteurRecherche = null;
  el.filtreRecherche.addEventListener("input", () => {
    // On attend 300 ms après la dernière frappe : sans ce délai, chaque caractère
    // déclencherait une requête, et dix caractères en enverraient dix.
    clearTimeout(minuteurRecherche);
    minuteurRecherche = setTimeout(charger, 300);
  });
  el.filtreProtocole.addEventListener("change", charger);

  // Reprise immédiate au retour sur l'onglet : sans cela, l'affichage resterait figé
  // jusqu'au prochain battement.
  document.addEventListener("visibilitychange", () => { if (!document.hidden) charger(); });

  /* ----------------------------------------------------------------- thème */
  const CLE_THEME = "analyzer-theme";

  function appliquerTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(CLE_THEME, theme); } catch (erreur) { /* mode privé */ }
  }

  el.theme.addEventListener("click", () => {
    const actuel = document.documentElement.dataset.theme;
    appliquerTheme(actuel === "clair" ? "sombre" : "clair");
  });

  try {
    const enregistre = localStorage.getItem(CLE_THEME);
    if (enregistre) appliquerTheme(enregistre);
  } catch (erreur) { /* mode privé : on garde le thème par défaut */ }

  /* ------------------------------------------------------------- partage
     Les mises en forme sont exposées : le module des communications est une autre
     fermeture et ne peut pas les voir. Les recopier créerait deux formats de taille qui
     divergeraient à la première correction. */
  window.formaterOctets = formaterOctets;
  window.formaterNombre = formaterNombre;
  window.formaterHeure = formaterHeure;

  /* ------------------------------------------------------------- démarrage */
  chargerSessions();
  charger();
  boucle();
  // Les sessions changent rarement : les rafraîchir toutes les quinze secondes suffit.
  setInterval(chargerSessions, 15000);
})();

/* =============================================================================
   Communications (Connections) — phase 2
   -----------------------------------------------------------------------------
   Rafraîchies moins souvent que les paquets : une conversation évolue en secondes, pas
   en dixièmes de seconde. Interroger à la même cadence que les paquets ferait quatre
   fois plus de requêtes pour un affichage identique.
   ============================================================================= */
(function () {
  "use strict";

  const PERIODE_COMMUNICATIONS = 3000;

  const zone = {
    corps: document.getElementById("corps-communications"),
    vide: document.getElementById("communications-vide"),
    gabarit: document.getElementById("gabarit-communication"),
    filtre: document.getElementById("filtre-etat"),
  };
  if (!zone.corps || !zone.gabarit) return;

  let enVol = false;

  function formaterDuree(secondes) {
    if (secondes === null || secondes === undefined) return "—";
    if (secondes < 1) return `${Math.round(secondes * 1000)} ms`;
    if (secondes < 60) return `${secondes.toFixed(1).replace(".", ",")} s`;
    const minutes = Math.floor(secondes / 60);
    return `${minutes} min ${Math.round(secondes % 60)} s`;
  }

  function extremite(ip, port) {
    return port === null || port === undefined ? ip : `${ip}:${port}`;
  }

  function rendre(communications) {
    zone.corps.textContent = "";
    if (!communications.length) {
      zone.vide.hidden = false;
      return;
    }
    zone.vide.hidden = true;

    const fragment = document.createDocumentFragment();
    for (const c of communications) {
      const ligne = zone.gabarit.content.firstElementChild.cloneNode(true);

      const etat = ligne.querySelector(".pastille-etat");
      etat.textContent = c.etat;
      etat.dataset.etat = c.etat;
      etat.dataset.certain = c.etat_certain ? "oui" : "non";
      etat.title = c.etat_certain
        ? "État observé directement"
        : "État déduit : la capture n'a pas vu le début de cette communication";

      const protocole = ligne.querySelector(".pastille-protocole");
      protocole.textContent = c.protocole;
      protocole.dataset.protocole = c.protocole;

      ligne.querySelector(".col-extremite-a").textContent = extremite(c.ip_a, c.port_a);
      ligne.querySelector(".col-extremite-b").textContent = extremite(c.ip_b, c.port_b);
      ligne.querySelector(".col-echanges").textContent =
        `${c.paquets_a_vers_b} → ${c.paquets_b_vers_a}`;
      ligne.querySelector(".col-volume").textContent =
        `${formaterOctets(c.octets_a_vers_b)} → ${formaterOctets(c.octets_b_vers_a)}`;
      ligne.querySelector(".col-duree").textContent = formaterDuree(c.duree_secondes);
      ligne.querySelector(".col-note").textContent = c.note_etat || "";

      fragment.appendChild(ligne);
    }
    zone.corps.appendChild(fragment);
  }

  async function charger() {
    if (enVol || document.hidden) return;
    enVol = true;
    try {
      const parametres = new URLSearchParams({ limite: "150" });
      if (zone.filtre.value) parametres.set("etat", zone.filtre.value);
      const reponse = await fetch(`/api/v1/flows?${parametres}`,
                                  { headers: { Accept: "application/json" } });
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);
      const donnees = await reponse.json();
      rendre(donnees.communications || []);
    } catch (erreur) {
      // On ne vide pas le tableau : l'indicateur principal signale déjà la panne.
      console.warn("Communications non rafraîchies :", erreur.message);
    } finally {
      enVol = false;
    }
  }

  zone.filtre.addEventListener("change", charger);
  charger();
  setInterval(charger, PERIODE_COMMUNICATIONS);
})();
