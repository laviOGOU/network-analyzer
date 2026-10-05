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

  /**
   * Le programme qui tient le port local, quand il a pu être identifié.
   *
   * Il est mis **en tête** : c'est l'information qui répond le plus directement à « que fait
   * cette machine ? ». Quand il manque — Windows ne donne pas le propriétaire d'un tiers des
   * connexions sans droits administrateur — la ligne reste exacte, simplement moins
   * parlante. Rien n'est inventé pour combler le vide.
   */
  function detailLisible(paquet) {
    const programme = (paquet.details || {}).processus_local;
    const suite = detailSansProgramme(paquet);
    return programme ? `${programme} · ${suite}` : suite;
  }

  function detailSansProgramme(paquet) {
    const detail = paquet.details || {};

    // Le nom du serveur visé, lu en clair dans le ClientHello TLS. C'est ce qui répond à
    // « quel site cette machine contacte-t-elle ? » pour une session que l'outil ne
    // déchiffre pas — et l'outil ne la déchiffre pas, par principe.
    if (detail.tls_sni) {
      return `HTTPS vers ${detail.tls_sni}`;
    }
    if (detail.http_hote) {
      const methode = detail.http_methode ? `${detail.http_methode} ` : "";
      const chemin = detail.http_chemin ? detail.http_chemin : "";
      const code = detail.http_code ? ` → ${detail.http_code}` : "";
      return `HTTP ${methode}${detail.http_hote}${chemin}${code}`;
    }
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


  /* ------------------------------------------------- recit d'une conversation */

  /**
   * Raconte une conversation : la chronologie des événements, puis le récit.
   *
   * Chaque phrase est présentée selon son genre — « fait observé » ou « lecture » — avec
   * les mêmes blocs que les explications. La distinction ne repose pas sur la couleur
   * seule : l'intitulé est écrit, sinon la moitié des lecteurs ne verrait pas la
   * différence.
   */
  async function raconterCommunication(communication) {
    const panneau = document.getElementById("recit-detail");
    const resume = document.getElementById("recit-resume");
    const conteneurMoments = document.getElementById("recit-moments");
    const conteneurPhrases = document.getElementById("recit-phrases");
    if (!panneau || !conteneurMoments || !conteneurPhrases) return;

    conteneurMoments.textContent = "";
    conteneurPhrases.textContent = "";
    resume.textContent = "Lecture de la conversation…";
    panneau.hidden = false;

    const enTete = document.querySelector(".col-extremite-b") ? "" : "";
    let donnees = null;
    try {
      const reponse = await fetch(`/api/v1/flows/recit?cle=${encodeURIComponent(communication.cle)}`,
                                  { headers: { Accept: "application/json" } });
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);
      donnees = await reponse.json();
    } catch (erreur) {
      resume.textContent = `Le récit n'a pas pu être obtenu (${erreur.message}).`;
      return;
    }

    const c = donnees.communication || communication;
    const quelle = c.nom_b || c.nom_a || c.ip_b || c.ip_a || "cette conversation";
    resume.textContent = `${c.protocole || "?"} · ${quelle} · `
      + `${donnees.paquets_analyses} paquet(s) relus pour ce récit`;

    if (!donnees.moments || !donnees.moments.length) {
      const vide = document.createElement("p");
      vide.className = "aide";
      vide.textContent = donnees.paquets_analyses
        ? "Aucun événement n'a été observé dans les paquets relus : ni ouverture, ni "
          + "fermeture, ni rupture. La conversation était sans doute déjà en cours."
        : "Les paquets de cette conversation n'ont pas été retrouvés dans la fenêtre relue.";
      conteneurMoments.appendChild(vide);
    } else {
      donnees.moments.forEach((moment) => {
        const ligne = document.createElement("div");
        ligne.className = "recit-moment";

        const delai = document.createElement("span");
        delai.className = "recit-moment-delai";
        delai.textContent = moment.depuis_debut_s === null || moment.depuis_debut_s === undefined
          ? "—" : `+ ${String(moment.depuis_debut_s).replace(".", ",")} s`;

        const nom = document.createElement("span");
        nom.className = "recit-moment-nom";
        nom.textContent = moment.moment;

        const quoi = document.createElement("span");
        quoi.textContent = moment.description || "";

        ligne.appendChild(delai);
        ligne.appendChild(nom);
        ligne.appendChild(quoi);
        conteneurMoments.appendChild(ligne);
      });
    }

    (donnees.recit || []).forEach((phrase) => {
      const bloc = document.createElement("div");
      bloc.className = phrase.genre === "fait" ? "bloc bloc-faits" : "bloc bloc-interpretation";

      const genre = document.createElement("span");
      genre.className = "recit-genre";
      genre.textContent = phrase.genre === "fait" ? "fait observé" : "lecture";

      const texte = document.createElement("span");
      texte.textContent = phrase.texte;

      bloc.appendChild(genre);
      bloc.appendChild(texte);
      conteneurPhrases.appendChild(bloc);
    });
  }

  function fermerRecit() {
    const panneau = document.getElementById("recit-detail");
    if (panneau) panneau.hidden = true;
  }

  // Ces deux fonctions sont définies dans la portée du module principal et appelées depuis
  // un bloc séparé : sans cette exposition, le clic ne ferait rien, sans erreur visible.
  // C'est le même piège que `formaterOctets` — le second module ne voit pas la fermeture
  // du premier.
  window.raconterCommunication = raconterCommunication;
  window.fermerRecit = fermerRecit;

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

      // Le texte du détail va dans un élément **interne** à la cellule : la cellule porte
      // aussi le bouton « Couches ». Écrire dans la cellule remplacerait le bouton, et
      // c'est exactement ce qui se passait.
      const detail = ligne.querySelector(".col-detail-texte") || ligne.querySelector(".col-detail");
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

  //: Liste affichée, dans l'ordre du tableau. Le détail d'un paquet a besoin de retrouver
  //: la fiche correspondant à la ligne cliquée : les identifiants n'existent pas en
  //: mémoire, et lire le texte des cellules serait plus fragile que de garder la source.
  window.paquetsAffiches = [];

  async function charger() {
    if (enVol) return;                    // règle 1 : une seule requête en vol
    enVol = true;
    try {
      const parametres = new URLSearchParams({ limite: String(LIMITE) });
      if (el.filtreProtocole.value) parametres.set("protocole", el.filtreProtocole.value);
      if (el.filtreRecherche.value.trim()) parametres.set("recherche", el.filtreRecherche.value.trim());
      if (window.filtreAffichage) parametres.set("filtre", window.filtreAffichage);

      const reponse = await fetch(`/api/v1/packets?${parametres}`, {
        headers: { Accept: "application/json" },
      });
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);

      const donnees = await reponse.json();
      signalerCriteresEcartes(donnees.filtre_ignores);
      const stats = donnees.statistiques || {};

      majCartes(stats);
      majFiltreProtocoles(stats.par_protocole);
      majRepartition(el.repartition,
        Object.entries(stats.par_protocole || {}).map(([valeur, nombre]) => ({ valeur, nombre })));
      majRepartition(el.sources, stats.top_sources || []);
      // On garde la source : le bouton « Couches » d'une ligne retrouvera ainsi sa fiche
      // par sa position, sans dépendre du texte des cellules.
      window.paquetsAffiches = donnees.paquets || [];
      majTableau(window.paquetsAffiches);
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
  document.addEventListener("filtre-change", charger);

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
    detail: document.getElementById("detail-communication"),
    detailTitre: document.getElementById("detail-titre"),
    detailResume: document.getElementById("detail-resume"),
    detailCorps: document.getElementById("detail-explications"),
    detailFermer: document.getElementById("detail-fermer"),
  };
  if (!zone.corps || !zone.gabarit) return;

  let enVol = false;
  let boutonOrigine = null;

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

  /**
   * Remplit une cellule d'extrémité : le nom connu au-dessus, l'adresse toujours dessous.
   *
   * Le nom vient des réponses DNS observées sur ce réseau — jamais d'un annuaire externe.
   * Il peut donc manquer, et il peut désigner un service partagé : c'est pourquoi il
   * accompagne l'adresse au lieu de la remplacer.
   */
  function remplirExtremite(cellule, ip, port, nom) {
    cellule.textContent = "";
    if (nom) {
      const ligneNom = document.createElement("span");
      ligneNom.className = "nom-domaine";
      ligneNom.textContent = nom;
      ligneNom.title = "Nom relevé dans les réponses DNS observées sur ce réseau";
      cellule.appendChild(ligneNom);
    }
    const ligneAdresse = document.createElement("span");
    ligneAdresse.className = "mono-cellule";
    ligneAdresse.textContent = extremite(ip, port);
    cellule.appendChild(ligneAdresse);
  }

  function rendre(communications) {
    // Le tableau est reconstruit à chaque rafraîchissement — toutes les trois secondes. Si
    // le focus se trouve sur l'un de ses boutons à cet instant, la reconstruction détruit
    // l'élément et le navigateur renvoie le focus sur la page : un lecteur au clavier perd
    // sa place sans rien avoir fait. On note donc où était le focus avant de reconstruire,
    // et on l'y remet après.
    const actif = document.activeElement;
    const focusAvant = actif && actif.classList && actif.classList.contains("bouton-detail")
      ? { cle: actif.dataset.cle, session: actif.dataset.session }
      : null;

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

      // Le nom de domaine est ajouté **au-dessus** de l'adresse, et l'adresse reste
      // affichée. Le nom est une commodité — celui que la machine a réellement demandé au
      // DNS ; l'adresse est le fait observé. Masquer l'adresse derrière un nom rendrait
      // impossible la vérification de ce qui a été vu.
      remplirExtremite(ligne.querySelector(".col-extremite-a"), c.ip_a, c.port_a, c.nom_a);
      remplirExtremite(ligne.querySelector(".col-extremite-b"), c.ip_b, c.port_b, c.nom_b);

      // La clé est posée sur le bouton : le tableau est reconstruit à chaque
      // rafraîchissement, donc on garde de quoi retrouver la conversation au clic plutôt
      // qu'un élément du document qui aura disparu.
      const boutonRecit = ligne.querySelector(".bouton-recit");
      if (boutonRecit) boutonRecit.dataset.cle = c.cle;
      ligne.querySelector(".col-echanges").textContent =
        `${c.paquets_a_vers_b} → ${c.paquets_b_vers_a}`;
      ligne.querySelector(".col-volume").textContent =
        `${formaterOctets(c.octets_a_vers_b)} → ${formaterOctets(c.octets_b_vers_a)}`;
      ligne.querySelector(".col-duree").textContent = formaterDuree(c.duree_secondes);
      // La colonne « ce que l'on peut en dire » affiche le titre produit par le moteur
      // d'explication — « Communication HTTPS probable » — plutôt que la note d'état, qui
      // ne parle que de la connexion. La note reste accessible dans le détail et dans
      // l'infobulle de la pastille.
      const explication = c.explication || null;
      const cellule = ligne.querySelector(".col-note");
      cellule.textContent = explication
        ? explication.titre
        : (c.note_etat || "—");
      if (c.note_etat) cellule.title = c.note_etat;

      // La clé et la session voyagent avec la ligne, pas dans une variable globale : le
      // tableau est reconstruit toutes les trois secondes, une variable globale désignerait
      // vite une ligne qui n'existe plus.
      const bouton = ligne.querySelector(".bouton-detail");
      bouton.dataset.cle = c.cle || "";
      bouton.dataset.session = c.session || "";
      bouton.setAttribute("aria-label",
        `Expliquer la communication entre ${c.ip_a} et ${c.ip_b}`);

      fragment.appendChild(ligne);
    }
    zone.corps.appendChild(fragment);

    // Rendre le focus à la ligne qui l'avait, si elle est toujours affichée. Sans cela, le
    // bouton cliqué « disparaît » sous les doigts de l'utilisateur au bout de trois
    // secondes, et la touche Entrée n'a plus d'effet.
    if (focusAvant) {
      const cible = Array.from(zone.corps.querySelectorAll(".bouton-detail"))
        .find((b) => b.dataset.cle === focusAvant.cle
                  && b.dataset.session === focusAvant.session);
      if (cible) cible.focus();
    }
  }

  async function charger() {
    if (enVol || document.hidden) return;
    enVol = true;
    try {
      const parametres = new URLSearchParams({ limite: "150" });
      if (zone.filtre.value) parametres.set("etat", zone.filtre.value);
      if (window.filtreAffichage) parametres.set("filtre", window.filtreAffichage);
      const reponse = await fetch(`/api/v1/flows?${parametres}`,
                                  { headers: { Accept: "application/json" } });
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);
      const donnees = await reponse.json();
      signalerCriteresEcartes(donnees.filtre_ignores);
      rendre(donnees.communications || []);
    } catch (erreur) {
      // On ne vide pas le tableau : l'indicateur principal signale déjà la panne.
      console.warn("Communications non rafraîchies :", erreur.message);
    } finally {
      enVol = false;
    }
  }

  /* ------------------------------------------------------------------ détail */

  /** Construit un bloc « faits » ou « interprétation », avec son intitulé écrit. */
  function bloc(intitule, contenu, classe) {
    const enveloppe = document.createElement("div");
    enveloppe.className = `bloc ${classe}`;

    const titre = document.createElement("span");
    titre.className = "bloc-intitule";
    titre.textContent = intitule;
    enveloppe.appendChild(titre);

    if (Array.isArray(contenu)) {
      // Une liste de faits : chacun est un élément vérifiable.
      const liste = document.createElement("ul");
      for (const element of contenu) {
        const item = document.createElement("li");
        item.textContent = element;
        liste.appendChild(item);
      }
      enveloppe.appendChild(liste);
    } else {
      const paragraphe = document.createElement("p");
      paragraphe.textContent = contenu;
      enveloppe.appendChild(paragraphe);
    }
    return enveloppe;
  }

  function rendreDetail(donnees) {
    zone.detailCorps.textContent = "";

    const communication = donnees.communication || {};
    zone.detailTitre.textContent = `Communication ${communication.protocole || ""} — `
      + `${extremite(communication.ip_a, communication.port_a)} vers `
      + `${extremite(communication.ip_b, communication.port_b)}`;

    const duree = formaterDuree(communication.duree_secondes);
    zone.detailResume.textContent =
      `État : ${communication.etat || "inconnu"}`
      + (communication.etat_certain ? " (observé)" : " (déduit)")
      + ` · ${communication.paquets_total || 0} paquets · `
      + `${formaterOctets(communication.octets_total || 0)} · durée ${duree}`;

    for (const explication of donnees.explications || []) {
      const enveloppe = document.createElement("div");
      enveloppe.className = "explication";

      const titre = document.createElement("h4");
      titre.className = "explication-titre";
      titre.appendChild(document.createTextNode(explication.titre));

      const confiance = document.createElement("span");
      confiance.className = `etiquette etiquette--${explication.confiance}`;
      confiance.textContent = `confiance ${explication.confiance}`;
      titre.appendChild(confiance);

      // Dire d'où vient la phrase : d'une règle écrite, ou d'un modèle qui l'a reformulée.
      const source = document.createElement("span");
      source.className = "etiquette etiquette--source";
      source.textContent = explication.source === "ia" ? "reformulé par IA" : "règle déterministe";
      titre.appendChild(source);
      enveloppe.appendChild(titre);

      enveloppe.appendChild(bloc("Faits observés", explication.faits_observes || [], "bloc-faits"));
      enveloppe.appendChild(bloc("Interprétation", explication.interpretation || "",
                                 "bloc-interpretation"));
      if (explication.explication_simple) {
        enveloppe.appendChild(bloc("En clair", explication.explication_simple, "bloc-simple"));
      }

      zone.detailCorps.appendChild(enveloppe);
    }

    // Rappel systématique : c'est la phrase qui protège le lecteur d'une conclusion trop
    // rapide, et elle doit être présente même quand la confiance est haute.
    const rappel = document.createElement("p");
    rappel.className = "jamais-certain";
    rappel.textContent = "Identifications de services déduites du numéro de port : "
      + "probables, jamais certaines. Cet outil n'analyse pas le contenu chiffré.";
    zone.detailCorps.appendChild(rappel);
  }

  async function ouvrirDetail(bouton) {
    const parametres = new URLSearchParams({ cle: bouton.dataset.cle });
    if (bouton.dataset.session) parametres.set("session", bouton.dataset.session);

    bouton.disabled = true;
    try {
      const reponse = await fetch(`/api/v1/flows/explications?${parametres}`,
                                  { headers: { Accept: "application/json" } });
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);
      rendreDetail(await reponse.json());
      zone.detail.hidden = false;
      // On mémorise les identifiants de la ligne, **pas l'élément** : le tableau est
      // reconstruit toutes les trois secondes, et l'élément mémorisé serait détaché du
      // document au moment de rendre le focus — sur lequel focus() est alors sans effet.
      boutonOrigine = { cle: bouton.dataset.cle, session: bouton.dataset.session };
      // Le focus suit l'ouverture : sinon, un lecteur au clavier ne saurait pas que quelque
      // chose s'est affiché, et devrait parcourir la page entière pour le trouver.
      zone.detailFermer.focus();
    } catch (erreur) {
      zone.detail.hidden = false;
      zone.detailTitre.textContent = "Explication indisponible";
      zone.detailCorps.textContent = "";
      zone.detailResume.textContent = `La demande a échoué : ${erreur.message}`;
      zone.detailFermer.focus();
    } finally {
      bouton.disabled = false;
    }
  }

  function fermerDetail() {
    zone.detail.hidden = true;
    if (!boutonOrigine) return;

    const origine = boutonOrigine;
    boutonOrigine = null;

    // On retrouve le bouton de la même ligne dans la table telle qu'elle est maintenant.
    const cible = Array.from(document.querySelectorAll(".bouton-detail"))
      .find((b) => b.dataset.cle === origine.cle && b.dataset.session === origine.session);

    // Si la communication a disparu du tableau entre-temps, le focus va sur le filtre :
    // jamais nulle part, sinon un lecteur au clavier repart du début de la page.
    (cible || zone.filtre).focus();
  }

  zone.corps.addEventListener("click", (evenement) => {
    const bouton = evenement.target.closest(".bouton-detail");
    if (bouton) ouvrirDetail(bouton);
  });

  zone.detailFermer.addEventListener("click", fermerDetail);
  document.addEventListener("keydown", (evenement) => {
    if (evenement.key === "Escape" && !zone.detail.hidden) fermerDetail();
  });

  zone.filtre.addEventListener("change", charger);
  document.addEventListener("filtre-change", charger);
  charger();
  setInterval(charger, PERIODE_COMMUNICATIONS);
})();


/* =============================================================================
   Détections — la section « Alerts »
   -----------------------------------------------------------------------------
   Un module à part, comme celui des communications : il a sa propre cadence, ses
   propres filtres, et il échoue indépendamment. Si l'agent ne transmet pas de
   détections, cette section reste simplement vide sans que le reste en souffre.
   ============================================================================= */
(function () {
  "use strict";

  const PERIODE_DETECTIONS = 5000;

  const zone = {
    liste: document.getElementById("liste-detections"),
    vide: document.getElementById("detections-vide"),
    gabarit: document.getElementById("gabarit-detection"),
    filtre: document.getElementById("filtre-niveau"),
  };
  if (!zone.liste || !zone.gabarit) return;

  let enVol = false;

  function formaterHeure(iso) {
    if (!iso) return "—";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "—";
    return date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit",
                                              second: "2-digit" });
  }

  function rendre(detections) {
    zone.liste.textContent = "";
    if (!detections.length) {
      zone.vide.hidden = false;
      return;
    }
    zone.vide.hidden = true;

    const fragment = document.createDocumentFragment();
    for (const detection of detections) {
      const carte = zone.gabarit.content.firstElementChild.cloneNode(true);

      const niveau = carte.querySelector(".etiquette-niveau");
      // Le niveau est écrit en toutes lettres, et non seulement coloré : environ un
      // homme sur douze distingue mal le rouge du vert.
      niveau.textContent = detection.niveau;
      niveau.dataset.niveau = detection.niveau;

      carte.querySelector(".detection-titre").textContent = detection.titre;
      carte.querySelector(".detection-cible").textContent = detection.cible;

      const faits = carte.querySelector(".detection-faits");
      for (const fait of detection.faits_observes || []) {
        const item = document.createElement("li");
        item.textContent = fait;
        faits.appendChild(item);
      }

      carte.querySelector(".detection-explication").textContent = detection.explication || "";
      carte.querySelector(".detection-faux-positifs").textContent =
        detection.faux_positifs || "Non précisé par cette règle.";

      carte.querySelector(".detection-confiance").textContent =
        `confiance ${detection.confiance || "inconnue"} · règle « ${detection.regle} »`;

      const occurrences = detection.occurrences || 1;
      carte.querySelector(".detection-occurrences").textContent = occurrences > 1
        ? `revue ${occurrences} fois · dernière à ${formaterHeure(detection.dernier)}`
        : `observée à ${formaterHeure(detection.debut)}`;

      fragment.appendChild(carte);
    }
    zone.liste.appendChild(fragment);
  }

  async function charger() {
    if (enVol || document.hidden) return;
    enVol = true;
    try {
      const parametres = new URLSearchParams({ limite: "50" });
      if (zone.filtre.value) parametres.set("niveau", zone.filtre.value);
      if (window.filtreAffichage) parametres.set("filtre", window.filtreAffichage);
      const reponse = await fetch(`/api/v1/alerts?${parametres}`,
                                  { headers: { Accept: "application/json" } });
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);
      const donnees = await reponse.json();
      signalerCriteresEcartes(donnees.filtre_ignores);
      rendre(donnees.detections || []);
    } catch (erreur) {
      // On ne vide pas la liste : l'indicateur principal signale déjà la panne, et des
      // détections anciennes valent mieux qu'un écran vide.
      console.warn("Détections non rafraîchies :", erreur.message);
    } finally {
      enVol = false;
    }
  }

  zone.filtre.addEventListener("change", charger);
  document.addEventListener("filtre-change", charger);
  charger();
  setInterval(charger, PERIODE_DETECTIONS);
})();


/**
 * Annonce à la barre de filtre les critères qu'une vue n'a pas pu appliquer.
 *
 * Chaque liste appelle cette fonction après sa requête. Les critères écartés s'additionnent
 * : « proto » n'a pas de sens pour les détections, « niveau » n'en a pas pour les paquets,
 * et l'utilisateur doit voir les deux plutôt que le dernier reçu.
 *
 * Une variable globale et un événement : c'est ce qui évite que les quatre modules se
 * connaissent les uns les autres. Chacun signale ce qu'il sait, la barre rassemble.
 */
function signalerCriteresEcartes(champs) {
  if (!Array.isArray(champs)) return;
  // Création paresseuse : les modules de liste démarrent avant que cette ligne ne soit
  // atteinte, et une requête peut revenir très vite. Initialiser ici plutôt qu'au
  // chargement évite de dépendre de l'ordre d'exécution du fichier.
  window.criteresEcartes = window.criteresEcartes || new Set();
  let change = false;
  for (const champ of champs) {
    if (!window.criteresEcartes.has(champ)) { window.criteresEcartes.add(champ); change = true; }
  }
  if (change) document.dispatchEvent(new CustomEvent("filtre-ecarte"));
}

/* =============================================================================
   Barre de filtre d'affichage
   -----------------------------------------------------------------------------
   Un seul filtre, trois listes. Le choix d'un état partagé plutôt que d'un filtre par
   liste est délibéré : un filtre qui ne s'appliquerait qu'à une partie de la page
   donnerait deux réponses différentes à la même question, et l'utilisateur ne saurait
   pas laquelle croire.

   La validation se fait **avant** d'engager les listes : une requête d'essai sur un seul
   paquet dit si l'expression est comprise. Si elle ne l'est pas, le message du serveur
   est affiché tel quel et les listes ne bougent pas — elles continuent de montrer les
   dernières données valides, plutôt que de se vider sur une faute de frappe.
   ============================================================================= */
(function () {
  "use strict";

  const DELAI_FRAPPE = 400;        // ms : on ne valide pas à chaque caractère

  const zone = {
    champ: document.getElementById("champ-filtre"),
    effacer: document.getElementById("effacer-filtre"),
    erreur: document.getElementById("filtre-erreur"),
    resume: document.getElementById("filtre-resume"),
  };
  if (!zone.champ) return;

  //: État partagé, lu par les trois modules de liste. Une variable globale assumée : la
  //: alternative serait de faire circuler le filtre de module en module, ce qui les
  //: rendrait dépendants les uns des autres.
  window.filtreAffichage = "";

  let minuteur = null;

  function afficherErreur(message) {
    zone.erreur.textContent = message || "";
    zone.erreur.hidden = !message;
    zone.champ.dataset.invalide = message ? "oui" : "non";
    zone.champ.setAttribute("aria-invalid", message ? "true" : "false");
  }

  function afficherResume(expression) {
    if (!expression) {
      zone.resume.hidden = true;
      zone.resume.textContent = "";
      return;
    }
    // On réaffiche ce que le serveur a compris : une valeur mal orthographiée se voit.
    zone.resume.hidden = false;
    zone.resume.textContent = "";
    const avant = document.createTextNode("Filtre appliqué : ");
    const code = document.createElement("code");
    code.textContent = expression;
    zone.resume.appendChild(avant);
    zone.resume.appendChild(code);
  }

  /** Réaffiche les critères sans objet, et vide la liste quand le filtre change. */
  function afficherCriteresEcartes() {
    const champs = [...(window.criteresEcartes || [])];
    if (!champs.length) {
      zone.resume.title = "";
      return;
    }
    zone.resume.title = "Sans objet dans cette vue : " + champs.join(", ");
  }

  async function validerEtAppliquer() {
    const expression = zone.champ.value.trim();
    // Nouveau filtre : les critères écartés de l'ancien ne veulent plus rien dire.
    if (window.criteresEcartes) window.criteresEcartes.clear();

    if (!expression) {
      afficherErreur("");
      afficherResume("");
      window.filtreAffichage = "";
      document.dispatchEvent(new CustomEvent("filtre-change"));
      return;
    }

    try {
      // Requête d'essai : un seul enregistrement suffit à savoir si l'expression est
      // comprise. Elle ne sert pas à afficher quoi que ce soit.
      const reponse = await fetch(
        `/api/v1/packets?limite=1&filtre=${encodeURIComponent(expression)}`,
        { headers: { Accept: "application/json" } });

      if (reponse.status === 400) {
        const donnees = await reponse.json();
        afficherErreur(donnees.detail || "Filtre incompris.");
        afficherResume("");
        window.filtreAffichage = "";
        return;
      }
      if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);

      afficherErreur("");
      afficherResume(expression);
      window.filtreAffichage = expression;
      document.dispatchEvent(new CustomEvent("filtre-change"));
    } catch (erreur) {
      // Une panne réseau n'est pas un filtre invalide : on le dit autrement, et on ne
      // touche pas au filtre en cours.
      afficherErreur(`Impossible de vérifier le filtre : ${erreur.message}`);
    }
  }

  function planifier() {
    if (minuteur) clearTimeout(minuteur);
    minuteur = setTimeout(validerEtAppliquer, DELAI_FRAPPE);
  }

  document.addEventListener("filtre-ecarte", afficherCriteresEcartes);
  zone.champ.addEventListener("input", planifier);
  // La touche Entrée applique tout de suite, sans attendre le délai.
  zone.champ.addEventListener("keydown", (evenement) => {
    if (evenement.key === "Enter") {
      evenement.preventDefault();
      if (minuteur) clearTimeout(minuteur);
      validerEtAppliquer();
    }
    if (evenement.key === "Escape") {
      zone.champ.value = "";
      if (minuteur) clearTimeout(minuteur);
      validerEtAppliquer();
    }
  });

  zone.effacer.addEventListener("click", () => {
    zone.champ.value = "";
    if (minuteur) clearTimeout(minuteur);
    validerEtAppliquer();
    zone.champ.focus();
  });
})();


/* =============================================================================
   Détail d'un paquet : les couches, leur rôle, et les octets des en-têtes
   -----------------------------------------------------------------------------
   Deux choses que cette vue ne fait pas, et qui sont écrites à l'écran :

     - elle ne montre pas le paquet, elle montre **ce que l'analyseur en a compris**.
       Aucun octet brut ne circule dans ce projet ; les octets affichés sont recalculés
       à partir des champs analysés.
     - elle laisse visibles les octets qu'elle ne sait pas reconstruire, sous la forme
       « ?? ». Les combler par des zéros donnerait un affichage plus complet et faux.

   Le savoir est côté serveur : la disposition des champs, leur largeur, l'explication
   du rôle de chaque couche viennent de /api/v1/layers. Ici, on ne fait que mettre en
   forme des valeurs déjà reçues.
   ============================================================================= */
(function () {
  "use strict";

  const zone = {
    panneau: document.getElementById("paquet-detail"),
    titre: document.getElementById("paquet-detail-titre"),
    resume: document.getElementById("paquet-detail-resume"),
    couches: document.getElementById("paquet-couches"),
    avertissement: document.getElementById("paquet-hex-avertissement"),
    hex: document.getElementById("paquet-hex"),
    fermer: document.getElementById("paquet-detail-fermer"),
    vide: document.getElementById("paquet-detail-vide"),
    contenu: document.getElementById("paquet-detail-contenu"),
  };
  if (!zone.panneau) return;

  // Le panneau reste visible en permanence : c'est un volet, pas une fenêtre. Ces deux
  // fonctions basculent entre le message d'attente et le contenu — jamais entre visible et
  // caché, sinon il faudrait retenir ce qu'on vient de quitter.
  function montrerAttente() {
    if (zone.vide) zone.vide.hidden = false;
    if (zone.contenu) zone.contenu.hidden = true;
  }

  function montrerContenu() {
    if (zone.vide) zone.vide.hidden = true;
    if (zone.contenu) zone.contenu.hidden = false;
  }

  montrerAttente();

  let connaissance = null;
  let paquetCourant = null;
  let boutonOrigine = null;

  // --------------------------------------------------------------- octets
  function octetsDeMAC(valeur) {
    const morceaux = String(valeur).split(":");
    if (morceaux.length !== 6 || morceaux.some((m) => !/^[0-9a-fA-F]{2}$/.test(m))) return null;
    return morceaux.map((m) => m.toLowerCase()).join(" ");
  }

  function octetsDeNombre(valeur, largeur) {
    if (valeur === null || valeur === undefined || valeur === "") return null;
    const nombre = Number(valeur);
    if (!Number.isFinite(nombre) || nombre < 0) return null;
    return nombre.toString(16).padStart(largeur * 2, "0").match(/../g).join(" ");
  }

  function octetsDAdresse(valeur) {
    const texte = String(valeur);
    // IPv4 : quatre nombres de 0 à 255. C'est le cas courant, et il est sans ambiguïté.
    const morceaux = texte.split(".");
    if (morceaux.length === 4 && morceaux.every((m) => /^\d{1,3}$/.test(m) && +m <= 255)) {
      return morceaux.map((m) => (+m).toString(16).padStart(2, "0")).join(" ");
    }
    return null;                       // IPv6 : montré au-dessus, non recalculé ici
  }

  function octetsDuChamp(source, paquet) {
    if (!source) return null;
    const valeur = source === "details"
      ? (paquet.details && Object.keys(paquet.details).length ? "…" : null)
      : paquet[source];

    if (source === "mac_source" || source === "mac_destination") return octetsDeMAC(valeur);
    if (source === "ip_source" || source === "ip_destination") return octetsDAdresse(valeur);
    if (source === "port_source" || source === "port_destination") return octetsDeNombre(valeur, 2);
    if (source === "ttl") return octetsDeNombre(valeur, 1);
    if (source === "taille") return octetsDeNombre(valeur, 2);
    if (source === "version_ip") return valeur ? ("0" + valeur) : null;
    if (source === "protocole") {
      const numeros = { TCP: "06", UDP: "11", ICMP: "01", ICMPv6: "3a", ARP: "0806" };
      const code = numeros[String(valeur)];
      return code || null;
    }
    return null;
  }

  // --------------------------------------------------------------- rendu
  function rendreCouches(paquet) {
    zone.couches.textContent = "";
    for (const couche of connaissance.couches) {
      const bloc = document.createElement("section");
      bloc.className = "couche";

      const nom = document.createElement("h5");
      nom.className = "couche__nom";
      nom.textContent = couche.nom;
      bloc.appendChild(nom);

      const role = document.createElement("p");
      role.className = "couche__role";
      role.textContent = couche.role;
      bloc.appendChild(role);

      const liste = document.createElement("ul");
      liste.className = "couche__champs";
      for (const champ of couche.champs) {
        const item = document.createElement("li");

        const intitule = document.createElement("span");
        intitule.className = "couche__champ";
        intitule.textContent = champ.libelle;
        item.appendChild(intitule);

        const valeur = document.createElement("span");
        const brut = champ.source === "details"
          ? (paquet.details && paquet.details.dns_question ? paquet.details.dns_question : "")
          : (champ.source ? paquet[champ.source] : "");
        if (brut === null || brut === undefined || brut === "" || !champ.source) {
          valeur.className = "couche__valeur couche__valeur--absente";
          valeur.textContent = "non extrait";
        } else {
          valeur.className = "couche__valeur";
          valeur.textContent = String(brut);
        }
        item.appendChild(valeur);
        liste.appendChild(item);
      }
      bloc.appendChild(liste);
      zone.couches.appendChild(bloc);
    }
  }

  function rendreHex(paquet) {
    const lignes = [];
    for (const couche of connaissance.couches) {
      lignes.push(`--- ${couche.nom} ---`);
      for (const champ of couche.champs) {
        const octets = octetsDuChamp(champ.source, paquet);
        const placement = octets || "??".padEnd(11, "?");
        lignes.push(`${champ.libelle.padEnd(30, " ")} ${placement}`);
      }
    }
    zone.hex.textContent = lignes.join("\n");
  }

  async function ouvrir(paquet, bouton) {
    if (!connaissance) {
      try {
        const reponse = await fetch("/api/v1/layers", { headers: { Accept: "application/json" } });
        if (!reponse.ok) throw new Error(`réponse ${reponse.status}`);
        connaissance = await reponse.json();
      } catch (erreur) {
        montrerContenu();
        zone.titre.textContent = "Description des couches indisponible";
        zone.resume.textContent = `La demande a échoué : ${erreur.message}`;
        return;
      }
    }

    paquetCourant = paquet;
    // Le titre reste **fixe** : il nomme la zone, il ne décrit pas son contenu. Écrasé à
    // chaque sélection, il faisait disparaître l'étiquette — et une zone sans nom ne se
    // reconnaît plus d'un coup d'œil, ce qui est justement ce qu'on cherche ici. Le paquet
    // est décrit sur la ligne suivante.
    zone.resume.textContent = `${paquet.protocole || "Paquet"} `
      + `${paquet.ip_source || "?"} → ${paquet.ip_destination || "?"}`
      + ` · ${paquet.taille || "?"} octets · TTL ${paquet.ttl ?? "?"}`
      + (paquet.flags_tcp ? ` · indicateurs ${paquet.flags_tcp}` : "")
      + (paquet.analyse_partielle ? " · analyse partielle, voir le motif ci-dessus" : "");
    zone.avertissement.textContent = connaissance.avertissement_hex;

    rendreCouches(paquet);
    rendreHex(paquet);
    // Le volet ne s'ouvre pas : il se remplit. Et le focus n'est plus déplacé — il n'y a
    // rien à annoncer, puisque la zone était déjà à l'écran. Voler le focus de la ligne
    // qu'on vient de cliquer ferait perdre sa place à qui navigue au clavier.
    montrerContenu();
    boutonOrigine = bouton;
  }

  function fermer() {
    montrerAttente();
    zone.couches.textContent = "";
    zone.hex.textContent = "";
    zone.resume.textContent = "";
    zone.avertissement.textContent = "";
    paquetCourant = null;
    if (boutonOrigine) { boutonOrigine.focus(); boutonOrigine = null; }
  }

  // Les lignes du tableau des paquets sont reconstruites à chaque rafraîchissement : on
  // garde le paquet en mémoire au moment du clic, et non un élément du document.
  document.addEventListener("click", (evenement) => {
    const bouton = evenement.target.closest(".bouton-couches");
    if (!bouton) return;
    const ligne = bouton.closest("tr");
    const index = ligne && ligne.parentElement ? [...ligne.parentElement.children].indexOf(ligne) : -1;
    const paquet = window.paquetsAffiches ? window.paquetsAffiches[index] : null;
    if (paquet) ouvrir(paquet, bouton);
  });

  zone.fermer.addEventListener("click", fermer);
  document.addEventListener("keydown", (evenement) => {
    if (evenement.key === "Escape" && !zone.panneau.hidden) fermer();
  });
})();

/* Le recit d'une conversation : obtention a la demande, jamais a chaque rafraichissement du
   tableau de bord. Raconter demande de relire les paquets de la conversation — ce n'est pas
   quelque chose qu'on fait toutes les trois secondes pour toutes les lignes. */
(() => {
  const panneau = document.getElementById("recit-detail");
  const boutonFermer = document.getElementById("recit-fermer");
  if (!panneau || !boutonFermer) return;

  document.addEventListener("click", (evenement) => {
    const bouton = evenement.target.closest(".bouton-recit");
    if (!bouton) return;
    const cle = bouton.dataset.cle;
    if (!cle) return;
    raconterCommunication({ cle: cle }).then(() => {
      panneau.scrollIntoView({ block: "nearest" });
      boutonFermer.focus();
    });
  });

  boutonFermer.addEventListener("click", fermerRecit);
  document.addEventListener("keydown", (evenement) => {
    if (evenement.key === "Escape" && !panneau.hidden) fermerRecit();
  });
})();

/* Les liens d'export suivent le filtre courant : on exporte ce que l'on voit. */
(function () {
  "use strict";
  const liens = [...document.querySelectorAll(".exports a")];

  function mettreAJour() {
    const filtre = window.filtreAffichage
      ? `&filtre=${encodeURIComponent(window.filtreAffichage)}` : "";
    for (const lien of liens) lien.href = lien.dataset.base || lien.href.split("&filtre=")[0];
    for (const lien of liens) {
      lien.dataset.base = lien.href;
      if (filtre) lien.href += filtre;
    }
  }

  document.addEventListener("filtre-change", mettreAJour);
  mettreAJour();
})();

/* ============================================================ répartitions et Expert Info

   Ces deux ensembles sont chargés à part du cycle principal du tableau de bord : ils
   demandent de relire les paquets — trois mille d'un coup — ce qu'on ne fait pas toutes les
   trois secondes. Un intervalle plus long suffit, et personne ne s'en aperçoit.

   Le rendu n'emploie que `textContent` : ce qui s'affiche vient du réseau, et une chaîne
   réseau insérée comme HTML s'exécuterait. */
(function () {
  "use strict";

  const hierarchie = document.getElementById("stats-hierarchie");
  const extremites = document.getElementById("stats-extremites");
  const graphique = document.getElementById("stats-debit");
  const listeAnomalies = document.getElementById("anomalies-liste");
  const resumeAnomalies = document.getElementById("anomalies-resume");
  if (!hierarchie || !extremites || !graphique || !listeAnomalies) return;

  const octets = (valeur) => {
    const nombre = Number(valeur) || 0;
    if (nombre < 1000) return `${nombre} o`;
    if (nombre < 1000000) return `${(nombre / 1000).toFixed(1).replace(".", ",")} ko`;
    return `${(nombre / 1000000).toFixed(1).replace(".", ",")} Mo`;
  };

  /** Une ligne : le nom, une barre proportionnelle, et le chiffre écrit.
   *  Le chiffre est là parce qu'une barre ne se lit pas au lecteur d'écran, et qu'une
   *  longueur relative ne dit pas une valeur. */
  function ligne(nom, part, maximum, chiffre) {
    const rangee = document.createElement("div");
    rangee.className = "ligne-part";

    const etiquette = document.createElement("span");
    etiquette.className = "ligne-part-nom";
    etiquette.textContent = nom;

    const rail = document.createElement("div");
    rail.className = "barre";
    const remplissage = document.createElement("div");
    remplissage.className = "barre-part";
    remplissage.style.width = maximum > 0
      ? `${Math.max(1, Math.round(100 * part / maximum))}%` : "0%";
    rail.appendChild(remplissage);

    const valeur = document.createElement("span");
    valeur.className = "ligne-part-chiffre";
    valeur.textContent = chiffre;

    rangee.appendChild(etiquette);
    rangee.appendChild(rail);
    rangee.appendChild(valeur);
    return rangee;
  }

  function rendreHierarchie(donnees) {
    hierarchie.textContent = "";
    const total = donnees.total || 0;
    if (!total) {
      const vide = document.createElement("p");
      vide.className = "aide";
      vide.textContent = "Aucun paquet dans la fenêtre analysée.";
      hierarchie.appendChild(vide);
      return;
    }
    const maximum = Math.max(...donnees.protocoles.map((p) => p.pourcent), 1);
    donnees.protocoles.forEach((part) => {
      hierarchie.appendChild(ligne(part.nom, part.pourcent, maximum,
        `${part.pourcent.toString().replace(".", ",")} % · ${part.paquets}`));
    });
    const totalLigne = document.createElement("p");
    totalLigne.className = "aide";
    totalLigne.textContent = `Sur ${total} paquet(s) examiné(s).`;
    hierarchie.appendChild(totalLigne);
  }

  function rendreExtremites(donnees) {
    extremites.textContent = "";
    const liste = donnees.extremites || [];
    if (!liste.length) {
      const vide = document.createElement("p");
      vide.className = "aide";
      vide.textContent = "Aucune machine identifiable dans la fenêtre analysée.";
      extremites.appendChild(vide);
      return;
    }
    const maximum = Math.max(...liste.map((f) => f.total), 1);
    liste.slice(0, 8).forEach((fiche) => {
      extremites.appendChild(ligne(fiche.adresse, fiche.total, maximum,
        `${fiche.total} ⇅ · ${octets(fiche.octets_total)}`));
    });
  }

  function rendreDebit(donnees) {
    graphique.textContent = "";
    const points = donnees.points || [];
    if (!points.length) {
      const vide = document.createElement("p");
      vide.className = "aide";
      vide.textContent = "Aucun paquet daté : pas de débit à tracer.";
      graphique.appendChild(vide);
      return;
    }
    const maximum = donnees.maximum_octets || 1;
    points.forEach((point) => {
      const palier = document.createElement("div");
      palier.className = "debit-palier";
      palier.style.height = `${Math.max(2, Math.round(100 * point.octets / maximum))}%`;
      // L'information est aussi dans l'attribut `title` : une barre sans chiffre ne se lit
      // pas autrement qu'à l'œil.
      palier.title = `+${String(point.offset_s).replace(".", ",")} s · `
        + `${point.paquets} paquet(s) · ${octets(point.octets)}`;
      graphique.appendChild(palier);
    });
    const legende = document.createElement("p");
    legende.className = "aide";
    legende.textContent = `${points.length} intervalle(s) de `
      + `${String(donnees.seau_secondes).replace(".", ",")} s · pic à `
      + `${octets(maximum)} par intervalle. Survolez une barre pour le détail.`;
    graphique.parentElement.appendChild(legende);
  }

  function rendreAnomalies(donnees) {
    listeAnomalies.textContent = "";
    if (donnees.disponible === false) {
      resumeAnomalies.textContent = "";
      const indisponible = document.createElement("p");
      indisponible.className = "aide";
      indisponible.textContent = donnees.note || "Analyse indisponible dans ce déploiement.";
      listeAnomalies.appendChild(indisponible);
      return;
    }

    const anomalies = donnees.anomalies || [];
    resumeAnomalies.textContent = `${donnees.total} anomalie(s) observée(s) sur `
      + `${donnees.paquets_examines} paquet(s) examiné(s)`;

    if (!anomalies.length) {
      // Une liste vide sans ce chiffre laisserait croire que rien n'a été analysé.
      const vide = document.createElement("p");
      vide.className = "aide";
      vide.textContent = donnees.paquets_examines
        ? "Aucune anomalie dans les paquets examinés."
        : "Aucun paquet à examiner pour l'instant.";
      listeAnomalies.appendChild(vide);
      return;
    }

    anomalies.slice(0, 12).forEach((anomalie) => {
      const bloc = document.createElement("div");
      bloc.className = "anomalie";

      const titre = document.createElement("div");
      titre.className = "anomalie-titre";
      titre.textContent = `${anomalie.anomalie} — `
        + `${anomalie.sens || anomalie.conversation || ""}`;
      bloc.appendChild(titre);

      const criteres = document.createElement("ul");
      criteres.className = "anomalie-criteres";
      (anomalie.criteres || []).forEach((critere) => {
        const item = document.createElement("li");
        item.textContent = critere;
        criteres.appendChild(item);
      });
      bloc.appendChild(criteres);
      listeAnomalies.appendChild(bloc);
    });
  }

  async function charger() {
    try {
      const [repartition, expert] = await Promise.all([
        fetch("/api/v1/statistiques?limite=3000", { headers: { Accept: "application/json" } }),
        fetch("/api/v1/anomalies?limite=800", { headers: { Accept: "application/json" } }),
      ]);
      if (repartition.ok) {
        const donnees = await repartition.json();
        rendreHierarchie(donnees.hierarchie || {});
        rendreExtremites(donnees.extremites || {});
        rendreDebit(donnees.debit || {});
      }
      if (expert.ok) rendreAnomalies(await expert.json());
    } catch (erreur) {
      // Un tableau de bord ne doit pas se vider parce qu'une vue secondaire a échoué : les
      // autres sections continuent de fonctionner.
      resumeAnomalies.textContent = "Statistiques indisponibles pour l'instant.";
    }
  }

  charger();
  setInterval(charger, 15000);
})();

/* =============================================================== profils d'analyse

   Un profil est un nom, un filtre et une phrase qui dit à quoi il sert. Les chercher dans le
   code n'aurait pas de sens : ils sont servis par l'API, où ils sont validés à
   l'enregistrement par le même parseur qui les applique.

   Choisir un profil **remplit le champ de filtre** au lieu de filtrer autrement : ce qui
   s'applique reste visible, et modifiable. Un filtre appliqué en secret derrière l'écran
   serait impossible à vérifier. */
(function () {
  "use strict";

  const choix = document.getElementById("choix-profil");
  const champ = document.getElementById("champ-filtre");
  const aide = document.getElementById("aide-filtre");
  if (!choix || !champ) return;

  let profils = [];

  function remplir() {
    choix.textContent = "";
    const vide = document.createElement("option");
    vide.value = "";
    vide.textContent = profils.length ? "Profils…" : "Aucun profil";
    choix.appendChild(vide);

    profils.forEach((profil, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = profil.nom;
      choix.appendChild(option);
    });
  }

  function appliquer(index) {
    const profil = profils[index];
    if (!profil) return;

    // On remplit le champ **et** on signale le changement : le filtre est appliqué par le
    // même chemin que si l'utilisateur l'avait tapé. Un second chemin de filtrage finirait
    // par diverger du premier.
    champ.value = profil.filtre || "";
    champ.dispatchEvent(new Event("input", { bubbles: true }));

    if (aide && profil.description) {
      aide.textContent = profil.description;
    }
    choix.value = "";
  }

  choix.addEventListener("change", () => {
    if (choix.value !== "") appliquer(Number(choix.value));
  });

  fetch("/api/v1/profils", { headers: { Accept: "application/json" } })
    .then((reponse) => (reponse.ok ? reponse.json() : null))
    .then((donnees) => {
      if (!donnees || !Array.isArray(donnees.profils)) return;
      profils = donnees.profils;
      remplir();
    })
    .catch(() => {
      // Un sélecteur vide n'empêche pas de filtrer à la main : on ne bloque rien.
    });
})();
