# Maison Diagnostic réel 0.8.0

Nouvelle application distincte, lecture seule réelle après activation locale. Aucun
appel de service, commande d’équipement, écriture de configuration, reload ou déploiement.
Le jeton Supervisor est puissant : l’isolation de lecture est assurée par le code
et les commandes autorisées, pas par un jeton Home Assistant intrinsèquement limité.

Installer uniquement l’image ARM64/AMD64 publiée après revue, validation et preuve
de provenance. Conserver Maison Read Gateway 0.5 et les applications existantes.
Garder protection activée, démarrage manuel, mises à jour automatiques et watchdog désactivés.

Une seule configuration locale est nécessaire : renseigner un jeton client distinct,
une clé d’enrôlement Tailscale limitée au tag `tag:ha-diagnostic`, puis activer
`read_approved`, `acl_reviewed` et `enabled` après avoir vérifié les ACL.
Ne communiquer aucun jeton dans une conversation ou dans Git. Retirer la clé
d’enrôlement des options après la première connexion ; l’identité persiste dans
`/data/diagnostic-v8/tailscale`, distinctement de tout nœud existant.

Le nœud `ha-green-diagnostic-v8` expose HTTPS 443 sur le tailnet seulement. Autoriser
uniquement l’identité Codex voulue vers ce tag/port ; aucune route de sous-réseau,
SSH, sortie VPN, Funnel ou port hôte n’est demandé. Le serveur applicatif est
lié à 127.0.0.1 et exige aussi un Bearer dédié. Ne jamais partager un socket ou
un état Tailscale avec une autre application.

La configuration Home Assistant est montée **en lecture seule** à `/homeassistant`.
Les définitions exportées sont des projections JSON assainies : automatisations,
scripts, scènes, packages, blueprints et leurs inclusions YAML sélectionnées.
`configuration.yaml` sert uniquement à découvrir les inclusions automation/script/
scene/packages ; son contenu général n’est pas exporté. `secrets.yaml` est lu
localement pour supprimer les copies accidentelles de valeurs, jamais exporté ni
résolu à la place des références `!secret`. Pas d’export brut `.storage`, base,
journal ou sauvegarde. Les champs sensibles, URL, variables et longues chaînes
opaques sont masqués. Toute synchronisation Git exige encore une revue des textes
libres ; aucun filtre ne peut reconnaître toute valeur secrète arbitraire.

API GET authentifiée : `/v2/capabilities`, `/v2/entities`, `/v2/unavailable`,
`/v2/registry?kind=entities|devices|areas`, `/v2/definitions`, `/v2/code-links`,
`/v2/history?entity_id=...&start=...&end=...`,
`/v2/traces?domain=automation|script&item_id=...` puis `&run_id=...`.
Listes paginées `limit` (1–200), `offset`, `next_offset`. Déclarations paginées
liées par `revision` ; refaire l’export si la révision change. Historique limité à
24 h et 1000 points, selon Recorder ; cache 30 s, réponse 1 Mio, upstream 4 Mio,
30 requêtes/minute et deux connexions simultanées. Réduire la page si réponse 413.

Les traces et registres utilisent seulement les commandes de lecture Core nommées.
Un refus de permission ou une fonctionnalité absente retourne 503, jamais une
réponse fictive. Les étapes de traces exposent erreurs, horodatages et booléens de
conditions, pas les variables ou résultats de services. Aucun journal brut n’est
exporté. Les traces non conservées et les cibles de templates non résolues restent
explicitement inconnues. Les registres de dispositifs omettent identifiants réseau,
numéros de série et connexions.

Pour revenir à l’état antérieur, désactiver ou arrêter **cette seule application**,
puis révoquer son jeton client et son nœud Tailscale. Aucun fichier opérationnel
n’ayant été modifié, aucun restore de configuration n’est nécessaire.

Le transport embarqué est reconstruit depuis Tailscale stable 1.104.4 (archive
SHA-256 épinglée) avec `github.com/klauspost/compress` 1.20.2 pour corriger
GO-2026-6865. Ce binaire modifié est identifié `1.104.4-maison-compress-1.20.2`,
pas présenté comme un binaire officiel inchangé. Le compilateur Go est épinglé,
les sommes de modules sont vérifiées, les tests courts zstd/flate précèdent la
compilation. Le certificat proxy est monté temporairement en secret BuildKit,
jamais copié dans l’image finale. La licence Tailscale est incluse.
