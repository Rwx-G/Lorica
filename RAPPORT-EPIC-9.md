# Epic 9 - rapport de session

**Auteur :** Romain G.
**Date :** 2026-09-09
**Branche :** `feat/v1.7.0`

## Où en est l'epic

| Story | Avant | Après | Reste |
|---|---|---|---|
| 9.5 Certificats control-plane | Review | **Done** | rien |
| 9.6 Fan-in télémétrie | Draft | **Review** | profil e2e, plafond mesuré |
| 9.7 Dashboard flotte | Draft | **InProgress** | toute la surface Svelte |
| 9.9 Audit flotte | Draft | Draft | tout |

L'epic **n'est pas terminée**. Je n'ai pas tenu le rythme espéré : 9.6 s'est
révélée beaucoup plus grosse que sa fiche ne le laissait croire, et l'audit y a
trouvé deux Critical qui méritaient d'être corrigés proprement plutôt que
d'enchaîner.

## Ce qui a été livré

23 commits, tous avec les trois gates clippy et la suite complète au vert.

### Story 9.5 - remédiation et clôture

Deux sujets litigieux arbitrés en dépêchant deux agents chacun (un sur les
pratiques publiées, un sur le code), comme demandé.

**D15 - le nom de nœud EST une entrée d'autorisation.** La revue Phase 1 et un
commentaire dans `roster.rs` affirmaient le contraire. C'était faux : un
`node_selector` de route liste des noms, et cette liste décide quelles clés
privées un nœud reçoit. L'agent web a montré que le nom auto-déclaré est une
classe de faiblesse documentée (Kubernetes, Consul, SPIFFE convergent vers une
identité assignée par le serveur ou liée au credential). L'agent code a établi
que `bound_node_name` existait déjà mais était **optionnel** : la protection
était disponible et non appliquée. Corrigé : nom obligatoire au mint, échec
fermé à la redemption sur un token sans binding, alphabet aligné sur celui des
sélecteurs, et la revue d'un nœud en attente montre désormais pour quels
hostnames ce nom est déjà sélectionné.

**D16 - un nœud hors ligne ne veto plus une commande ACME.** Le verdict était
tout-ou-rien : un seul follower éteint bloquait le renouvellement de **tous**
les certificats sur une route fleet-wide, avec un retry toutes les 12h
seulement. La distinction qui tranche : un nœud sans session cluster ne répond
pas non plus sur le port 80, donc refuser d'essayer n'évite aucun échec et en
provoque un vrai. Un nœud vivant qui refuse, lui, répondra 404 et doit toujours
bloquer. `ChallengeMiss::{Offline, Refused}` remplace la chaîne de caractères.

### Story 9.6 - fan-in télémétrie

Protocole sur les tags 40-41 réservés depuis 9.2, base de fan-in séparée,
quota d'ingestion par nœud, drain, endpoints de lecture, bans fleet-wide,
documentation.

La décision structurante (D5) : **le store de logs partagé EST déjà le ring
buffer** demandé par l'AC #5. Il est écrit hors du chemin de requête, borné par
la rétention, partagé entre workers sous WAL, et compte déjà ses pertes. Une
seconde file devant lui aurait dupliqué une borne existante sans résoudre le
mode worker. Le chemin de requête n'est donc pas touché du tout.

Une décision de sécurité vaut d'être notée : **aucun message ne porte
d'identité de nœud.** Le control plane estampille avec le `node_id` que la
session mTLS prouve. C'est la leçon de D15 appliquée avant l'erreur.

## Les deux Critical trouvés par l'audit

Quatre auditeurs en parallèle (sécurité, qualité, architecture, performance).
Les deux Critical relèvent de la même faute : **une règle correcte ailleurs,
recopiée là où sa prémisse ne tient plus.**

**1. La rétention par nœud élaguait des nœuds qui étaient dans leur quota.**

J'avais repris l'estimation `MAX(id) - MIN(id) + 1` de `log_store.rs`. Elle est
juste là-bas, sur une table à un seul écrivain où les trous ne viennent que des
suppressions passées. Sur la table de fan-in, `id` est **un seul autoincrement
partagé par tous les nœuds** : l'écart d'un nœud est gonflé par toutes les
lignes intercalées des autres, donc surestimé d'environ la taille de la flotte.
Le quota croyait un nœud calme largement au-dessus de son budget et l'élaguait
en dessous de son allocation. C'est exactement le « un edge bruyant évince les
lignes d'un edge calme » que l'AC #3 existe pour empêcher, réintroduit par le
mécanisme censé l'empêcher, et actif dans la seule condition qui compte : une
flotte à plus d'un nœud.

Mon test ne l'a pas vu parce qu'il écrivait les 300 lignes du nœud bruyant
**avant** celle du nœud calme : les ids ne s'intercalaient jamais et
l'estimation tombait juste par accident. Il y a maintenant un test qui
intercale trois nœuds.

**2. Le drain ne pouvait pas atteindre le plafond que sa propre doc annonçait.**

512 lignes par tick de 10 s = 51 lignes/s, contre « quelques centaines de rps
par nœud » que j'avais écrit dans `docs/cluster.md`. Au-delà, le retard
croissait sans borne jusqu'à ce que la rétention locale supprime des lignes que
le curseur n'avait pas atteintes : perte silencieuse et **définitive**, pas un
simple retard. J'avais écrit le plafond et la cadence dans deux commits
séparés sans jamais les multiplier. L'arithmétique qui l'expose tient en une
ligne.

Huit autres corrections, dont : les bans contournaient entièrement le quota
d'ingestion ; le watermark de stockage supprimait les bans en silence alors
qu'un commentaire trois lignes plus bas affirmait qu'ils ne le sont jamais ; le
drain appelait SQLite en synchrone sur l'exécuteur async, précisément la
discipline que D5-D7 passent trois décisions à établir.

## Ce que je dois vous signaler

**1. `metrics_require_auth` n'est toujours pas basculé.** Le PRD v1.7.0 l'exige
et `settings.rs` documente « flips to `true` in v1.7.0 », mais le défaut est
toujours `false` et rien dans 9.1-9.5 ni 9.8 ne l'a planifié. Ce n'est l'AC
d'aucune story. Enregistré en D10 pour la clôture d'epic avec la note de
release. **À ne pas oublier avant le bump de version.**

**2. Le profil e2e `cluster` n'a jamais existé** (backlog #66). Les quinze
profils de `run.sh` n'en contiennent pas. L'Integration Verification de 9.2 à
9.6 n'a donc **jamais tourné** : 9.5 dit explicitement « ships on unit tests
only ». C'est de la dette héritée, pas créée cette nuit, mais elle est
maintenant visible et chiffrée. Le construire une fois couvre cinq stories.

**3. Le plafond de fan-in est dérivé, pas mesuré** (backlog #64). La doc le dit
en toutes lettres plutôt que d'afficher un chiffre qui aurait l'air mesuré.

**4. Deux gates ne passent pas, pour des raisons préexistantes** (backlog #63,
#65) : `cargo fmt --check` échoue sur `ai_bot.rs`, et
`cargo clippy -p lorica-api --all-targets` échoue sur du code de test de 9.8.
Aucune des deux n'est de mon fait ; je ne les ai pas repliées dans un commit
d'Epic 9 pour ne pas mélanger.

## Un motif qui se répète

C'est la deuxième story d'affilée où l'audit trouve des **commentaires qui
affirment une sécurité que le code n'a pas**. En 9.5 il y en avait cinq. En 9.6,
trois de plus : « les bans ne sont jamais élagués par le quota » (ils le
sont), la justification de l'estimation MIN/MAX recopiée dans un contexte où
elle est fausse, et la discipline anti-blocage énoncée dans un module qui la
violait.

Le point commun : la phrase était vraie quand elle a été écrite, ou vraie
ailleurs. Elle n'a pas été revérifiée sur place. C'est le défaut le plus
coûteux de cet epic parce qu'il survit à la relecture — un commentaire qui
affirme une garantie est lu comme une garantie.

## Prochaines étapes

1. Finir 9.7 : la surface Svelte (page Cluster, dialogue de token, tiroir de
   nœud, filtres, badge, bannières). La fondation testée est en place.
2. Story 9.9 (audit flotte), qui a une contrainte forte : le fan-in ne doit
   **jamais** passer par `insert_audit`, sous peine de corrompre la chaîne du
   control plane.
3. Basculer `metrics_require_auth` + note de release.
4. Construire le profil e2e `cluster`.
5. Audit complet d'epic, puis bump de version.

Rien n'est en cours d'exécution, tout est commité sur `feat/v1.7.0`, rien n'a
été poussé.
