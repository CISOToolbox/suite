# Tests navigateur — suite

Ce que ces tests regardent, et que rien d'autre ne voit : **ce qui se passe
entre le clic et l'écran**. Une exception JS qui casse la moitié d'un panneau
laisse le serveur répondre 200 ; ni les tests unitaires, ni la posture HTTP
(`tests/run-posture.sh`) ne peuvent la constater.

À ne pas confondre avec `standalone-modules/<m>/webapp/e2e/` : ces suites-là
servent elles-mêmes une application statique sans backend. Celle-ci vise la
stack suite derrière son proxy, avec une session.

## Lancer

```bash
bash mint-tokens.sh     # une session par module, dans tokens.json (gitignoré)
npx playwright test     # les 10 modules
npx playwright test --grep "risk —"
npx playwright test --headed        # pour regarder
```

La stack doit tourner. `mint-tokens.sh` échoue si aucun jeton n'a pu être
frappé, plutôt que d'écrire un fichier vide qui ferait passer la suite à vide.

## Comment la session est obtenue

Chaque module signe avec sa propre clé, d'où un jeton par module. Le compte est
**découvert** dans l'annuaire de Pilot, jamais codé en dur : un JWT valide ne
suffit pas — `_is_active_upstream` demande à Pilot si le compte est actif et
refuse tout email qu'il ne connaît pas. Un compte présent seulement dans la base
d'un module est donc inutilisable.

Pilot a son propre `src/auth.py`, dont `create_jwt` prend en plus la liste des
modules ; les neuf autres passent par `src/auth_common.py`.

## Ce que le parcours fait

Ouvre chaque module, puis **traverse chaque entrée de navigation**, en échouant
à la moindre erreur console, exception, requête en échec ou réponse ≥ 400 — au
chargement comme après chaque clic.

Trois choses apprises en l'écrivant, qui expliquent le code :

- **Les entrées sont identifiées par leurs `data-args`**, jamais par leur index
  ni par leur texte. L'index casse parce qu'un premier clic re-rend la
  navigation et la raccourcit (Surface) ; le texte casse parce qu'il contient du
  dynamique — « ANSSI Hygiène 38% 16 OK 26 KO » change entre deux rendus.
- **Le clic reprend une fois**, en re-résolvant le localisateur : sélectionner un
  panneau re-rend la navigation, donc le nœud trouvé n'est pas toujours celui
  qui reçoit le clic. Sans cela, un échec sur trois — et une suite navigateur
  instable finit ignorée, ce qui est pire que pas de suite.
- **Une réponse 404 ne déclenche pas `requestfailed`** : la requête a abouti,
  avec un mauvais statut. D'où l'écoute séparée de `response`.

## La liste d'exclusions

`IGNORED`, dans `console.spec.js`. Toute entrée doit dire **pourquoi** : une
liste non justifiée finit par tout contenir, et le test ne regarde plus rien.

Elle ne contient aujourd'hui que deux entrées, toutes deux propres à
l'environnement local : l'absence de favicon et le certificat auto-signé du
proxy.

## Sécurité de la campagne

Ces tests ouvrent des **sessions administrateur**. Trois propriétés les rendent
sûrs, et il faut les préserver :

**Aucun identifiant n'existe.** `mint-tokens.sh` emprunte la clé de signature à
l'intérieur du conteneur (`docker exec`). Il ne crée pas de compte, ne stocke
pas de mot de passe, n'appelle aucune route de connexion. Qui peut faire ce
`docker exec` contrôle déjà le processus et sa base : le mécanisme ne donne rien
de plus, et n'est pas exploitable à distance.

**Le compte est découvert, jamais codé en dur** — le premier administrateur de
l'annuaire Pilot. Un compte dédié appartient à une stack de CI avec son propre
annuaire, jamais à l'annuaire d'une production.

**Le refus est explicite.** La suite s'arrête si `E2E_PROXY` n'est pas local,
sauf `E2E_ALLOW_REMOTE=1`. Une CI mal configurée ne peut donc pas frapper des
sessions administrateur sur un environnement portant des données réelles.

`tokens.json` est en `600` et gitignoré. Il reste valide `JWT_EXPIRY_HOURS`
(24 h par défaut) : l'effacer après la campagne (`rm tokens.json`) est la bonne
habitude.

## Ce que la première exécution a trouvé

- `cisotoolbox.css` déclarait sept `@font-face` vers des fichiers qui
  n'existaient nulle part. Corrigé : les cinq faces utilisées sont désormais
  livrées depuis `private/shared/fonts/` (voir son README).
- Pilot chargeait l'avatar de l'utilisateur depuis le fournisseur d'identité
  dans le tableau des permissions. La CSP le bloquait, donc l'image ne s'est
  jamais affichée : il ne restait qu'une requête vers l'IdP depuis le navigateur
  de l'administrateur à chaque rendu. Corrigé — seules les images servies par la
  suite sont rendues.
