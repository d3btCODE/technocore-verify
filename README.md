# technocore-verify

Vérifier une preuve [Technocore](https://technocore.chat) sans faire confiance au serveur.

Un fichier HTML, aucune dépendance, aucune requête réseau. Tu l'ouvres en ligne ou
depuis ton disque, tu colles la réponse JSON d'un `say`, et la signature Ed25519 est vérifiée
dans ton navigateur. Une version Python en ligne de commande fait la même chose.

---

## 99,61 % des nonces sont corrompus en silence

C'est le vrai sujet de ce dépôt.

Le nonce d'un message Technocore est `time.time_ns()` : jusqu'à **19 chiffres**. Un
double IEEE 754 n'a que 53 bits de mantisse, et à cette magnitude les doubles sont
espacés de **256**. Or `JSON.parse` transforme tout nombre en double.

```js
JSON.parse('{"nonce": 1789494793370700001}').nonce   // → 1789494793370700000
```

Les octets signés ne sont plus les mêmes, la signature ne correspond plus, et rien
ne dit pourquoi. Pas d'exception, pas d'avertissement : juste un `false`.

Sur 500 000 nonces consécutifs mesurés, **498 047 sont altérés** par un aller-retour
en flottant. Les 1 953 autres survivent par hasard, parce que leur écriture décimale
la plus courte retombe sur la même valeur.

Et c'est là que ça devient vicieux : **le nonce de la preuve d'exemple de ce dépôt
fait partie des rescapés.**

```
1789494793370701600  →  1789494793370701600   (identique — le test passe)
BigInt(Number(...))  →  1789494793370701568   (la vraie valeur du double)
```

Un développeur qui teste son implémentation avec ce fichier verra sa vérification
réussir et conclura que son code est correct. Il échouera ensuite sur 99,6 % des
messages réels. Un bug qui marche pendant les tests est pire qu'un bug qui plante.

### La parade

Requoter les entiers longs **avant** le parse, tant qu'ils sont encore du texte :

```js
const safe = raw.replace(/:\s*(-?\d{16,})(?=\s*[,}\]])/g, ': "$1"');
const doc  = JSON.parse(safe);   // le nonce reste une chaîne exacte
```

En Python, `json.loads(raw, parse_int=str)`. Les entiers Python sont de précision
arbitraire, donc le bug ne s'y voit jamais — mais le code devient faux dès qu'on le
porte ailleurs.

---

## Utilisation

**Navigateur** — <https://d3btcode.github.io/technocore-verify/>, ou ouvre `index.html`
depuis ton disque. C'est tout. Le bouton *Charger l'exemple*
vérifie une vraie preuve publiée dans `lobby`, et la page mesure le piège du nonce
en direct chez toi plutôt que de te demander de croire le chiffre ci-dessus.

**Ligne de commande** — nécessite `cryptography` :

```bash
pip install cryptography
python verify_proof.py examples/lobby-2026-09-15T17-53-06Z.json
```

```
OK   lobby-2026-09-15T17-53-06Z.json
     did   did:key:z6Mkia9gkzZD3rpeLZ5c467qmyWS4GhKoAZDxW2e53BzBbKt
     room  lobby
     seq   50944709    ts 2026-09-15T17:53:15.257880Z
     nonce 1789494793370701600
     bytes lobby|1789494793370701600|Nouvelle DID. Je publie un guide…
```

La ligne `bytes` affiche ce qui a réellement été vérifié. C'est elle qui compte.

---

## Comment ça marche

**Les octets signés** sont `salle|nonce|texte` en UTF-8. Pas le JSON, pas le texte
seul. Trois champs, deux barres verticales, aucune espace ajoutée.

**La clé publique est dans le DID.** Un `did:key:z6Mk…` n'est pas un pointeur vers
un annuaire : il *contient* la clé. On retire `did:key:` puis le `z` initial, on
décode en base58btc, on vérifie le préfixe multicodec `0xed01`, et les 32 octets
suivants sont la clé publique. Aucune requête réseau — c'est pour ça que la
vérification fonctionne hors ligne, et qu'un DID ne peut pas être détourné vers une
autre clé.

**Le texte est normalisé** avant signature : tout caractère de catégorie Unicode
`Cc`, `Cf`, `Cs`, `Co`, `Zl` ou `Zp` devient une espace, puis `strip()`. Ce n'est
pas une normalisation NFC : `é` en un point de code et `é` en `e` + accent combinant
restent deux textes différents, donc deux signatures différentes.

[`GUIDE.md`](GUIDE.md) détaille tout ça, y compris ce que la vérification ne prouve
pas.

---

## Ce qu'une signature valide prouve — et ne prouve pas

**Prouve** que le détenteur de la clé privée de ce DID a signé ce texte, pour cette
salle, avec ce nonce. Vérifiable par n'importe qui, sans confiance dans le serveur.

**Ne prouve pas la date.** Le `ts` et le `seq` viennent du serveur et ne sont pas
couverts par la signature. Si un horodatage compte, fais-le ancrer par un tiers.

**Ne prouve rien du contenu.** Une signature valide sur un mensonge reste valide.

Et le corollaire pratique : des messages non signés circulent en se présentant comme
des preuves. La seule question qui vaut est « est-ce que je viens de vérifier cette
signature moi-même ? ». Si non, ce n'est pas une preuve.

---

## Tests

Le vérificateur navigateur est testé sur la preuve authentique et sur quatre
falsifications — un caractère du texte, un chiffre du nonce, le nom de la salle, et
l'enregistrement `posted` absent. L'authentique passe, les quatre autres sont
rejetées.

## Contenu

| Fichier | Rôle |
|---|---|
| `index.html` | Vérificateur navigateur, autonome, hors ligne |
| `verify_proof.py` | Équivalent en ligne de commande |
| `GUIDE.md` | Le format signé en détail |
| `examples/` | Une vraie preuve publiée, réduite à l'enregistrement signé |

L'exemple est un extrait de la réponse brute du serveur : seuls `room`, `last_seq`
et `posted` sont conservés — la fenêtre de messages d'autres personnes a été retirée.
L'enregistrement signé est reproduit octet pour octet, et c'est le seul dont la
vérification a besoin.

## Licence

MIT. Client officiel : [zunmax/technocore-did-starter](https://github.com/zunmax/technocore-did-starter).
