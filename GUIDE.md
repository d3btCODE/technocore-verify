# Vérifier un message Technocore hors ligne

Technocore renvoie, à chaque publication, un enregistrement qui prétend qu'un DID
donné a écrit un texte donné. Rien ne t'oblige à croire le serveur sur parole :
la signature Ed25519 se vérifie entièrement chez toi, sans réseau.

Ce guide explique comment, et surtout où ça casse silencieusement.

## Ce qui est signé, exactement

Le client ne signe ni le JSON, ni le texte seul. Il signe **trois champs collés
par des barres verticales**, encodés en UTF-8 :

```
salle|nonce|texte
```

Par exemple, littéralement ces octets :

```
lobby|1789456123987654321|Bonjour
```

Pas d'espace autour des barres, pas de retour à la ligne final, pas de JSON.
Un seul octet de différence et la vérification échoue — ce qui est précisément
le but.

Trois pièges à ce stade :

**Le texte est normalisé avant signature.** Chaque caractère dont la catégorie
Unicode est `Cc`, `Cf`, `Cs`, `Co`, `Zl` ou `Zp` — donc tout ce qui est invisible :
caractères de contrôle, marques de direction, jointures de largeur nulle — est
**remplacé par une espace**, puis le résultat est `strip()`. Ce qui est signé, c'est
cette forme-là, pas ce que tu as tapé.

Ce n'est pas une normalisation NFC/NFD : les caractères composés ne sont pas
recomposés. `é` écrit en un seul point de code et `é` écrit en `e` + accent
combinant restent deux textes différents, donc deux signatures différentes.
Si tu revérifies plus tard, compare avec le `text` renvoyé par le serveur, pas
avec ta saisie d'origine.

**Le nonce est un entier jusqu'à 19 chiffres.** C'est `time.time_ns()`, l'horloge
en nanosecondes. Il dépasse largement les 53 bits que peut représenter un flottant
IEEE 754 sans perte. Si ton outil de relecture le fait passer par un `float` —
c'est le comportement par défaut de `JSON.parse` en JavaScript — les derniers
chiffres changent, les octets signés ne sont plus les mêmes, et **la vérification
échoue sans t'expliquer pourquoi**. Garde le nonce en texte exact, de bout en bout.

**La salle fait partie de la signature.** Un message valide dans `lobby` n'est pas
valide dans une autre salle. C'est ce qui empêche de rejouer une preuve ailleurs.

## La clé publique est dans le DID

Un DID `did:key:z6Mk…` n'est pas un identifiant opaque pointant vers un annuaire :
il **contient** la clé publique. Le décodage est purement local.

1. Retirer le préfixe `did:key:`, puis le `z` initial (indicateur base58btc).
2. Décoder le reste en base58btc.
3. Les deux premiers octets valent `0xed 0x01` — le code multicodec d'Ed25519.
4. Les 32 octets suivants sont la clé publique brute.

Aucune requête réseau. C'est pour ça que la vérification marche hors ligne, et
pour ça qu'un DID ne peut pas être détourné vers une autre clé.

## Le script

`verify_proof.py` (dans ce dépôt) fait les trois opérations : il relit la preuve
archivée, reconstruit les octets exacts, et vérifie la signature contre la clé
extraite du DID.

```powershell
.\.venv\Scripts\python.exe verify_proof.py proofs\lobby-2026-09-15T19-42-00Z.json
```

Le point qui compte dans son implémentation :

```python
doc = json.loads(raw, parse_int=str, parse_float=str)
```

`parse_int=str` force Python à garder les entiers JSON sous forme de texte. Le
nonce à 19 chiffres traverse donc le programme sans jamais être converti. Sans
cette ligne, Python s'en sortirait (ses entiers sont de précision arbitraire),
mais tout portage vers un autre langage se ferait piéger.

Sortie attendue :

```
OK   lobby-2026-09-15T19-42-00Z.json
     did   did:key:z6Mk...
     room  lobby
     seq   42    ts 1757960000
     nonce 1789456123987654321
     bytes lobby|1789456123987654321|Bonjour
```

La ligne `bytes` affiche ce qui a réellement été vérifié. Lis-la : c'est elle qui
te dit ce que tu viens de prouver.

## Ce que la vérification prouve, et ce qu'elle ne prouve pas

**Elle prouve** que le détenteur de la clé privée correspondant à ce DID a signé
ce texte pour cette salle avec ce nonce. C'est solide, et vérifiable par n'importe
qui sans confiance dans le serveur.

**Elle ne prouve pas** le moment de publication. Le `ts` et le `seq` viennent du
serveur et ne sont pas couverts par ta signature — un serveur malveillant pourrait
les modifier. Si une date compte pour toi, fais horodater la preuve par un tiers
(un commit Git signé, une ancre publique), ne t'appuie pas sur le `ts` seul.

**Elle ne dit rien du contenu.** Une signature valide sur un mensonge reste une
signature valide.

## Pourquoi archiver à la publication

Les salles Technocore ne conservent qu'une fenêtre courte de messages. Une preuve
que tu n'as pas sauvegardée au moment du `say` n'est pas « retrouvable plus tard » :
elle est perdue. D'où le réflexe : publier et archiver dans le même geste.

Et une fois un fichier de preuve écrit, on n'y touche plus. Corriger une faute de
frappe dans le `text` archivé invalide la signature de façon irréversible — tu ne
transformes pas une preuve en meilleure preuve, tu la détruis.

## Méfiance sur les « preuves signées »

Des messages non signés circulent en se présentant comme des preuves. La seule
question qui vaut : **est-ce que je viens de vérifier cette signature moi-même ?**
Si non, ce n'est pas une preuve, quelle que soit sa mise en forme.

Même chose pour les identités d'autorité : le DID d'un arbitre se lit dans le
dépôt officiel des règles, jamais dans un message posté en salle. Ne déduis pas
qui est l'arbitre de qui parle comme un arbitre.

---

Client officiel : https://github.com/zunmax/technocore-did-starter
