# 🏆 CTF Writeups — Fèmi KPONOU

![Challenges](https://img.shields.io/badge/Challenges-80%2B-brightgreen)
![CryptoHack](https://img.shields.io/badge/CryptoHack-Top%205%25%20mondial-gold)
![CTF ESAIP](https://img.shields.io/badge/CTF%20ESAIP%202025-Top%203%20Forensique-orange)
![Category](https://img.shields.io/badge/Catégorie-CTF%20·%20Compétitions-red)

> Writeups de mes solutions CTF sur Root-Me, HackTheBox, CryptoHack et TryHackMe.  
> Domaines couverts : Forensique · Cryptographie · Sécurité réseau · Web

## 📊 Statistiques

| Plateforme | Challenges résolus | Rang | Spécialité |
|------------|-------------------|------|------------|
| **CryptoHack** | 45+ | Top 5% mondial | Cryptographie |
| **Root-Me** | 20+ | — | Forensique, Réseau |
| **TryHackMe** | 10+ | — | Blue Team, SOC |
| **HackTheBox** | 5+ | — | Pentesting |
| **CTF ESAIP 2025** | — | 🥉 Top 3 piste forensique | Forensique |

## 📁 Organisation

```
ctf-writeups/
├── cryptography/
│   ├── cryptohack/
│   │   ├── rsa-challenges.md
│   │   ├── ecc-challenges.md
│   │   └── padding-oracle.md
│   └── root-me/
│       └── crypto-writeups.md
├── forensics/
│   ├── rootme/
│   │   ├── pcap-analysis.md
│   │   └── memory-forensics.md
│   └── ctf-esaip-2025/
│       └── top3-writeup.md
├── network/
│   └── rootme/
│       └── network-challenges.md
├── web/
│   └── tryhackme/
│       └── web-challenges.md
└── README.md
```

## 🔐 Cryptographie

### CryptoHack — RSA Challenges

#### Challenge : RSA Starter (débutant)
**Plateforme** : CryptoHack | **Points** : 10 | **Difficulté** : Facile

**Contexte** : Déchiffrer un message RSA avec de petits paramètres.

**Approche** :
```python
from Crypto.Util.number import long_to_bytes

# Paramètres donnés
n = 3233  # n = p*q = 61 * 53
e = 17
c = 2790  # chiffré

# Factorisation triviale (petit n)
p, q = 61, 53
phi = (p-1) * (q-1)  # phi(n) = 60 * 52 = 3120

# Calcul clé privée d = e^-1 mod phi(n)
d = pow(e, -1, phi)  # d = 2753

# Déchiffrement
m = pow(c, d, n)
print(long_to_bytes(m))  # flag
```

---

#### Challenge : Modular Arithmetic — Chinese Remainder Theorem
**Plateforme** : CryptoHack | **Points** : 15 | **Difficulté** : Moyen

**Concept** : Appliquer le Théorème Chinois des Restes (CRT) pour résoudre un système de congruences.

```python
from sympy.ntheory.modular import crt

# Système de congruences : x ≡ ri (mod ni)
remainders = [2, 3, 2]
moduli = [3, 5, 7]

# CRT : trouver x unique mod (3*5*7 = 105)
M, x = crt(moduli, remainders)
print(f"x = {x} mod {M}")  # x = 23 mod 105
```

---

#### Challenge : Padding Oracle Attack
**Plateforme** : CryptoHack | **Points** : 40 | **Difficulté** : Difficile

**Concept** : Exploiter une oracle de padding CBC pour déchiffrer sans la clé.

**Principe** :
- Le serveur révèle si le padding PKCS#7 est valide
- On peut déchiffrer bloc par bloc en manipulant le vecteur IV
- Complexité : 256 requêtes maximum par byte

```python
def padding_oracle_attack(ciphertext, iv, oracle):
    """
    Attaque oracle de padding sur AES-CBC.
    oracle(ct) -> True si padding valide, False sinon
    """
    block_size = 16
    plaintext = b""
    
    blocks = [iv] + [ciphertext[i:i+block_size] 
                     for i in range(0, len(ciphertext), block_size)]
    
    for block_idx in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        
        for byte_pos in range(block_size - 1, -1, -1):
            padding_byte = block_size - byte_pos
            
            for guess in range(256):
                modified_prev = bytearray(blocks[block_idx - 1])
                
                # Fixer les bytes déjà trouvés
                for k in range(byte_pos + 1, block_size):
                    modified_prev[k] = decrypted_block[k] ^ padding_byte
                
                modified_prev[byte_pos] = guess
                
                if oracle(bytes(modified_prev) + blocks[block_idx]):
                    # Trouver le byte intermédiaire
                    intermediate = guess ^ padding_byte
                    # Trouver le plaintext
                    decrypted_block[byte_pos] = (
                        intermediate ^ blocks[block_idx - 1][byte_pos]
                    )
                    break
        
        plaintext += bytes(decrypted_block)
    
    # Supprimer padding PKCS#7
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]
```

---

## 🔍 Forensique

### CTF ESAIP 2025 — Top 3 Piste Forensique

#### Challenge : Lost in Memory (Volatility)
**Événement** : CTF ESAIP 2025 | **Points** : 300 | **Difficulté** : Difficile  
**Résultat** : 🥉 3ème équipe à résoudre ce challenge

**Contexte** : Une image mémoire dun poste Windows infecté est fournie. Retrouver les credentials exfiltrés.

**Solution** :
```bash
# 1. Identifier le profil
python3 vol.py -f challenge.mem windows.info

# 2. Lister les processus suspects
python3 vol.py -f challenge.mem windows.pslist | grep -v "System\|svchost\|explorer"
# Résultat suspect : stealer.exe (PID 4892)

# 3. Dump du processus malveillant
python3 vol.py -f challenge.mem windows.dumpfiles --pid 4892

# 4. Strings sur le dump
strings -n 8 pid.4892.dmp | grep -E "password|NTLM|flag"

# 5. Analyse réseau — connexions actives
python3 vol.py -f challenge.mem windows.netstat
# Connexion sortante vers 185.220.x.x:4444

# Flag trouvé dans les credentials en mémoire
# FLAG{m3m0ry_f0r3ns1cs_m4st3r_2025}
```

---

#### Challenge : PCAP Mystery (Wireshark)
**Plateforme** : Root-Me | **Points** : 25 | **Difficulté** : Moyen

**Contexte** : Analyser un fichier PCAP pour retrouver des données exfiltrées via DNS tunneling.

**Solution** :
```bash
# Filtrer les requêtes DNS suspectes (longues)
tshark -r challenge.pcap -Y "dns.qry.name.len > 50" \
  -T fields -e dns.qry.name

# Extraire les sous-domaines (données encodées en base64)
tshark -r challenge.pcap -Y "dns.qry.type == 1" \
  -T fields -e dns.qry.name \
  | awk -F. "{print \$1}" \
  | sort -u

# Décoder base64 des fragments
echo "ZmxhZ3tkbnNfdHVubmVsaW5nX2RldGVjdGVkfQ==" | base64 -d
# FLAG{dns_tunneling_detected}
```

---

## 🌐 Sécurité Réseau

### Root-Me — Analyse PCAP Avancée

#### Challenge : Exfiltration HTTP
**Plateforme** : Root-Me | **Points** : 30 | **Difficulté** : Moyen

```bash
# Extraire tous les fichiers transférés via HTTP
tcpflow -r challenge.pcap

# Ou avec Wireshark : File > Export Objects > HTTP

# Chercher données sensibles dans les requêtes POST
tshark -r challenge.pcap -Y "http.request.method == POST" \
  -T fields -e http.file_data
```

---

## 📚 Ressources recommandées

### Pour débuter en CTF
- [PicoCTF](https://picoctf.org/) — Parfait pour débutants
- [CryptoHack](https://cryptohack.org/) — Cryptographie interactive
- [TryHackMe](https://tryhackme.com/) — Parcours guidés

### Outils indispensables
```bash
# Crypto
sage, pycryptodome, gmpy2, z3-solver

# Forensique
volatility3, autopsy, binwalk, foremost

# Réseau
wireshark, tshark, tcpflow, NetworkMiner

# Stéganographie
steghide, zsteg, stegsolve
```

### Références
- [CTF Field Guide](https://trailofbits.github.io/ctf/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CryptoPals Challenges](https://cryptopals.com/)

---

## 👤 Auteur

**Fèmi KPONOU** — Étudiant Bachelor Cybersécurité ESAIP  
🌐 [Portfolio](https://primaelkpfv.github.io) · 💼 [LinkedIn](https://linkedin.com/in/primaelkponou)

> *"The best way to learn security is to break things — ethically."*
