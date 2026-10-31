# -*- coding: utf-8 -*-
"""
TP Réseaux - Analyse de trafic avec Scapy
Mini-projet : outil complet d'analyse d'une capture réseau (tp02.pcap)

Utilisation :
    python analyseur.py               -> analyse tp02.pcap
    python analyseur.py autre.pcap    -> analyse un autre fichier

Le programme :
    1. charge la capture (en gérant fichier absent / illisible / vide),
    2. affiche une fiche détaillée pour CHAQUE paquet,
    3. calcule les statistiques globales,
    4. recherche des anomalies (retransmissions, chevauchements, scans...),
    5. écrit tout dans le terminal ET dans le fichier rapport.txt.
"""

import sys
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import rdpcap, Ether, ARP, IP, IPv6, ICMP, TCP, UDP, DNS
from scapy.error import Scapy_Exception


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

FICHIER_PAR_DEFAUT = "tp02.pcap"
FICHIER_RAPPORT = "rapport.txt"
SEUIL_PORTS = 10      # même seuil que dans la partie 9 du TP
TOP = 10              # nombre d'éléments affichés dans les classements

PROTOCOLES_IP = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

TYPES_DNS = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}

TYPES_ICMP = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
              8: "Echo Request", 11: "Time Exceeded"}

# Premier octet d'un enregistrement TLS
TYPES_TLS = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake",
             23: "Application Data"}

VERSIONS_TLS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                0x0303: "TLS 1.2 (ou 1.3)"}

# 6e octet d'un enregistrement Handshake
TYPES_HANDSHAKE = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
                   11: "Certificate", 12: "ServerKeyExchange",
                   14: "ServerHelloDone", 16: "ClientKeyExchange"}

METHODES_HTTP = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                 b"OPTIONS ", b"PATCH ")

SERVICES = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
            123: "NTP", 137: "NetBIOS", 143: "IMAP", 443: "HTTPS/TLS",
            445: "SMB", 1900: "SSDP", 3389: "RDP", 5353: "mDNS"}


# ---------------------------------------------------------------------------
# Écriture dans le terminal et dans le rapport
# ---------------------------------------------------------------------------

sortie = None   # fichier rapport.txt, ouvert dans main()


def ecrire(texte=""):
    """Affiche une ligne dans le terminal ET l'enregistre dans le rapport."""
    print(texte)
    if sortie is not None:
        sortie.write(texte + "\n")


def titre(texte):
    """Affiche un titre de section."""
    ecrire()
    ecrire("=" * 70)
    ecrire(texte)
    ecrire("=" * 70)


# ---------------------------------------------------------------------------
# Petites fonctions utilitaires
# ---------------------------------------------------------------------------

def en_texte(valeur):
    """Convertit des octets en texte (comme dans la partie 5.1 du TP)."""
    if isinstance(valeur, bytes):
        return valeur.decode("utf-8", errors="replace")
    return str(valeur)


def nom_service(port):
    """Renvoie '443 (HTTPS/TLS)' par exemple."""
    if port in SERVICES:
        return f"{port} ({SERVICES[port]})"
    return str(port)


def date_lisible(temps):
    """Convertit un horodatage (secondes) en date lisible."""
    return datetime.fromtimestamp(temps).strftime("%Y-%m-%d %H:%M:%S.%f")


def adresses_ip(paquet):
    """Renvoie (source, destination) en IPv4 ou IPv6, ou (None, None)."""
    if IP in paquet:
        return paquet[IP].src, paquet[IP].dst
    if IPv6 in paquet:
        return paquet[IPv6].src, paquet[IPv6].dst
    return None, None


def liste_couches(paquet):
    """Renvoie le nom de toutes les couches du paquet (Ether, IP, TCP, Raw...)."""
    return [couche.__name__ for couche in paquet.layers()]


def liste_enregistrements(champ):
    """
    Renvoie les questions ou réponses DNS sous forme de liste.
    Depuis Scapy 2.6, dns.qd et dns.an sont des listes. Dans les anciennes
    versions, les enregistrements sont chaînés par .payload (code de la 5.1).
    """
    if champ is None:
        return []
    if isinstance(champ, list):
        return champ
    resultat = []
    while hasattr(champ, "qname") or hasattr(champ, "rrname"):
        resultat.append(champ)
        champ = champ.payload
    return resultat


def protocole_principal(paquet):
    """Protocole de plus haut niveau, utilisé pour les statistiques de taille."""
    if DNS in paquet:
        return "DNS"
    if TCP in paquet:
        tcp = paquet[TCP]
        if 80 in (tcp.sport, tcp.dport):
            return "HTTP (TCP 80)"
        if 443 in (tcp.sport, tcp.dport):
            return "TLS (TCP 443)"
        return "TCP autre"
    if UDP in paquet:
        return "UDP autre"
    if ICMP in paquet:
        return "ICMP"
    if IPv6 in paquet and paquet[IPv6].nh == 58:
        return "ICMPv6"
    if ARP in paquet:
        return "ARP"
    if IP in paquet:
        return "IPv4 autre"
    if IPv6 in paquet:
        return "IPv6 autre"
    return "Autre"


def classe_taille(taille):
    """Classes de taille de la partie 8.2 du TP."""
    if taille < 100:
        return "Moins de 100 octets"
    elif taille < 500:
        return "100 a 499 octets"
    elif taille < 1000:
        return "500 a 999 octets"
    else:
        return "1000 octets et plus"


# ---------------------------------------------------------------------------
# 1. Chargement de la capture
# ---------------------------------------------------------------------------

def charger_capture(fichier):
    """Charge le fichier pcap. Renvoie la liste des paquets ou None si erreur."""
    try:
        paquets = rdpcap(fichier)
    except FileNotFoundError:
        print(f"Erreur : le fichier '{fichier}' est introuvable.")
        return None
    except Scapy_Exception as erreur:
        print(f"Erreur : le fichier '{fichier}' n'est pas une capture lisible ({erreur}).")
        return None
    except Exception as erreur:
        print(f"Erreur inattendue en lisant '{fichier}' : {erreur}")
        return None

    if len(paquets) == 0:
        print(f"La capture '{fichier}' ne contient aucun paquet.")
        return None

    return paquets


def nouvelles_statistiques():
    """Crée le dictionnaire qui contient toutes les statistiques."""
    return {
        "couches": Counter(),          # ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS
        "toutes_couches": Counter(),   # toutes les couches reconnues par Scapy
        "ip_sources": Counter(),
        "ip_destinations": Counter(),
        "mac_sources": Counter(),
        "mac_destinations": Counter(),
        "ports_tcp": Counter(),
        "ports_udp": Counter(),
        "flux": Counter(),
        "conversations": Counter(),
        "tailles": [],
        "classes": Counter(),
        "tailles_par_protocole": defaultdict(list),
        "dns_requetes": 0,
        "dns_reponses": 0,
        "dns_noms": Counter(),
        "dns_resultats": [],
        "http": [],
        "tls": Counter(),
        "tls_octets": 0,
    }


# ---------------------------------------------------------------------------
# 2. Analyse détaillée d'un paquet
# ---------------------------------------------------------------------------

def compter_couches(paquet, stats):
    """Code de la partie 4.1 du TP + comptage de toutes les autres couches."""
    for nom, couche in [
        ("ARP", ARP),
        ("IPv4", IP),
        ("IPv6", IPv6),
        ("ICMP", ICMP),
        ("TCP", TCP),
        ("UDP", UDP),
        ("DNS", DNS),
    ]:
        if couche in paquet:
            stats["couches"][nom] += 1

    for nom in liste_couches(paquet):
        stats["toutes_couches"][nom] += 1


def afficher_ethernet(paquet, stats):
    """Adresses MAC (partie 4.3 du TP)."""
    if Ether in paquet:
        eth = paquet[Ether]
        ecrire(f"Ethernet     : {eth.src} -> {eth.dst}")
        stats["mac_sources"][eth.src] += 1
        stats["mac_destinations"][eth.dst] += 1
    else:
        ecrire("Ethernet     : pas de couche Ethernet dans ce paquet")


def afficher_arp(paquet):
    """Requête ou réponse ARP."""
    arp = paquet[ARP]
    if arp.op == 1:
        ecrire(f"ARP          : Requête - qui a {arp.pdst} ? "
               f"Répondre à {arp.psrc} ({arp.hwsrc})")
    elif arp.op == 2:
        ecrire(f"ARP          : Réponse - {arp.psrc} est à l'adresse {arp.hwsrc}")
    else:
        ecrire(f"ARP          : opération {arp.op}")


def afficher_ip(paquet, stats):
    """Adresses IPv4 (partie 4.2 du TP) ou IPv6."""
    if IP in paquet:
        ip = paquet[IP]
        nom_proto = PROTOCOLES_IP.get(ip.proto, "autre")
        ecrire(f"IPv4         : {ip.src} -> {ip.dst} | TTL={ip.ttl} | "
               f"Protocole={ip.proto} ({nom_proto})")
        stats["ip_sources"][ip.src] += 1
        stats["ip_destinations"][ip.dst] += 1

    if IPv6 in paquet:
        ip6 = paquet[IPv6]
        nom_proto = PROTOCOLES_IP.get(ip6.nh, "autre")
        ecrire(f"IPv6         : {ip6.src} -> {ip6.dst} | Hop limit={ip6.hlim} | "
               f"En-tête suivant={ip6.nh} ({nom_proto})")
        stats["ip_sources"][ip6.src] += 1
        stats["ip_destinations"][ip6.dst] += 1


def afficher_icmp(paquet):
    """Type et code ICMP."""
    icmp = paquet[ICMP]
    nom = TYPES_ICMP.get(icmp.type, "autre")
    ecrire(f"ICMP         : type {icmp.type} ({nom}) | code {icmp.code}")


def afficher_tcp(paquet, stats):
    """Ports, flags, Seq et Ack (partie 5.3 du TP) + flux et conversations."""
    tcp = paquet[TCP]
    flags = tcp.sprintf("%TCP.flags%")
    taille_donnees = len(bytes(tcp.payload))

    ecrire(f"TCP          : port {nom_service(tcp.sport)} -> port {nom_service(tcp.dport)}")
    ecrire(f"               Flags={flags} | Seq={tcp.seq} | Ack={tcp.ack} | "
           f"Fenêtre={tcp.window} | Données={taille_donnees} octets")

    stats["ports_tcp"][tcp.dport] += 1

    source, destination = adresses_ip(paquet)
    if source is not None:
        # Flux directionnel (partie 7.1)
        cle = (source, tcp.sport, destination, tcp.dport)
        stats["flux"][cle] += 1

        # Conversation dans les deux sens (partie 7.2)
        extremite1 = (source, tcp.sport)
        extremite2 = (destination, tcp.dport)
        stats["conversations"][tuple(sorted((extremite1, extremite2)))] += 1


def afficher_udp(paquet, stats):
    """Ports UDP (partie 5.2 du TP)."""
    udp = paquet[UDP]
    taille_donnees = len(bytes(udp.payload))
    ecrire(f"UDP          : port {nom_service(udp.sport)} -> port {nom_service(udp.dport)} | "
           f"Longueur={udp.len} | Données={taille_donnees} octets")
    stats["ports_udp"][udp.dport] += 1


def afficher_dns(paquet, stats):
    """Requête ou réponse DNS (partie 5.1 du TP), avec les réponses en plus."""
    dns = paquet[DNS]
    nature = "Requête" if dns.qr == 0 else "Réponse"
    ecrire(f"DNS          : {nature} (id={dns.id}) | questions={dns.qdcount} | "
           f"réponses={dns.ancount}")

    if dns.qr == 0:
        stats["dns_requetes"] += 1
    else:
        stats["dns_reponses"] += 1

    for question in liste_enregistrements(dns.qd):
        nom = en_texte(question.qname)
        type_dns = TYPES_DNS.get(question.qtype, str(question.qtype))
        ecrire(f"  Nom demandé : {nom} (type {type_dns})")
        if dns.qr == 0:
            stats["dns_noms"][nom] += 1

    if dns.qr == 1:
        if dns.rcode == 3:
            ecrire("  Résultat    : NXDOMAIN (le nom n'existe pas)")
        elif dns.rcode != 0:
            ecrire(f"  Résultat    : erreur (rcode={dns.rcode})")

        for reponse in liste_enregistrements(dns.an):
            nom = en_texte(reponse.rrname)
            type_dns = TYPES_DNS.get(reponse.type, str(reponse.type))
            valeur = en_texte(getattr(reponse, "rdata", "?"))
            ecrire(f"  Réponse     : {nom} -> {valeur} (type {type_dns}, TTL={reponse.ttl}s)")
            stats["dns_resultats"].append(f"{nom} -> {valeur} ({type_dns})")


def afficher_http(numero, paquet, stats):
    """Données HTTP lisibles (partie 5.4 du TP)."""
    donnees = bytes(paquet[TCP].payload)

    if not donnees:
        ecrire("HTTP         : port 80, mais pas de données (segment de contrôle TCP)")
        return

    ecrire(f"HTTP         : {len(donnees)} octets de données en clair")
    ecrire(f"  Aperçu      : {repr(donnees[:200])}")

    premiere_ligne = en_texte(donnees.split(b"\r\n")[0])

    if donnees.startswith(METHODES_HTTP):
        hote = "?"
        for ligne in donnees.split(b"\r\n"):
            if ligne.lower().startswith(b"host:"):
                hote = en_texte(ligne[5:]).strip()
        ecrire(f"  Requête     : {premiere_ligne}")
        ecrire(f"  Hôte        : {hote}")
        stats["http"].append(f"Paquet {numero} : requête {premiere_ligne} (Host: {hote})")
    elif donnees.startswith(b"HTTP/"):
        ecrire(f"  Réponse     : {premiere_ligne}")
        stats["http"].append(f"Paquet {numero} : réponse {premiere_ligne}")
    else:
        ecrire("  Contenu     : suite de données HTTP (corps d'une page, fichier...)")


def afficher_tls(paquet, stats):
    """Données TLS (partie 5.5 du TP) + lecture de l'en-tête TLS (non chiffré)."""
    donnees = bytes(paquet[TCP].payload)

    if not donnees:
        ecrire("TLS          : port 443, mais pas de données (segment de contrôle TCP)")
        return

    ecrire(f"TLS          : {len(donnees)} octets de données")
    ecrire(f"  Octets      : {donnees[:48].hex()}")
    stats["tls_octets"] += len(donnees)

    # Un enregistrement TLS commence par 5 octets non chiffrés :
    # type (1 octet) | version (2 octets) | longueur (2 octets)
    if len(donnees) >= 5 and donnees[0] in TYPES_TLS and donnees[1] == 3:
        type_enregistrement = TYPES_TLS[donnees[0]]
        version = donnees[1] * 256 + donnees[2]
        longueur = donnees[3] * 256 + donnees[4]
        nom_version = VERSIONS_TLS.get(version, hex(version))
        ecrire(f"  En-tête     : {type_enregistrement} | version {nom_version} | "
               f"longueur {longueur} octets")

        if donnees[0] == 22 and len(donnees) >= 6:
            message = TYPES_HANDSHAKE.get(donnees[5], f"type {donnees[5]}")
            ecrire(f"  Handshake   : {message}")
            stats["tls"][f"Handshake - {message}"] += 1
        else:
            stats["tls"][type_enregistrement] += 1

        if donnees[0] == 23:
            ecrire("  Contenu     : chiffré (illisible sans la clé de session)")
    else:
        ecrire("  En-tête     : pas d'en-tête TLS au début du segment "
               "(suite d'un enregistrement précédent)")
        stats["tls"]["Suite d'enregistrement"] += 1


def analyser_paquet(numero, paquet, stats):
    """Affiche la fiche complète d'un paquet et met à jour les statistiques."""
    temps = float(paquet.time)
    taille = len(paquet)
    protocole = protocole_principal(paquet)

    ecrire()
    ecrire(f"----- Paquet {numero} " + "-" * 50)
    ecrire(f"Horodatage   : {temps:.6f} ({date_lisible(temps)})")
    ecrire(f"Taille       : {taille} octets")
    ecrire(f"Résumé       : {paquet.summary()}")
    ecrire(f"Couches      : {' / '.join(liste_couches(paquet))}")
    ecrire(f"Protocole    : {protocole}")

    # Statistiques générales
    compter_couches(paquet, stats)
    stats["tailles"].append(taille)
    stats["classes"][classe_taille(taille)] += 1
    stats["tailles_par_protocole"][protocole].append(taille)

    # On teste toujours la présence d'une couche avant de lire ses champs
    afficher_ethernet(paquet, stats)

    if ARP in paquet:
        afficher_arp(paquet)

    afficher_ip(paquet, stats)

    if ICMP in paquet:
        afficher_icmp(paquet)

    if TCP in paquet:
        afficher_tcp(paquet, stats)
        tcp = paquet[TCP]
        if 80 in (tcp.sport, tcp.dport):
            afficher_http(numero, paquet, stats)
        elif 443 in (tcp.sport, tcp.dport):
            afficher_tls(paquet, stats)
    elif UDP in paquet:
        afficher_udp(paquet, stats)

    if DNS in paquet:
        afficher_dns(paquet, stats)


# ---------------------------------------------------------------------------
# 4. Recherche d'anomalies
# ---------------------------------------------------------------------------

def rechercher_anomalies(paquets):
    """
    Reprend les parties 6.1 (chevauchements) et 9 (ports multiples) du TP,
    et ajoute : retransmissions, connexions sans réponse, RST.
    """
    segments_vus = defaultdict(list)
    retransmissions = []
    chevauchements = []
    ports_par_source = defaultdict(set)
    syn_envoyes = {}
    syn_ack_vus = set()
    resets = []

    for numero, paquet in enumerate(paquets, start=1):
        if TCP not in paquet:
            continue

        source, destination = adresses_ip(paquet)
        if source is None:
            continue

        tcp = paquet[TCP]
        flags = str(tcp.flags)
        cle = (source, tcp.sport, destination, tcp.dport)

        # Tentatives de connexion : SYN sans ACK.
        # On ne garde que les SYN pour la recherche de scan : sinon un serveur
        # qui répond à un client sur ses ports éphémères ressemblerait à un scan.
        if "S" in flags and "A" not in flags:
            ports_par_source[source].add((destination, tcp.dport))
            syn_envoyes[cle] = numero
        elif "S" in flags and "A" in flags:
            # On remet la clé dans le sens client -> serveur
            syn_ack_vus.add((destination, tcp.dport, source, tcp.sport))

        if "R" in flags:
            resets.append(f"Paquet {numero} : RST {source}:{tcp.sport} -> "
                          f"{destination}:{tcp.dport}")

        # Retransmissions et chevauchements (partie 6.1)
        donnees = bytes(tcp.payload)
        if not donnees:
            continue

        debut = tcp.seq
        fin = debut + len(donnees)

        if (debut, fin) in segments_vus[cle]:
            retransmissions.append(
                f"Paquet {numero} : {source}:{tcp.sport} -> {destination}:{tcp.dport}, "
                f"Seq={debut}, longueur={len(donnees)} (segment identique déjà vu)")
        elif any(debut < ancien_fin and fin > ancien_debut
                 for ancien_debut, ancien_fin in segments_vus[cle]):
            chevauchements.append(
                f"Paquet {numero} : {source}:{tcp.sport} -> {destination}:{tcp.dport}, "
                f"Seq={debut}, longueur={len(donnees)} (recouvre un segment déjà vu)")

        segments_vus[cle].append((debut, fin))

    # Sources qui contactent beaucoup de ports différents (partie 9)
    ports_multiples = []
    for source, cibles in sorted(ports_par_source.items()):
        destinations = defaultdict(set)
        for destination, port in cibles:
            destinations[destination].add(port)
        for destination, ports in destinations.items():
            if len(ports) >= SEUIL_PORTS:
                exemple = sorted(ports)[:15]
                ports_multiples.append(
                    f"{source} -> {destination} | {len(ports)} ports distincts "
                    f"(ex. : {exemple})")

    # SYN sans SYN-ACK : connexion refusée, filtrée, ou capture incomplète
    sans_reponse = []
    for cle, numero in syn_envoyes.items():
        if cle not in syn_ack_vus:
            source, sport, destination, dport = cle
            sans_reponse.append(f"Paquet {numero} : {source}:{sport} -> "
                                f"{destination}:{dport}")

    return {
        "retransmissions": retransmissions,
        "chevauchements": chevauchements,
        "ports_multiples": ports_multiples,
        "sans_reponse": sans_reponse,
        "resets": resets,
    }


# ---------------------------------------------------------------------------
# 5. Rapport de synthèse
# ---------------------------------------------------------------------------

def afficher_liste(lignes, maximum=20):
    """Affiche une liste de lignes, en limitant leur nombre."""
    if not lignes:
        ecrire("  Aucun")
        return
    for ligne in lignes[:maximum]:
        ecrire(f"  {ligne}")
    if len(lignes) > maximum:
        ecrire(f"  ... et {len(lignes) - maximum} autre(s)")


def afficher_classement(compteur, largeur=40):
    """Affiche les TOP éléments les plus fréquents d'un Counter."""
    if not compteur:
        ecrire("  Aucun")
        return
    for element, nombre in compteur.most_common(TOP):
        ecrire(f"  {str(element):{largeur}s} : {nombre}")


def generer_synthese(fichier, paquets, stats, anomalies):
    """Rapport de synthèse (partie 10 du TP, en plus complet)."""
    temps = [float(p.time) for p in paquets]
    duree = max(temps) - min(temps)
    tailles = stats["tailles"]

    titre("RAPPORT DE SYNTHESE")
    ecrire(f"Fichier              : {fichier}")
    ecrire(f"Nombre de paquets    : {len(paquets)}")
    ecrire(f"Premier paquet       : {date_lisible(min(temps))}")
    ecrire(f"Dernier paquet       : {date_lisible(max(temps))}")
    ecrire(f"Durée apparente      : {duree:.3f} secondes")

    titre("PROTOCOLES")
    ecrire("Couches principales (un paquet peut en contenir plusieurs) :")
    afficher_classement(stats["couches"], 10)
    ecrire()
    ecrire("Toutes les couches reconnues par Scapy :")
    for nom, nombre in stats["toutes_couches"].most_common():
        ecrire(f"  {nom:30s} : {nombre}")

    titre("ADRESSES LES PLUS FREQUENTES")
    ecrire("Adresses IP source :")
    afficher_classement(stats["ip_sources"])
    ecrire("\nAdresses IP destination :")
    afficher_classement(stats["ip_destinations"])
    ecrire("\nAdresses MAC source :")
    afficher_classement(stats["mac_sources"], 20)
    ecrire("\nAdresses MAC destination :")
    afficher_classement(stats["mac_destinations"], 20)

    titre("PORTS DE DESTINATION LES PLUS UTILISES")
    ecrire("TCP :")
    afficher_classement(Counter({nom_service(p): n for p, n in stats["ports_tcp"].items()}), 20)
    ecrire("\nUDP :")
    afficher_classement(Counter({nom_service(p): n for p, n in stats["ports_udp"].items()}), 20)

    titre("FLUX ET CONVERSATIONS TCP")
    ecrire(f"Nombre de flux (directionnels) : {len(stats['flux'])}")
    ecrire(f"Nombre de conversations        : {len(stats['conversations'])}")
    ecrire("\nFlux les plus fréquents :")
    for (src, sport, dst, dport), nombre in stats["flux"].most_common(TOP):
        ecrire(f"  {src}:{sport} -> {dst}:{dport} | Paquets : {nombre}")
    ecrire("\nConversations les plus fréquentes (les deux sens regroupés) :")
    for (a, b), nombre in stats["conversations"].most_common(TOP):
        ecrire(f"  {a[0]}:{a[1]} <-> {b[0]}:{b[1]} : {nombre} paquets")

    titre("TAILLE DES PAQUETS")
    ecrire(f"Taille minimale : {min(tailles)} octets")
    ecrire(f"Taille maximale : {max(tailles)} octets")
    ecrire(f"Taille moyenne  : {sum(tailles) / len(tailles):.2f} octets")
    ecrire(f"Volume total    : {sum(tailles)} octets")

    ecrire("\nDix plus grands paquets :")
    for numero, taille in sorted(enumerate(tailles, start=1),
                                 key=lambda element: element[1],
                                 reverse=True)[:10]:
        ecrire(f"  Paquet {numero} : {taille} octets")

    ecrire("\nRépartition par classe de taille :")
    for classe in ["Moins de 100 octets", "100 a 499 octets",
                   "500 a 999 octets", "1000 octets et plus"]:
        nombre = stats["classes"][classe]
        pourcentage = 100 * nombre / len(tailles)
        ecrire(f"  {classe:25s} : {nombre:6d} ({pourcentage:5.1f} %)")

    ecrire("\nRépartition par protocole :")
    ecrire(f"  {'Protocole':16s} {'Paquets':>8s} {'Moyenne':>10s} {'Volume':>10s}")
    for protocole, liste in sorted(stats["tailles_par_protocole"].items(),
                                   key=lambda element: len(element[1]),
                                   reverse=True):
        moyenne = sum(liste) / len(liste)
        ecrire(f"  {protocole:16s} {len(liste):8d} {moyenne:10.1f} {sum(liste):10d}")

    titre("DNS")
    ecrire(f"Requêtes : {stats['dns_requetes']} | Réponses : {stats['dns_reponses']}")
    ecrire("\nNoms de domaine demandés :")
    afficher_classement(stats["dns_noms"], 45)
    ecrire("\nRéponses obtenues :")
    afficher_liste(stats["dns_resultats"])

    titre("HTTP (port 80, en clair)")
    afficher_liste(stats["http"])

    titre("TLS (port 443, chiffré)")
    ecrire(f"Volume de données TLS : {stats['tls_octets']} octets")
    afficher_classement(stats["tls"], 35)

    titre("ANOMALIES ET COMPORTEMENTS A EXAMINER")
    ecrire(f"Retransmissions possibles ({len(anomalies['retransmissions'])}) :")
    afficher_liste(anomalies["retransmissions"])
    ecrire(f"\nChevauchements possibles ({len(anomalies['chevauchements'])}) :")
    afficher_liste(anomalies["chevauchements"])
    ecrire(f"\nSources contactant au moins {SEUIL_PORTS} ports distincts "
           f"({len(anomalies['ports_multiples'])}) :")
    afficher_liste(anomalies["ports_multiples"])
    ecrire(f"\nSYN sans SYN-ACK observé ({len(anomalies['sans_reponse'])}) :")
    afficher_liste(anomalies["sans_reponse"])
    ecrire(f"\nSegments RST ({len(anomalies['resets'])}) :")
    afficher_liste(anomalies["resets"])
    ecrire()
    ecrire("Remarque : ces éléments sont des indices, pas des preuves d'attaque.")
    ecrire("Une retransmission peut venir d'une simple perte de paquet, un RST")
    ecrire("d'un port fermé, et une capture partielle peut créer de faux positifs.")

    # Valeurs pour remplir le tableau de la partie 10.1
    titre("ELEMENTS POUR LE TABLEAU DE SYNTHESE (partie 10.1)")
    dominants = ", ".join(f"{n} ({c})" for n, c in stats["couches"].most_common(3))
    principales = ", ".join(a for a, _ in stats["ip_sources"].most_common(3))
    nb_anomalies = len(anomalies["retransmissions"]) + len(anomalies["chevauchements"])
    ecrire(f"Nombre de paquets    : {len(paquets)} sur {duree:.1f} s")
    ecrire(f"Protocoles dominants : {dominants}")
    ecrire(f"Adresses principales : {principales}")
    ecrire(f"Requêtes DNS         : {stats['dns_requetes']} requêtes, "
           f"{len(stats['dns_noms'])} noms distincts")
    ecrire(f"Échanges HTTP        : {len(stats['http'])} requêtes/réponses lisibles")
    ecrire(f"Échanges TLS         : {sum(stats['tls'].values())} segments avec données, "
           f"{stats['tls_octets']} octets")
    ecrire(f"Anomalies TCP        : {nb_anomalies} (retransmissions + chevauchements)")
    ecrire("Limites              : capture ponctuelle, contenu TLS chiffré, "
           "seuils arbitraires")


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    global sortie

    fichier = sys.argv[1] if len(sys.argv) > 1 else FICHIER_PAR_DEFAUT

    paquets = charger_capture(fichier)
    if paquets is None:
        sys.exit(1)

    sortie = open(FICHIER_RAPPORT, "w", encoding="utf-8")

    titre("ANALYSE DE LA CAPTURE " + fichier)
    temps = [float(p.time) for p in paquets]
    ecrire(f"Nombre total de paquets : {len(paquets)}")
    ecrire(f"Durée apparente         : {max(temps) - min(temps):.3f} secondes")

    titre("DETAIL DES PAQUETS")
    stats = nouvelles_statistiques()
    for numero, paquet in enumerate(paquets, start=1):
        analyser_paquet(numero, paquet, stats)

    anomalies = rechercher_anomalies(paquets)
    generer_synthese(fichier, paquets, stats, anomalies)

    sortie.close()
    print(f"\nRapport enregistré dans {FICHIER_RAPPORT}")


if __name__ == "__main__":
    main()
