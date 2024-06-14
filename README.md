# BitTorrent Client

Questo progetto è un semplice client BitTorrent scritto in Python. Il client può decodificare i dati bencode, analizzare file torrent, eseguire handshake con i peer, recuperare liste di peer e scaricare pezzi di un file torrent.

## Funzionalità

- **Decodifica Bencode**: Decodifica dati bencode.
- **Analisi File Torrent**: Analizza i file torrent per estrarre informazioni come la URL del tracker, la lunghezza del file e l'hash delle informazioni.
- **Handshake con i Peer**: Esegue handshake con i peer per iniziare il download.
- **Recupero Peer**: Recupera la lista dei peer dal tracker.
- **Download di Pezzi**: Scarica pezzi specifici di un file torrent.
- **Download Completo**: Scarica l'intero file descritto nel file torrent.

## Prerequisiti

- Python 3.x
- Moduli Python: hashlib, typing, json, sys, urllib, random, math, socket, threading, queue, os, tempfile

## Installazione

1. Clona questo repository:
    ```bash
    git clone https://github.com/ref1o/bitTorrent-Client.git
    ```

2. Entra nella directory del progetto:
    ```bash
    cd bitTorrent-Client
    ```

## Utilizzo

### Comandi Disponibili

#### 1. Decodifica Bencode

Decodifica un valore bencode:
```bash
./bittorrent.sh decode "<valore_bencode>"
```
Esempio:
```bash
./bittorrent.sh decode "5:hello"
```

#### 2. Informazioni sul Torrent

Mostra informazioni dettagliate su un file torrent:
```bash
./bittorrent.sh info <file_torrent>
```
Esempio:
```bash
./bittorrent.sh info esempio.torrent
```

#### 3. Lista dei Peer

Recupera la lista dei peer da un file torrent:
```bash
./bittorrent.sh peers <file_torrent>
```
Esempio:
```bash
./bittorrent.sh peers esempio.torrent
```

#### 4. Handshake con un Peer

Esegue handshake con un peer specifico:
```bash
./bittorrent.sh handshake <file_torrent> <peer_ip:peer_port>
```
Esempio:
```bash
./bittorrent.sh handshake esempio.torrent 127.0.0.1:6881
```

#### 5. Download di un Pezzo Specifico

Scarica un pezzo specifico da un torrent:
```bash
./bittorrent.sh download_piece <output_file> <file_torrent> <target_piece>
```
Esempio:
```bash
./bittorrent.sh download_piece output.file esempio.torrent 0
```

#### 6. Download Completo

Scarica l'intero file descritto nel file torrent:
```bash
./bittorrent.sh download <output_file> <file_torrent>
```
Esempio:
```bash
./bittorrent.sh download output.file esempio.torrent
```

## Dettagli del Codice

### Gestione delle Comunicazioni di Rete

Il codice include funzionalità avanzate per la gestione delle comunicazioni di rete tramite socket. Questo permette al client di stabilire connessioni con i peer e scambiare dati in modo efficiente durante il download dei pezzi del torrent.

### Download Parallelo dei Pezzi

Il client supporta il download parallelo dei pezzi utilizzando thread. Questo approccio migliora le prestazioni complessive del download permettendo al client di scaricare più pezzi contemporaneamente da diversi peer.

### Gestione delle Operazioni di I/O

Il client gestisce in modo efficiente le operazioni di I/O per la scrittura dei file scaricati. Ciò assicura che i dati dei pezzi scaricati siano correttamente salvati nel file locale, mantenendo l'integrità del torrent.

### Decodifica e Codifica Bencode

Il file include funzioni per la decodifica (`decode_bencode` e `decode_bencode_helper`) e codifica (`encode_bencode`) di dati bencode.

### Analisi del File Torrent

La funzione `parse_torrent` legge e decodifica un file torrent.

### Hash delle Informazioni

La funzione `get_info_hash` calcola l'hash SHA-1 del dizionario "info" del file torrent.

### Comunicazione di Rete

Funzioni come `handshake_message`, `perform_handshake`, e `get_peers` gestiscono le interazioni di rete con i peer.

### Download dei Pezzi

Il codice include la logica per richiedere e scaricare specifici pezzi del file torrent da peer.

### Funzione Principale

La funzione `main` gestisce i vari comandi disponibili per decodificare dati bencode, mostrare informazioni sul torrent, elencare i peer, eseguire handshake, scaricare pezzi specifici o l'intero file.

## Contributi

Sono benvenuti contributi sotto forma di issue e pull request. Si prega di seguire le convenzioni di codifica e includere test appropriati per le nuove funzionalità.

## Licenza

Questo progetto è distribuito sotto la licenza MIT. Vedi il file LICENSE per maggiori dettagli.
