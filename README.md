#### **Deutsch**

**p2pPortForward** ist ein experimentelles Tool, das Peer-to-Peer (P2P)-Verbindungen über UDP nutzt, um Port-Forwarding zu ermöglichen. Es verwendet UDP für das Hole-Punching, um eine direkte Verbindung zwischen zwei Endpunkten herzustellen. Nach der Etablierung dieser Verbindung können sowohl UDP- als auch TCP-Pakete durch diese UDP-Verbindung übertragen werden. Das Tool befindet sich noch in einem experimentellen Stadium und ist daher noch nicht vollständig ausgereift. Es kann noch zu Problemen kommen, insbesondere bei der Handhabung von TCP-Verbindungen oder bei Routern, die fragmentierte UDP-Pakete blockieren, wenn diese zu groß sind.

#### **Befehle:**

Die Anwendung kann in zwei Modi ausgeführt werden:

- **source**: Startet den Quell-Client, der auf eingehende Verbindungen wartet und Daten weiterleitet.
- **dest**: Startet den Ziel-Client, der sich mit dem Quell-Client verbindet und Daten empfängt.

**Verwendung:**
```
Usage: <mode: source/dest> <server_ip> <fake_server_port/dest_port/real_server_port> <network_id> <network_password> <udp/tcp> <p2p_server_ip> <p2p_server_port>
```

**Beispiel:**

- Quell-Client:
  ```
  ./client source :: 19132 heldendesbildschirms nopassword udp 164.68.125.80 8888
  ```

- Ziel-Client:
  ```
  ./client dest 164.68.125.80 19132 heldendesbildschirms nopassword udp 164.68.125.80 8888
  ```

- Server:
  ```
  ./server 8888
  ```

#### **Funktionsweise:**

- **UDP für Hole-Punching**: UDP wird verwendet, um eine direkte Verbindung zwischen zwei Endpunkten über ein Peer-to-Peer-Netzwerk zu etablieren. Dies geschieht durch das Hole-Punching-Verfahren, bei dem UDP-Nachrichten zwischen den Peers ausgetauscht werden, um NATs (Network Address Translators) zu umgehen.
  
- **UDP und TCP durch die UDP-Verbindung**: Sobald das Hole-Punching abgeschlossen ist und die Peer-to-Peer-Verbindung hergestellt ist, können sowohl UDP- als auch TCP-Pakete über die bestehende UDP-Verbindung übertragen werden. Dies ermöglicht es, TCP-basierte Protokolle und Anwendungen durch das UDP-Netzwerk zu tunneln.

#### **Probleme:**

1. **TCP benötigt ein eigenes Protokoll**:
   - TCP erfordert spezielle Mechanismen zur Verbindung und Fehlerbehandlung, die nicht vollständig implementiert sind. Daher kann es bei der Kommunikation zu Problemen kommen, insbesondere bei Verbindungsabbrüchen oder Zeitüberschreitungen.

2. **Router blockieren fragmentierte UDP-Pakete**:
   - Wenn UDP-Pakete zu groß sind, müssen sie fragmentiert werden. Einige Router blockieren diese fragmentierten Pakete, was zu Verbindungsabbrüchen oder fehlgeschlagenen Übertragungen führen kann. Dies bedeutet, dass Pakete möglicherweise nicht korrekt über das Netzwerk weitergeleitet werden, was die Verbindungsstabilität beeinträchtigen könnte.

---

#### **English**

**p2pPortForward** is an experimental tool that enables Peer-to-Peer (P2P) connections over UDP to facilitate port forwarding. It uses UDP for hole-punching to establish a direct connection between two endpoints, after which both UDP and TCP packets can be transmitted through the UDP connection. The tool is still in an experimental stage, meaning it is not fully mature and may still experience issues, especially with TCP connections or routers that block fragmented UDP packets when they are too large.

#### **Commands:**

The application can be run in two modes:

- **source**: Starts the source client that listens for incoming connections and forwards data.
- **dest**: Starts the destination client that connects to the source client and receives data.

**Usage:**
```
Usage: <mode: source/dest> <server_ip> <fake_server_port/dest_port/real_server_port> <network_id> <network_password> <udp/tcp> <p2p_server_ip> <p2p_server_port>
```

**Example:**

- Source client:
  ```
  ./client source :: 19132 heldendesbildschirms nopassword udp 164.68.125.80 8888
  ```

- Destination client:
  ```
  ./client dest 164.68.125.80 19132 heldendesbildschirms nopassword udp 164.68.125.80 8888
  ```

- Server:
  ```
  ./server 8888
  ```

#### **How It Works:**

- **UDP for Hole-Punching**: UDP is used to establish a direct connection between two endpoints over a peer-to-peer network using the hole-punching technique. This involves exchanging UDP packets between the peers to bypass NATs (Network Address Translators).
  
- **UDP and TCP through the UDP Connection**: Once hole-punching is complete and the peer-to-peer connection is established, both UDP and TCP packets can be transmitted over the existing UDP connection. This allows tunneling of TCP-based protocols and applications through the UDP network.

#### **Problems:**

1. **TCP Requires Its Own Protocol**:
   - TCP requires specific connection and error-handling mechanisms that are not fully implemented here. Therefore, communication may experience issues, especially with connection drops or timeouts.

2. **Routers Block Fragmented UDP Packets**:
   - If UDP packets are too large, they need to be fragmented. Some routers block these fragmented packets, causing connection failures or incomplete data transmission. This means that packets may not be properly forwarded through the network, potentially affecting connection stability.
