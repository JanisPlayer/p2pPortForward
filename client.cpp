#include <iostream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <stdexcept>
#include <sys/socket.h>
#include <boost/asio.hpp> // Boost ASIO inkludieren
#include <thread>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

int sock = socket(AF_INET, SOCK_DGRAM, 0);
struct sockaddr_in dest_addr;

void receiveMessages(int sockfd)
{
    char buffer[1024];
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int receivedBytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (receivedBytes > 0)
        {
            std::cout << "\nEmpfangen: " << buffer << std::endl;
        }
    }
}

void connect_to_p2p_server(const std::string &server_ip, int server_port, const std::string &network_id, const std::string &network_password, const std::string &mode)
{
    // Socket erstellen
    if (sock < 0)
    {
        perror("Socket erstellen fehlgeschlagen");
        exit(EXIT_FAILURE);
    }

    // Lokale Serveradresse definieren
    struct sockaddr_in local_server_addr;
    memset(&local_server_addr, 0, sizeof(local_server_addr));
    local_server_addr.sin_family = AF_INET;
    local_server_addr.sin_port = htons(0); // Verwende 0, um einen beliebigen freien Port automatisch zuzuweisen
    local_server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&local_server_addr, sizeof(local_server_addr)) < 0)
    {
        std::cerr << "Fehler beim Binden des Sockets." << std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Ungültige Server-IP-Adresse" << std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }

    // inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (mode == "source")
    {
        std::string connect_data = "CONNECT:" + network_id + ":" + network_password;
        if (sendto(sock, connect_data.c_str(), connect_data.size(), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            perror("Daten senden fehlgeschlagen");
            close(sock);
            exit(EXIT_FAILURE);
        }
    }
    else if (mode == "dest")
    {
        // Netzwerk-ID und Passwort als Registrierung senden
        std::string auth_data = "REGISTER:" + network_id + ":" + network_password;
        if (sendto(sock, auth_data.c_str(), auth_data.size(), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            perror("Daten senden fehlgeschlagen");
            close(sock);
            exit(EXIT_FAILURE);
        }
    }

    std::cout << "Warte auf Antwort vom Server...\n";

    // Warten auf Antwort des Servers (Verbindungsinformationen des Zielclients)
    char buffer[1024];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &from_len);
    if (n < 0)
    {
        perror("Fehler beim Empfangen der Antwort");
        close(sock);
        exit(EXIT_FAILURE);
    }

    buffer[n] = '\0'; // Nullterminierung der empfangenen Nachricht
    std::cout << "Verbindungsdaten vom P2P-Server erhalten: " << buffer << std::endl;

    // Parsing der empfangenen Verbindungsdaten des Zielclients
    std::string received_data(buffer);
    size_t pos = received_data.find(":");
    if (pos == std::string::npos)
    {
        std::cerr << "Fehlerhafte Antwort vom Server." << std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Schritt 1: Entferne "CLIENT:" oder passe das Parsing entsprechend an
    size_t prefix_pos = received_data.find(":");
    if (prefix_pos != std::string::npos)
    {
        received_data = received_data.substr(prefix_pos + 1); // Entferne den Präfix bis zum ersten ":"
    }

    // Schritt 2: Teile die IP-Adresse und den Port auf
    size_t colon_pos = received_data.find(":");
    if (colon_pos == std::string::npos)
    {
        std::cerr << "Fehlerhafte Antwort vom Server: Kein Port gefunden." << std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }

    std::string dest_ip = received_data.substr(0, colon_pos);
    int dest_port = std::stoi(received_data.substr(colon_pos + 1));

    // Jetzt eine direkte Verbindung zum Zielclient herstellen
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);

    // Hole-Punching: An den Zielclient senden, unabhängig von der Erfolgsprüfung

    std::cout << "Jetzt eine direkte Verbindung zum Zielclient herstellen. " << dest_ip << ":" << dest_port << std::endl;

    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0)
    {
        std::cerr << "Fehler bei der Konvertierung der Ziel-IP-Adresse." << std::endl;
        close(sock);
        return;
    }

    std::string punch_message = "PING";
    sendto(sock, punch_message.c_str(), punch_message.size(), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    // Danach warten wir auf eine Antwort
    socklen_t addr_len = sizeof(dest_addr);
    int bytes_received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&dest_addr, &addr_len);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0'; // Null-terminieren
        std::cout << "Antwort vom Peer erhalten: " << buffer << std::endl;
    }
    else
    {
        perror("Fehler beim Empfangen der Antwort");
    }

    std::cout << "Verbindung zum Zielclient hergestellt.\n";
    return;

    // Starte Thread für Empfang
    std::thread receiveThread(receiveMessages, sock);

    // Jetzt warten, um auf Daten zu warten und die Kommunikation fortzusetzen
    while (true)
    {
        // Beispiel für das Senden von Nachrichten:
        char message[1024];
        std::cout << "Geben Sie eine Nachricht ein: ";
        std::cin.getline(message, sizeof(message));

        // Nachricht an den anderen Client senden
        ssize_t sent = sendto(sock, message, strlen(message), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (sent < 0)
        {
            perror("Nachricht senden fehlgeschlagen");
            close(sock);
            exit(EXIT_FAILURE);
        }

        // Warten auf Antwort des Zielclients
        /*ssize_t n = recvfrom(sock, message, sizeof(message) - 1, 0, (struct sockaddr*)&dest_addr, &addr_len);
        if (n > 0) {
            message[n] = '\0'; // Nullterminierung
            std::cout << "Antwort vom Zielclient: " << message << std::endl;
        } else {
            perror("Fehler beim Empfangen der Antwort");
        }*/
    }

    // close(sock); // Schließe die Verbindung, wenn alles erledigt ist
}

#define MAX_PACKET_SIZE 1024
#define MAX_UDP_SIZE 1024

void fragmentAndSend(int sockfd, struct sockaddr_in &dest_addr, const char *data, size_t data_size)
{
    size_t offset = 0;
    int fragment_id = 0; // Fragment-ID zur Identifikation der Fragmente

    while (offset < data_size)
    {
        size_t remaining_data = data_size - offset;
        size_t fragment_size = std::min(remaining_data, (size_t)MAX_UDP_SIZE);

        // Fragment erstellen
        char fragment[MAX_UDP_SIZE];
        std::memcpy(fragment, data + offset, fragment_size);

        // Header für Fragment ID und mehr Information hinzufügen (optional)
        char header[4];
        header[0] = fragment_id & 0xFF;                       // Fragment-ID (1 Byte)
        header[1] = (fragment_id >> 8) & 0xFF;                // Fragment-ID (weiteres Byte)
        header[2] = (remaining_data <= MAX_UDP_SIZE) ? 1 : 0; // End-Flag, wenn das letzte Fragment
        header[3] = 0;                                        // Kann für die Sequenznummer oder weiteres verwendet werden

        // Fragment senden
        sendto(sockfd, header, sizeof(header), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        sendto(sockfd, fragment, fragment_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // Offset anpassen und Fragment-ID erhöhen
        offset += fragment_size;
        fragment_id++;
    }
}

void receiveAndReconstruct(int sockfd)
{
    char buffer[MAX_UDP_SIZE];
    struct sockaddr_in from_addr;
    socklen_t addr_len = sizeof(from_addr);
    int current_fragment_id = 0;
    bool received_all_fragments = false;

    while (!received_all_fragments)
    {
        ssize_t received_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &addr_len);

        if (received_len > 0)
        {
            // Erstellt Fragment-ID aus Header
            int fragment_id = buffer[0] | (buffer[1] << 8);

            // Überprüfen, ob das Fragment das letzte ist
            bool is_last_fragment = buffer[2] == 1;

            // Datenfragment
            char *data = buffer + 4; // Header-Datenüberspringen

            // Hier kannst du die Daten weiterverarbeiten oder speichern

            std::cout << "Fragment #" << fragment_id << " erhalten" << std::endl;

            // Wenn es das letzte Fragment ist, beende die Rekonstruktion
            if (is_last_fragment)
            {
                received_all_fragments = true;
                std::cout << "Alle Fragmente empfangen, Rekonstruktion abgeschlossen." << std::endl;
            }
        }
    }
}

void start_source_client(const std::string &fake_server_ip, unsigned short port, const std::string &network_id, const std::string &network_password, std::string &protocol)
{
    boost::asio::io_context io_context;
    boost::asio::ip::address address = boost::asio::ip::address::from_string(fake_server_ip);
    // udp::socket socket(io_context, udp::endpoint(udp::v4(), port));
    udp::socket socket(io_context, udp::endpoint(address, port));

    /*if (protocol == "udp")
    {
        udp::socket socket(io_context, udp::endpoint(udp::v4(), port));
    }
    else if (protocol == "tcp")
    {
        tcp::socket socket(io_context, tcp::endpoint(tcp::v4(), port));
    }*/

    socket.set_option(boost::asio::socket_base::receive_buffer_size(MAX_PACKET_SIZE));
    socket.set_option(boost::asio::socket_base::send_buffer_size(MAX_PACKET_SIZE));

    int rcvbuf_size = MAX_PACKET_SIZE; // Puffergröße in Bytes

    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    /*int mtu = 1500; // Typische MTU für Ethernet-Verbindungen
    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu)) < 0)
    {
        perror("Fehler beim Setzen der MTU-Entdeckung");
        close(sock);
        return;
    }*/

    std::cout << "Source client gestartet. Fake Server IP: " << fake_server_ip << " Port: " << port << "\n";
    std::cout << "Verbinden mit P2P-Netzwerk mit ID: " << network_id << " und Passwort: " << network_password << "\n";

    // Paketweiterleitungsschleife
    char recv_P2P_buf[MAX_PACKET_SIZE] = {0};
    std::array<char, MAX_PACKET_SIZE> recv_buf;
    udp::endpoint remote_endpoint;
    boost::system::error_code error;
    while (true)
    {
        size_t len = socket.receive_from(boost::asio::buffer(recv_buf), remote_endpoint, 0, error);

        if (!error && len > 0 && dest_addr.sin_addr.s_addr != 0 && dest_addr.sin_port != 0)
        {
            std::cout << "Paket empfangen von: " << remote_endpoint << " Größe: " << len << "\n";
            std::string data(recv_buf.data(), len);
            std::cout << "Daten: " << data << std::endl;

            // Paketweiterleitungslogik

            // fragmentAndSend(sock, dest_addr, recv_buf.data(), len);

            ssize_t sent = sendto(sock, recv_buf.data(), len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (sent < 0)
            {
                perror("Nachricht senden fehlgeschlagen");
                close(sock);
                exit(EXIT_FAILURE);
            }
            // udp::socket sockettest(io_context, udp::endpoint(udp::v4(), 0));
            // sockettest.set_option(boost::asio::socket_base::receive_buffer_size(MAX_PACKET_SIZE));
            // sockettest.set_option(boost::asio::socket_base::send_buffer_size(MAX_PACKET_SIZE));
            // std::string ip_address = inet_ntoa(dest_addr.sin_addr);
            // udp::endpoint test_endpoint(boost::asio::ip::address::from_string(ip_address), dest_addr.sin_port);
            // sockettest.send_to(boost::asio::buffer(recv_buf), test_endpoint, 0, error);
        }

        int receivedBytes = recvfrom(sock, recv_P2P_buf, sizeof(recv_P2P_buf), 0, nullptr, nullptr);

        if (receivedBytes > 0)
        {
            std::string dataj(recv_P2P_buf, receivedBytes);
            std::cout << "\nEmpfangen: " << dataj << std::endl;
            socket.send_to(boost::asio::buffer(dataj), remote_endpoint, 0, error);
        }
    }
}

void start_dest_client(const std::string &server_ip, unsigned short port, const std::string &network_id, const std::string &network_password, std::string &protocol)
{
    boost::asio::io_context io_context;
    udp::socket socket(io_context, udp::endpoint(udp::v4(), 0));

    /*if (protocol == "udp")
    {
        udp::socket socket(io_context, udp::endpoint(udp::v4(), 0));
    }
    else if (protocol == "tcp")
    {
        tcp::socket socket(io_context, tcp::endpoint(tcp::v4(), 0));
    }*/

    socket.set_option(boost::asio::socket_base::receive_buffer_size(MAX_PACKET_SIZE));
    socket.set_option(boost::asio::socket_base::send_buffer_size(MAX_PACKET_SIZE));

    int rcvbuf_size = MAX_PACKET_SIZE; // Puffergröße in Bytes

    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    /*int mtu = 1500; // Typische MTU für Ethernet-Verbindungen
    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu)) < 0)
    {
        perror("Fehler beim Setzen der MTU-Entdeckung");
        close(sock);
        return;
    }*/

    // Zielserveradresse vorbereiten
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Ungültige Server-IP-Adresse.\n";
        return;
    }

    std::cout << "Destination client gestartet. Port: " << port << "\n";
    std::cout << "Verbinden mit P2P-Netzwerk mit ID: " << network_id << " und Passwort: " << network_password << "\n";

    char recv_P2P_buf[MAX_PACKET_SIZE] = {0};
    std::array<char, MAX_PACKET_SIZE> recv_buf;
    udp::endpoint server_endpoint(boost::asio::ip::address::from_string(server_ip), port);
    udp::endpoint remote_endpoint;
    boost::system::error_code error;

    while (true)
    {

        int receivedBytes = recvfrom(sock, recv_P2P_buf, sizeof(recv_P2P_buf), 0, nullptr, nullptr);

        if (receivedBytes > 0)
        {
            std::string dataj(recv_P2P_buf, receivedBytes);
            std::cout << "\nEmpfangen: " << dataj << std::endl;
            socket.send_to(boost::asio::buffer(dataj), server_endpoint, 0, error);
        }

        size_t len = socket.receive_from(boost::asio::buffer(recv_buf), server_endpoint, 0, error);

        if (!error && len > 0)
        {
            std::cout << "Paket empfangen von: " << server_endpoint << "\n";
            std::string data(recv_buf.begin(), recv_buf.begin() + len);
            std::cout << "Daten: " << data << "\n";

            ssize_t sent = sendto(sock, recv_buf.data(), len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (sent < 0)
            {
                perror("Nachricht senden fehlgeschlagen");
                close(sock);
                exit(EXIT_FAILURE);
            }
        }
    }
}

void start_source_client_tcp(const std::string &fake_server_ip, unsigned short port, const std::string &network_id, const std::string &network_password, std::string &protocol)
{
    boost::asio::io_context io_context;
    // tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));
    boost::asio::ip::address address = boost::asio::ip::address::from_string(fake_server_ip);
    tcp::acceptor acceptor(io_context, tcp::endpoint(address, port));

    // Warten auf und Akzeptieren einer Verbindung
    tcp::socket socket(io_context);
    acceptor.accept(socket); // Blockiert, bis ein Client sich verbindet
    // socket.non_blocking(true); //async_read_some async_resolve async_connect

    socket.set_option(boost::asio::socket_base::receive_buffer_size(MAX_PACKET_SIZE));
    socket.set_option(boost::asio::socket_base::send_buffer_size(MAX_PACKET_SIZE));

    int rcvbuf_size = MAX_PACKET_SIZE; // Puffergröße in Bytes

    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    /*int mtu = 1500; // Typische MTU für Ethernet-Verbindungen
    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu)) < 0)
    {
        perror("Fehler beim Setzen der MTU-Entdeckung");
        close(sock);
        return;
    }*/

    std::cout << "Source client gestartet. Fake Server IP: " << fake_server_ip << " Port: " << port << "\n";
    std::cout << "Verbinden mit P2P-Netzwerk mit ID: " << network_id << " und Passwort: " << network_password << "\n";

    // Paketweiterleitungsschleife
    char recv_P2P_buf[MAX_PACKET_SIZE] = {0};
    std::array<char, MAX_PACKET_SIZE> recv_buf;
    tcp::endpoint remote_endpoint;
    boost::system::error_code error;

    while (true)
    {
        size_t len = socket.read_some(boost::asio::buffer(recv_buf), error);
        if (error)
        {
            std::cerr << "Fehler beim Empfang: " << error.message() << "\n";
        }

        if (!error && len > 0 && dest_addr.sin_addr.s_addr != 0 && dest_addr.sin_port != 0)
        {
            std::cout << "Paket empfangen von: " << remote_endpoint << " Größe: " << len << "\n";
            std::string data(recv_buf.data(), len);
            std::cout << "Daten: " << data << std::endl;

            // Paketweiterleitungslogik

            // fragmentAndSend(sock, dest_addr, recv_buf.data(), len);

            ssize_t sent = sendto(sock, recv_buf.data(), len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (sent < 0)
            {
                perror("Nachricht senden fehlgeschlagen");
                close(sock);
                exit(EXIT_FAILURE);
            }

            // udp::socket sockettest(io_context, udp::endpoint(udp::v4(), 0));
            // sockettest.set_option(boost::asio::socket_base::receive_buffer_size(MAX_PACKET_SIZE));
            // sockettest.set_option(boost::asio::socket_base::send_buffer_size(MAX_PACKET_SIZE));
            // std::string ip_address = inet_ntoa(dest_addr.sin_addr);
            // udp::endpoint test_endpoint(boost::asio::ip::address::from_string(ip_address), dest_addr.sin_port);
            // sockettest.send_to(boost::asio::buffer(recv_buf), test_endpoint, 0, error);
        }

        int receivedBytes = recvfrom(sock, recv_P2P_buf, sizeof(recv_P2P_buf), 0, nullptr, nullptr);

        if (receivedBytes > 0)
        {
            std::string dataj(recv_P2P_buf, receivedBytes);
            std::cout << "\nEmpfangen: " << dataj << std::endl;
            socket.send(boost::asio::buffer(dataj));
        }
    }
}

void start_dest_client_tcp(const std::string &server_ip, unsigned short port, const std::string &network_id, const std::string &network_password, std::string &protocol)
{
    boost::asio::io_context io_context;
    tcp::socket socket(io_context, tcp::endpoint(tcp::v4(), 0));

    socket.set_option(boost::asio::socket_base::receive_buffer_size(MAX_PACKET_SIZE));
    socket.set_option(boost::asio::socket_base::send_buffer_size(MAX_PACKET_SIZE));

    // socket.non_blocking(true); //async_read_some async_resolve async_connect
    int rcvbuf_size = MAX_PACKET_SIZE; // Puffergröße in Bytes

    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        perror("Fehler beim Setzen der Empfangspuffergröße");
        close(sock);
        return;
    }

    /*int mtu = 1500; // Typische MTU für Ethernet-Verbindungen
    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu)) < 0)
    {
        perror("Fehler beim Setzen der MTU-Entdeckung");
        close(sock);
        return;
    }*/

    // Zielserveradresse vorbereiten
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Ungültige Server-IP-Adresse.\n";
        return;
    }

    std::cout << "Destination client gestartet. Port: " << port << "\n";
    std::cout << "Verbinden mit P2P-Netzwerk mit ID: " << network_id << " und Passwort: " << network_password << "\n";

    char recv_P2P_buf[MAX_PACKET_SIZE] = {0};
    std::array<char, MAX_PACKET_SIZE> recv_buf;
    tcp::endpoint server_endpoint(boost::asio::ip::address::from_string(server_ip), port);
    udp::endpoint remote_endpoint;
    boost::system::error_code error;

    // socket.connect(server_endpoint, error);
    // if (error)
    // {
    //     std::cerr << "Verbindungsfehler: " << error.message() << "\n";
    //     return;
    // }

    while (true)
    {

        int receivedBytes = recvfrom(sock, recv_P2P_buf, sizeof(recv_P2P_buf), 0, nullptr, nullptr);

        if (receivedBytes > 0)
        {
            std::string dataj(recv_P2P_buf, receivedBytes);
            std::cout << "\nEmpfangen: " << dataj << std::endl;
            // socket.close();                   // Schließe den aktuellen Socket
            // socket = tcp::socket(io_context); // Erstelle einen neuen Socket

            socket.connect(server_endpoint, error);
            socket.send(boost::asio::buffer(dataj));

            if (error)
            {
                std::cerr << "Verbindungsfehler: " << error.message() << "\n";
            }
        }

        size_t len = socket.read_some(boost::asio::buffer(recv_buf), error);
        if (error)
        {
            if (error == boost::asio::error::eof)
            {
                std::cerr << "Verbindung geschlossen.\n";
                socket.close();                   // Schließe den aktuellen Socket
                socket = tcp::socket(io_context); // Erstelle einen neuen Socket
                socket.connect(server_endpoint, error);
                if (error)
                {
                    std::cerr << "Verbindungsfehler: " << error.message() << "\n";
                }
            }
            else
            {
                std::cerr << "Fehler beim Empfang: " << error.message() << "\n";
            }
        }
        std::cout << "Empfangene Daten: " << std::string(recv_buf.data(), len) << "\n";

        if (!error && len > 0)
        {
            std::cout << "Paket empfangen von: " << server_endpoint << "\n";
            std::string data(recv_buf.begin(), recv_buf.begin() + len);
            std::cout << "Daten: " << data << "\n";

            ssize_t sent = sendto(sock, recv_buf.data(), len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (sent < 0)
            {
                perror("Nachricht senden fehlgeschlagen");
                close(sock);
                exit(EXIT_FAILURE);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    std::cout << "argc: " << argc << std::endl; // Ausgabe der Argumentanzahl
    for (int i = 0; i < argc; ++i)
    {
        std::cout << "argv[" << i << "]: " << argv[i] << std::endl; // Ausgabe jedes Arguments
    }

    if (argc != 9)
    {
        std::cerr << "Usage: <mode: source/dest> <server_ip> <fake_server_port/dest_port/real_server_port> <network_id> <network_password> <udp/tcp> <p2p_server_ip> <p2p_server_port>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string fake_server_ip = argv[2];
    int port = std::stoi(argv[3]);
    std::string network_id = argv[4];
    std::string network_password = argv[5];
    std::string protocol = argv[6];
    std::string p2p_server_ip = argv[7];
    int p2p_server_port = std::stoi(argv[8]);

    // std::string p2p_server_ip = "164.68.125.80";
    // int p2p_server_port = 8888;

    connect_to_p2p_server(p2p_server_ip, p2p_server_port, network_id, network_password, mode);

    if (mode == "source")
    {
        if (protocol == "udp")
        {
            start_source_client(fake_server_ip, port, network_id, network_password, protocol);
        }
        else if (protocol == "tcp")
        {
            start_source_client_tcp(fake_server_ip, port, network_id, network_password, protocol);
        }
    }
    else if (mode == "dest")
    {
        if (protocol == "udp")
        {
            start_dest_client(fake_server_ip, port, network_id, network_password, protocol);
        }
        else if (protocol == "tcp")
        {
            start_dest_client_tcp(fake_server_ip, port, network_id, network_password, protocol);
        }
    }
    else
    {
        std::cerr << "Ungültiger Modus. Verwenden Sie 'source' oder 'dest'.\n";
        return 1;
    }

    return 0;
}