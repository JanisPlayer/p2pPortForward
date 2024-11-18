#include <iostream>
#include <unordered_map>
#include <string>
#include <asio.hpp>
#include <sstream>

using asio::ip::udp;

struct ClientInfo
{
    udp::endpoint endpoint;
    std::string network_id;
    std::string network_password;

    // Default constructor
    ClientInfo() : endpoint(), network_id(""), network_password("") {}

    // Your existing constructor
    ClientInfo(const udp::endpoint &ep, const std::string &net_id, const std::string &net_pwd)
        : endpoint(ep), network_id(net_id), network_password(net_pwd) {}
};

class P2PServer
{
public:
    P2PServer(asio::io_context &io_context, unsigned short port)
        : socket_(io_context, udp::endpoint(udp::v4(), port))
    {
        start_receive();
    }

private:
    void start_receive()
    {
        socket_.async_receive_from(
            asio::buffer(recv_buffer_), remote_endpoint_,
            [this](std::error_code ec, std::size_t bytes_recvd)
            {
                if (!ec && bytes_recvd > 0)
                {
                    handle_receive(bytes_recvd);
                }
                start_receive();
            });
    }

    void handle_receive(std::size_t bytes_recvd)
    {
        std::string received_data(recv_buffer_.begin(), recv_buffer_.begin() + bytes_recvd);
        std::cout << "Received message: " << received_data << " from " << remote_endpoint_ << "\n";

        // Parse message (assume simple format: "REGISTER:<network_id>:<network_password>")
        std::string command, network_id, network_password;
        std::istringstream iss(received_data);
        if (std::getline(iss, command, ':') &&
            std::getline(iss, network_id, ':') &&
            std::getline(iss, network_password))
        {

            if (command == "REGISTER")
            {
                register_client(network_id, network_password);
            }
            else if (command == "CONNECT")
            {
                connect_clients(network_id, network_password);
            }
        }
    }

    void register_client(const std::string &network_id, const std::string &network_password)
    {
        // Wenn der erste Client sich registriert, wird er als P2P-Host festgelegt
        if (p2p_host_ == nullptr)
        {
            p2p_host_ = std::make_shared<ClientInfo>(remote_endpoint_, network_id, network_password);
            std::cout << "P2P Host set: " << remote_endpoint_ << " with Network ID: " << network_id << "\n";
        }
        else
        {
            ClientInfo client_info{remote_endpoint_, network_id, network_password};
            clients_[network_id] = client_info;
            std::cout << "Registered client: " << remote_endpoint_ << " with Network ID: " << network_id << "\n";
        }
    }

    void connect_clients(const std::string &network_id, const std::string &network_password)
    {
        if (p2p_host_)
        {
            // Schritt 1: Sende P2P-Host-Informationen an den neuen Client
            std::string response = "PEER:" + p2p_host_->endpoint.address().to_string() + ":" + std::to_string(p2p_host_->endpoint.port());
            socket_.send_to(asio::buffer(response), remote_endpoint_);

            // Schritt 2: Umwandeln der Remote-Client-Endpunktinformationen (IP und Port) in eine Zeichenkette
            std::string client_info = "CLIENT:" + remote_endpoint_.address().to_string() + ":" + std::to_string(remote_endpoint_.port());

            // Sende die Informationen des neuen Clients an den P2P-Host
            socket_.send_to(asio::buffer(client_info), p2p_host_->endpoint);

            std::cout << "P2P host info sent to client: " << response << "\n";
            std::cout << "Client info sent to P2P host: " << client_info << "\n";

            // Schritt 3: Bestätigen, dass der Hole-Punching-Prozess abgeschlossen ist
            // std::string complete_message = "Hole Punching abgeschlossen!";
            // socket_.send_to(asio::buffer(complete_message), remote_endpoint_);
        }
        else
        {
            std::string error_message = "ERROR: No P2P host available.";
            socket_.send_to(asio::buffer(error_message), remote_endpoint_);
        }
    }

    udp::socket socket_;
    udp::endpoint remote_endpoint_;
    std::array<char, 1024> recv_buffer_;
    std::unordered_map<std::string, ClientInfo> clients_;
    std::shared_ptr<ClientInfo> p2p_host_ = nullptr; // Der erste verbundene Client wird der P2P-Host
};

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: p2p_server <port>\n";
        return 1;
    }

    asio::io_context io_context;
    unsigned short port = std::stoi(argv[1]);

    P2PServer server(io_context, port);
    io_context.run();

    return 0;
}
