#include "server.hpp"
#include "dns_parser.hpp"
#include <sys/time.h>
#include <arpa/inet.h>
DNSServer::DNSServer(int port) : _port(port), _server_fd(-1), _epoll_fd(-1), _running(false) {}
DNSServer::~DNSServer(){ stop(); }
bool DNSServer::initSocket(){
    _server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    // create a UDP socket
    if (_server_fd < 0) {
        std::cerr << "[-] Error: Failed to create socket." << std::endl;
        return false;
    }
    // some non_blocking flags such that the port becomes non_blocking
    int flags = fcntl(_server_fd, F_GETFL, 0);
    if (fcntl(_server_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "[-] Error: Failed to set non-blocking flag." << std::endl;
        return false;
    }
    // initialise the struct for that port
    sockaddr_in addr{};
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(_port);
    // here you bind the socket to the port
    if (bind(_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[-] Error: Failed to bind to port " << _port << std::endl;
        return false;
    }
    std::cout << "[+] Socket bound successfully to port " << _port << std::endl;
    return true;
}
bool DNSServer::initEpoll(){
    // create epoll
    _epoll_fd = epoll_create1(0);
    if (_epoll_fd < 0) {
        std::cerr << "[-] Error: Failed to create epoll instance." << std::endl;
        return false;
    }
    // here i will add the server socket so that the epoll keeps track of it
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLET;// this is to tell the kernel when to trigger i.e first flag is to
    //                               tell when any socket is reading and second flag is edge-trigger mode
    ev.data.fd = _server_fd;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _server_fd, &ev) < 0) {
        std::cerr << "[-] Error: Failed to add socket to epoll control." << std::endl;
        return false;
    }
    return true;
}
int DNSServer::buildSinkholeResponse(const char* query_buffer, int query_len, char* response_buffer) {
    // this header file is made with the help of AI i dont know each and every specifications of the DNS packet
    // 1. Copy the entire original query (Header + Question) into our response buffer
    std::memcpy(response_buffer, query_buffer, query_len);
    
    // 2. Modify the Header
    DNSHeader* header = reinterpret_cast<DNSHeader*>(response_buffer);
    
    // Set Flags: 0x8180 (Standard Query Response, No Error)
    // htons() ensures the bytes are in Network Order (Big Endian)
    header->flags = htons(0x8180); 
    
    // Set Answer Count to 1
    header->ancount = htons(1);
    
    // 3. Append the Answer Record at the end of the query
    int offset = query_len;
    
    // Name: Compression pointer to byte offset 12 (0xC00C)
    response_buffer[offset++] = 0xC0;
    response_buffer[offset++] = 0x0C;
    
    // Type: A Record (IPv4) = 1 (0x0001)
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x01;
    
    // Class: IN (Internet) = 1 (0x0001)
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x01;
    
    // TTL: 600 seconds (0x00000258)
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x02;
    response_buffer[offset++] = 0x58;
    
    // Data Length: 4 bytes for an IPv4 address (0x0004)
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x04;
    
    // The IP Address: 0.0.0.0
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x00;
    response_buffer[offset++] = 0x00;
    
    return offset; // Return the new total packet size
}
int DNSServer::forwardToUpstream(const char* query_buffer, int query_len, char* response_buffer){
    int burner_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(burner_socket < 0){
        return -1;
    }
    struct timeval  tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(burner_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in upstream_addr{};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);

    if (inet_pton(AF_INET, "8.8.8.8", &upstream_addr.sin_addr) <= 0) {
        close(burner_socket);
        return -1;
    }

    int res = sendto(burner_socket, query_buffer, query_len, 0, (struct sockaddr *)(&upstream_addr), sizeof(upstream_addr));
    if(res < 0){
        close(burner_socket);
        return -1;
    }
    socklen_t upstream_len = sizeof(upstream_addr);
    int bytes_received = recvfrom(burner_socket, response_buffer, 4096, 0, (struct sockaddr*)&upstream_addr, &upstream_len);
    close(burner_socket);
    return bytes_received;
}
bool DNSServer::start(){
    if (!initSocket() || !initEpoll()) {
        return false;
    }
    _running = true;
    std::cout << "[+] DNS Server running. Waiting for events..." << std::endl;
    char buffer[4096];
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);


    // change this when doing final testing
    // _blocklist.loadFromFile("../data/blocklist.txt");
    std::string temp = "netflix.com";


    _blocklist.insert(temp);
    while(_running) {
        int num_events = epoll_wait(_epoll_fd, _events, MAX_EVENTS, -1);
        if (num_events < 0) {
            if (errno == EINTR) continue; // some system signal interruption
            std::cerr << "[-] Critical: epoll_wait failed." << std::endl;
            break;
        }
        for (int i = 0; i < num_events; i++) {
            if (_events[i].data.fd == _server_fd) {
                while (true) {
                    // edge triggered so we will drain completely
                    std::memset(buffer, 0, sizeof(buffer));
                    int bytes_read = (int)recvfrom(_server_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &client_len);
                    
                    if (bytes_read < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break; 
                        }
                        std::cerr << "[-] Error reading data from socket." << std::endl;
                        break;
                    }
                    std::cout << "[*] Intercepted raw DNS query! Size: " << bytes_read << " bytes." << std::endl;
                    DNSHeader* header = reinterpret_cast<DNSHeader*>(buffer);
                    int offset = sizeof(DNSHeader);
                    std::string domain = DNSParser::extractDomainName(buffer, offset);
                    std::cout << "[>>>] Ingress Request: " << domain << std::endl;
                    if(_blocklist.search(domain)){
                        std::cout << "[X] INTERCEPTED: ";
                        for(int i = domain.size() - 1;i>=0;i--){
                            std::cout<<domain[i];
                        }
                        std::cout << " resolved through sinkhole matrix." << std::endl;
                        char response_buffer[4096];
                        int response_len = buildSinkholeResponse(buffer, bytes_read, response_buffer);
                        
                        sendto(_server_fd, response_buffer, response_len, 0, 
                            (struct sockaddr*)&client_addr, client_len);
                    }else{
                        std::cout << "[V] PASS-THROUGH: " << domain << " forwading to Google's DNS Server." << std::endl;
                        /* 
                        * now what if this is a valid packet i cant just allow this packet to pass through 
                        * this packet needs to be handled by me so that it reaches the appropriate dns server for resolving
                        * or better i could just make a LRU cache and give it to him, but i cant allow the server to talk to 
                        * the dns server on the same port it needs to be done by a different port * 
                        */
                        char response_buffer[4096];
                        int response_len = forwardToUpstream(buffer, bytes_read, response_buffer);
                        if(response_len > 0){
                            // client --> My DNS Server(dalal) --> Google's DNS server 
                            int sent = sendto(_server_fd, response_buffer, response_len, 0, (struct sockaddr*)&client_addr, client_len);
                            if (sent < 0) {
                                std::cerr << "[-] Error sending upstream response to client." << std::endl;
                            }
                        }else{
                            std::cerr << "[-] Upstream timeout or network failure for " << domain << std::endl;
                        }
                    }
                }
            }
        }
    }
    return true;
}
void DNSServer::stop(){
    if (!_running) return;
    _running = false;
    if (_server_fd != -1) close(_server_fd);
    if (_epoll_fd != -1) close(_epoll_fd);
    std::cout << "[+] Server shutdown complete." << std::endl;
}