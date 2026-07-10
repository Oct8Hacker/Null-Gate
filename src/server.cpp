#include "server.hpp"
#include "dns_parser.hpp"
#include <sys/time.h>
#include <thread>
#include <arpa/inet.h>
DNSServer::DNSServer(int port) : _port(port), _server_fd(-1), _epoll_fd(-1), _running(false), _cache(1e4) {}
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
    int opt = 1;
    setsockopt(_server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    // initialise the struct for that port
    sockaddr_in addr{};
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(_port);
    // here you bind the socket to the port
    if (bind(_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // std::cerr << "[-] Error: Failed to bind to port " << _port << std::endl;
        perror("bind");
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
int DNSServer::buildSinkholeResponse(const char* query_buffer, int query_len, char* response_buffer, uint16_t qtype) {
    // 1. Copy the entire original query (Header + Question) into our response buffer
    std::memcpy(response_buffer, query_buffer, query_len);
    
    // 2. Modify the Header
    DNSHeader* header = reinterpret_cast<DNSHeader*>(response_buffer);
    header->flags = htons(0x8180); // Standard Query Response, No Error
    header->ancount = htons(1);    // 1 Answer Record
    header->arcount = 0;
    // 3. Append the Answer Record at the end of the query
    int offset = query_len;
    
    // Name: Compression pointer to byte offset 12 (0xC00C)
    response_buffer[offset++] = 0xC0;
    response_buffer[offset++] = 0x0C;
    
    if (qtype == 28) {
        // --- IPv6 (AAAA) RESPONSE ---
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x1C; // Type: 28 (0x001C)
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x01; // Class: IN
        
        // TTL: 600 seconds
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x00; 
        response_buffer[offset++] = 0x02; response_buffer[offset++] = 0x58; 
        
        // Data Length: 16 bytes for an IPv6 address
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x10; 
        
        // The IP Address: 16 bytes of zeros (::)
        for(int i = 0; i < 16; i++) {
            response_buffer[offset++] = 0x00;
        }
    } else {
        // --- IPv4 (A) RESPONSE (Default fallback) ---
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x01; // Type: 1 (0x0001)
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x01; // Class: IN
        
        // TTL: 600 seconds
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x00; 
        response_buffer[offset++] = 0x02; response_buffer[offset++] = 0x58; 
        
        // Data Length: 4 bytes for an IPv4 address
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x04; 
        
        // The IP Address: 0.0.0.0
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x00; 
        response_buffer[offset++] = 0x00; response_buffer[offset++] = 0x00;
    }
    
    return offset; 
}
int DNSServer::forwardToUpstream(const char* query_buffer, int query_len, char* response_buffer){
    int burner_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(burner_socket < 0){
        return -1;
    }
    struct timeval  tv;
    tv.tv_sec = 0;
    tv.tv_usec = 300000;
    setsockopt(burner_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in upstream_addr{};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);

    if (inet_pton(AF_INET, "1.1.1.1", &upstream_addr.sin_addr) <= 0) {
        close(burner_socket);
        return -1;
    }

    int res = sendto(burner_socket, query_buffer, query_len, 0, (struct sockaddr *)(&upstream_addr), sizeof(upstream_addr));
    if(res < 0){
        close(burner_socket);
        return -1;
    }
    socklen_t upstream_len = sizeof(upstream_addr);
    int bytes_received = recvfrom(burner_socket, response_buffer, 65536, 0, (struct sockaddr*)&upstream_addr, &upstream_len);
    // std::cout << "[DEBUG] Upstream returned "
    //       << bytes_received
    //       << " bytes\n";
    close(burner_socket);
    return bytes_received;
}
bool DNSServer::start(){
    if (!initSocket() || !initEpoll()) {
        return false;
    }
    _running = true;
    std::cout << "[+] DNS Server running. Waiting for events..." << std::endl;
    char buffer[65536];
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    _blocklist.loadFromFile("data/blocklist.txt");
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
                    //std::cout << "[*] Intercepted raw DNS query! Size: " << bytes_read << " bytes." << std::endl;
                    DNSHeader* header = reinterpret_cast<DNSHeader*>(buffer);
                    int offset = sizeof(DNSHeader);
                    std::string domain = DNSParser::extractDomainName(buffer, offset);
                    uint8_t* ubuffer = reinterpret_cast<uint8_t*>(buffer);
                    uint16_t q_type = (ubuffer[offset] << 8) | (ubuffer[offset + 1]); 
                    // std::cout << "TYPE = " << q_type << '\n';
                    int question_len = offset + 4;
                    if(_blocklist.search(domain)){
                        std::cout << "[X] INTERCEPTED: ";
                        for(int i = 0;i<domain.size();i++){
                            std::cout<<domain[i];
                        }
                        std::cout << " resolved through sinkhole matrix." << std::endl;
                        char response_buffer[65536];
                        int response_len = buildSinkholeResponse(buffer, question_len, response_buffer, q_type);
                        
                        sendto(_server_fd, response_buffer, response_len, 0, 
                            (struct sockaddr*)&client_addr, client_len);
                    }else{
                        /*
                        * so i will store the entire dns query by google in the cache resposne makes sense saves time*
                        * now what if this is a valid packet i cant just allow this packet to pass through 
                        * this packet needs to be handled by me so that it reaches the appropriate dns server for resolving
                        * or better i could just make a LRU cache and give it to him, but i cant allow the server to talk to 
                        * the dns server on the same port it needs to be done by a different port * 
                        */
                        std::string cache_key = domain + "|" + std::to_string(q_type);
                        std::vector<char> cached_response;
                        int cached_query_size = 0;
                        if(_cache.get(cache_key, cached_response, cached_query_size)){
                            // std::cout << "[*] CACHE HIT: " << domain << " (Type " << q_type << ") served from RAM." << std::endl;
                            
                            DNSHeader* cached_header = reinterpret_cast<DNSHeader*>(cached_response.data());
                            DNSHeader* client_header = reinterpret_cast<DNSHeader*>(buffer);
                            cached_header->id = client_header->id; 
                            
                            sendto(_server_fd, cached_response.data(), cached_response.size(), 0, 
                            (struct sockaddr*)&client_addr, client_len);
                        } else {
                            // [!] CACHE MISS: We need to ask 8.8.8.8
                            
                            // 1. The Semaphore Check (Admission Control)
                            if (_active_threads.load() >= MAX_CONCURRENT_THREADS) {
                                std::cerr << "[-] Traffic Spike: Max threads (" << MAX_CONCURRENT_THREADS 
                                        << ") reached. Dropping query for " << domain << " to prevent crash.\n";
                                continue; // Instantly skip this packet and go back to epoll_wait
                            }

                            // 2. Claim the slot
                            _active_threads++; 
                            
                            std::string query_str(buffer, bytes_read);
                            
                            try {
                                std::thread([this, query_str, cache_key, client_addr, client_len, bytes_read]() {
                                    char response_buffer[65536];
                                    
                                    // Do the heavy lifting over the network
                                    int response_len = forwardToUpstream(query_str.data(), query_str.size(), response_buffer);
                                    
                                    if (response_len > 0) {
                                        sendto(_server_fd, response_buffer, response_len, 0, 
                                            (struct sockaddr*)&client_addr, client_len);
                                        
                                        _cache.put(cache_key, response_buffer, response_len, bytes_read, 300);
                                    }
                                    
                                    // 3. Release the slot right before the thread dies
                                    _active_threads--; 
                                    
                                }).detach();
                                
                            } catch (const std::system_error& e) {
                                // If the OS still fails for some obscure memory reason, release the slot and survive
                                _active_threads--;
                                std::cerr << "[-] System error during thread spawn: " << e.what() << std::endl;
                            }
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