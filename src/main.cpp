#include "server.hpp"
#include "necessary.hpp"
#include <csignal>
DNSServer* global_server = nullptr;
// this handle_signal can only take one parameter some restrictions huh
// so now we cannot pass it if we are in stack memory so it has to be global
void handle_signal(int sig) {
    if (global_server != nullptr) {
        std::cout << "\n[!] Intercepted OS Signal " << sig << ". Initiating graceful shutdown..." << std::endl;
        global_server->stop();
    }
}
int main() {
    // testing on 5353
    DNSServer server(5353);
    global_server = &server;
    if (!server.start()) {
        std::cerr << "[-] Failed to start DNS Server." << std::endl;
        return 1;
    }
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    return 0;
}