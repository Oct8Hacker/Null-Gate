#pragma once
#include "necessary.hpp"
#include <sys/epoll.h>
#include <netinet/in.h>
#include "radix_tree.hpp"
class DNSServer{
    private: 
        Trie _blocklist;
        int _port;
        int _server_fd;
        int _epoll_fd;
        bool _running;
        static constexpr int MAX_EVENTS = 64;
        epoll_event _events[MAX_EVENTS];
        bool initSocket();
        bool initEpoll();
    public:
        DNSServer(int port);
        ~DNSServer();
        bool start();
        void stop();
        int buildSinkholeResponse(const char* query_buffer, int query_len, char* response_buffer);
        int forwardToUpstream(const char* query_buffer, int query_len, char* response_buffer);
};