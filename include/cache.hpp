#pragma once
#include <list>
#include <chrono>
#include <unordered_map>
#include "necessary.hpp"
// now i dont plan to keep the server multithreaded but might in future
// if i get some time then i will modify this to be multithreaded
// so my locks and all will not be reqd
struct CacheEntry{
    std::vector<char> raw_response;
    int og_query_size;
    std::chrono::steady_clock::time_point expires_at;
};
class LRUCache{
    private:
        size_t capacity;
        std::list<std::string> lru;
        std::unordered_map<std::string, std::pair<std::list<std::string>::iterator, CacheEntry>>umpp;
    public:
        LRUCache(int capacity);
        // same logic as that leetcode question
        bool get(const std::string& domain, std::vector<char>&output_data, int &out_query_size);
        void put(const std::string& domain, const char* response_buffer, int response_size, int query_size, int ttl_seconds);
};