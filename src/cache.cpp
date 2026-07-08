#include "cache.hpp"
LRUCache::LRUCache(int capacity){
    this->capacity = capacity;
}
void LRUCache::put(const std::string& domain, const char* response_buffer, int response_size, int query_size, int ttl_seconds){ 
    auto it = umpp.find(domain);
    if(it == umpp.end()){
        if(umpp.size() == capacity){
            umpp.erase(lru.back());
            lru.pop_back();
        }
        lru.push_front(domain);
        CacheEntry new_entry;
        new_entry.raw_response.assign(response_buffer, response_buffer + response_size);
        new_entry.og_query_size = query_size;
        new_entry.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(ttl_seconds);
        umpp[domain] = {lru.begin(), new_entry};
    }else{
        lru.splice(lru.begin(), lru, it->second.first);
        it->second.second.raw_response.assign(response_buffer, response_buffer + response_size);
        it->second.second.og_query_size = query_size;
        it->second.second.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(ttl_seconds);
    }
}
bool LRUCache::get(const std::string& domain, std::vector<char>&output_data, int &out_query_size){
    auto it = umpp.find(domain);
    if(it == umpp.end()){
        return false; // no data with me;
    }else{
        auto now = std::chrono::steady_clock::now();
        if(now > it->second.second.expires_at){
            lru.erase(it->second.first);
            umpp.erase(it);
            return false;
        }else{
            lru.splice(lru.begin(), lru, it->second.first);
            // this is some function of stl list 
            // somehow it automatically does the pointer magic will 
            // have to learn this properly
            output_data = it->second.second.raw_response;
            out_query_size = it->second.second.og_query_size;
        }
    }
    return true;
}