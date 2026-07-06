#include "radix_tree.hpp"
Vertex::Vertex(){
    std::fill(next, next + 38, -1);
}
void Trie::insert(std::string &word) {
    int v = 0;
    std::reverse(word.begin(), word.end());
    for(char c: word){
        int ind = charToIndex(c);
        if(ind == -1)return;
        if(trie[v].next[ind] == -1){
            trie[v].next[ind] = trie.size();
            trie.emplace_back();
        }
        v = trie[v].next[ind];
    }
    trie[v].output = true;
}
bool Trie::search(std::string &word) {
    int v = 0;
    std::reverse(word.begin(), word.end());
    for(char c: word){
        int index = charToIndex(c);
        if(index == -1)return false;
        if(index == -1)continue;
        if(trie[v].next[index] == -1)return false;
        if(trie[v].output)return true;
        v = trie[v].next[index];
    }
    return trie[v].output;
}
int Trie::charToIndex(char &c) {
    if (c >= 'A' && c <= 'Z') c += 32; 
    if (c >= 'a' && c <= 'z') return c - 'a';              // 0 to 25
    if (c >= '0' && c <= '9') return (c - '0') + 26;       // 26 to 35
    if (c == '-') return 36;                               // 36
    if (c == '.') return 37;
    return -1;
}
bool Trie::loadFromFile(const std::string &filepath){
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[-] Error: Failed to open blocklist file path: " << filepath << std::endl;
        return false;
    }
    std::string line;
    int count = 0;
    while(std::getline(file, line)){
        if(line.empty() || line[0] == '#')continue;
        std::istringstream iss(line);
        std::string ip, domain;
        iss>>ip>>domain;
        if(ip == "0.0.0.0" || ip == "127.0.0.1"){
            insert(domain);
            ++count;
        }
    }
    std::cout << "[+] Ingested " << count << " rules into memory-mapped array tree blocks." << std::endl;
    return true;
}