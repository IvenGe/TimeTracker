#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <string>
#include <sstream>
#include <thread>
#include <csignal>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <map>
#include <mutex>
#include <iomanip>
#include <algorithm>

// Platform specific includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <wtsapi32.h>
    #include <powrprof.h>
    #include <conio.h>
    #include <wincrypt.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "wtsapi32.lib")
    #pragma comment(lib, "powrprof.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "crypt32.lib")
    typedef int socklen_t;
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define CLOSE_SOCKET close
#endif

// Config structure
struct Config {
    std::string emailFrom;
    std::string emailTo;
    std::string smtpServer;
    std::string smtpPort;
    std::string smtpUsername;
    std::string smtpPassword;
    std::string logPath;
    std::string timeServer;
    std::string peerPort;
    std::string deviceName;
    std::vector<std::string> peers;
};

// Enhanced Block structure for blockchain with working hours
struct Block {
    int index;
    std::string timestamp;
    std::string deviceName;
    std::string status; // "STARTED", "WORKING", "LOCKED", "SLEEP", "STOPPED", "WORK_SESSION"
    std::string previousHash;
    std::string hash;
    int nonce;
    
    // New fields for working hours tracking
    std::string sessionId;     // Unique session identifier
    std::string startTime;     // Session start time
    std::string endTime;       // Session end time (empty if ongoing)
    int workedMinutes;         // Total minutes worked in this session
    std::string date;          // Date of work (YYYY-MM-DD)
    std::string reason;        // Reason for session end
};

// Work session structure for tracking
struct WorkSession {
    std::string sessionId;
    std::string startTime;
    std::string endTime;
    int totalMinutes;
    std::string reason;
};

// Daily work summary
struct DailyWorkSummary {
    std::string date;
    std::vector<WorkSession> sessions;
    int totalMinutes;
};

// Peer info structure
struct PeerInfo {
    std::string address;
    std::string deviceName;
    std::string status;
    std::string lastSeen;
    std::string startTime;
    std::string workedHours;
    std::string localTime;
    int timeDrift; // seconds difference from our time
    std::vector<std::string> knownPeers;
};

// Global variables
Config config;
std::chrono::system_clock::time_point startTime;
bool running = true;
time_t onlineStartTime = 0;
std::string sessionEndReason = "Gebruiker actie";
std::string currentSessionId = "";
std::vector<Block> blockchain;
std::map<std::string, PeerInfo> peerNetwork;
std::mutex blockchainMutex;
std::mutex peerMutex;
SOCKET peerServerSocket = INVALID_SOCKET;
std::thread peerServerThread;
std::thread peerClientThread;

// Forward declarations
std::string generateSessionId();
std::string getNTPTime();
std::string getOnlineTime();
time_t getOnlineTimestamp();
std::string getCurrentTimeString();
std::string getCurrentDateString();
std::string calculateWorkedHours();
std::string calculateHash(const Block& block);
bool isBlockValid(const Block& newBlock, const Block& previousBlock);
void broadcastBlock(const Block& block);
void startPeerServer();
void connectToPeers();
std::vector<DailyWorkSummary> extractWorkSummariesFromBlockchain();
void addWorkSessionBlock(const std::string& startTime, const std::string& endTime, int minutes, const std::string& reason);

// Generate unique session ID
std::string generateSessionId() {
    std::stringstream ss;
    ss << config.deviceName << "_" << std::time(nullptr) << "_" << rand();
    return ss.str();
}

// Get current date string (YYYY-MM-DD)
std::string getCurrentDateString() {
    std::string timeStr = getCurrentTimeString();
    if (timeStr.length() >= 10) {
        return timeStr.substr(0, 10);
    }
    return "1970-01-01";
}

// Function to read config file
Config readConfig(const std::string& filename) {
    Config cfg;
    std::ifstream file(filename);
    if (!file.is_open()) {
        // Create default config if not exists
        std::ofstream newFile(filename);
        newFile << "# Uren Registratie Tool Configuration\n";
        newFile << "email_from=your_email@example.com\n";
        newFile << "email_to=recipient@example.com\n";
        newFile << "smtp_server=smtp.gmail.com\n";
        newFile << "smtp_port=587\n";
        newFile << "smtp_username=your_email@example.com\n";
        newFile << "smtp_password=your_app_password\n";
        newFile << "log_path=work_hours.log\n";
        newFile << "time_server=worldtimeapi.org\n";
        newFile << "peer_port=8888\n";
        newFile << "device_name=Computer1\n";
        newFile << "# Add peer addresses below (one per line)\n";
        newFile << "# peer=192.168.1.100:8888\n";
        newFile << "# peer=192.168.1.101:8888\n";
        newFile.close();
        
        cfg.emailFrom = "your_email@example.com";
        cfg.emailTo = "recipient@example.com";
        cfg.smtpServer = "smtp.gmail.com";
        cfg.smtpPort = "587";
        cfg.smtpUsername = "your_email@example.com";
        cfg.smtpPassword = "your_app_password";
        cfg.logPath = "work_hours.log";
        cfg.timeServer = "worldtimeapi.org";
        cfg.peerPort = "8888";
        cfg.deviceName = "Computer1";
        
        std::cout << "Created default config.txt. Please edit it with your settings.\n";
        return cfg;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            if (key == "email_from") cfg.emailFrom = value;
            else if (key == "email_to") cfg.emailTo = value;
            else if (key == "smtp_server") cfg.smtpServer = value;
            else if (key == "smtp_port") cfg.smtpPort = value;
            else if (key == "smtp_username") cfg.smtpUsername = value;
            else if (key == "smtp_password") cfg.smtpPassword = value;
            else if (key == "log_path") cfg.logPath = value;
            else if (key == "time_server") cfg.timeServer = value;
            else if (key == "peer_port") cfg.peerPort = value;
            else if (key == "device_name") cfg.deviceName = value;
            else if (key == "peer") cfg.peers.push_back(value);
        }
    }
    file.close();
    return cfg;
}

// Simple hash function using Windows CryptoAPI on Windows, or a basic implementation for others
std::string sha256(const std::string& str) {
#ifdef _WIN32
    // Use Windows CryptoAPI
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 32;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // Fallback to simple hash
        std::hash<std::string> hasher;
        std::stringstream ss;
        ss << std::hex << hasher(str);
        return ss.str();
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        std::hash<std::string> hasher;
        std::stringstream ss;
        ss << std::hex << hasher(str);
        return ss.str();
    }
    
    CryptHashData(hHash, (BYTE*)str.c_str(), str.length(), 0);
    
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::stringstream ss;
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)rgbHash[i];
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return ss.str();
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
#endif
    
    // Fallback simple hash function for non-Windows or if CryptoAPI fails
    std::hash<std::string> hasher;
    std::stringstream ss;
    ss << std::hex << hasher(str);
    
    // Make it longer to simulate SHA256 length
    std::string result = ss.str();
    while (result.length() < 64) {
        result += result;
    }
    return result.substr(0, 64);
}

// Calculate hash for a block (enhanced for work sessions)
std::string calculateHash(const Block& block) {
    std::stringstream ss;
    ss << block.index << block.timestamp << block.deviceName 
       << block.status << block.previousHash << block.nonce
       << block.sessionId << block.startTime << block.endTime
       << block.workedMinutes << block.date << block.reason;
    return sha256(ss.str());
}

// Mine block (simple proof of work)
void mineBlock(Block& block, int difficulty = 2) {
    std::string target(difficulty, '0');
    while (block.hash.substr(0, difficulty) != target) {
        block.nonce++;
        block.hash = calculateHash(block);
    }
}

// Create genesis block
Block createGenesisBlock() {
    Block genesis;
    genesis.index = 0;
    genesis.timestamp = getCurrentTimeString();
    genesis.deviceName = "GENESIS";
    genesis.status = "CREATED";
    genesis.previousHash = "0";
    genesis.nonce = 0;
    genesis.sessionId = "";
    genesis.startTime = "";
    genesis.endTime = "";
    genesis.workedMinutes = 0;
    genesis.date = "";
    genesis.reason = "";
    genesis.hash = calculateHash(genesis);
    return genesis;
}

// Add work session block to blockchain
void addWorkSessionBlock(const std::string& startTime, const std::string& endTime, int minutes, const std::string& reason) {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    
    Block newBlock;
    newBlock.index = blockchain.size();
    newBlock.timestamp = getCurrentTimeString();
    newBlock.deviceName = config.deviceName;
    newBlock.status = "WORK_SESSION";
    newBlock.previousHash = blockchain.back().hash;
    newBlock.nonce = 0;
    
    // Work session specific data
    newBlock.sessionId = currentSessionId;
    newBlock.startTime = startTime;
    newBlock.endTime = endTime;
    newBlock.workedMinutes = minutes;
    newBlock.date = getCurrentDateString();
    newBlock.reason = reason;
    
    // Mine the block
    mineBlock(newBlock);
    
    blockchain.push_back(newBlock);
    
    // Broadcast to peers
    broadcastBlock(newBlock);
    
    std::cout << "Work session block added: " << minutes << " minutes on " << newBlock.date << "\n";
}

// Add status block to blockchain (original function, enhanced)
void addBlock(const std::string& status) {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    
    Block newBlock;
    newBlock.index = blockchain.size();
    newBlock.timestamp = getCurrentTimeString();
    newBlock.deviceName = config.deviceName;
    newBlock.status = status;
    newBlock.previousHash = blockchain.back().hash;
    newBlock.nonce = 0;
    
    // Initialize work session fields
    newBlock.sessionId = (status == "STARTED") ? currentSessionId : "";
    newBlock.startTime = (status == "STARTED") ? getCurrentTimeString() : "";
    newBlock.endTime = "";
    newBlock.workedMinutes = 0;
    newBlock.date = getCurrentDateString();
    newBlock.reason = "";
    
    // Mine the block
    mineBlock(newBlock);
    
    blockchain.push_back(newBlock);
    
    // Broadcast to peers
    broadcastBlock(newBlock);
}

// Serialize block to string (enhanced for work sessions)
std::string serializeBlock(const Block& block) {
    std::stringstream ss;
    ss << "BLOCK|" << block.index << "|" << block.timestamp << "|" 
       << block.deviceName << "|" << block.status << "|" 
       << block.previousHash << "|" << block.hash << "|" << block.nonce << "|"
       << block.sessionId << "|" << block.startTime << "|" << block.endTime << "|"
       << block.workedMinutes << "|" << block.date << "|" << block.reason;
    return ss.str();
}

// Deserialize block from string (enhanced for work sessions)
Block deserializeBlock(const std::string& data) {
    Block block;
    std::stringstream ss(data);
    std::string token;
    int field = 0;
    
    while (std::getline(ss, token, '|')) {
        switch(field) {
            case 0: break; // "BLOCK"
            case 1: block.index = std::stoi(token); break;
            case 2: block.timestamp = token; break;
            case 3: block.deviceName = token; break;
            case 4: block.status = token; break;
            case 5: block.previousHash = token; break;
            case 6: block.hash = token; break;
            case 7: block.nonce = std::stoi(token); break;
            case 8: block.sessionId = token; break;
            case 9: block.startTime = token; break;
            case 10: block.endTime = token; break;
            case 11: block.workedMinutes = (token.empty() ? 0 : std::stoi(token)); break;
            case 12: block.date = token; break;
            case 13: block.reason = token; break;
        }
        field++;
    }
    return block;
}

// Extract work summaries from blockchain
std::vector<DailyWorkSummary> extractWorkSummariesFromBlockchain() {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    std::map<std::string, DailyWorkSummary> summaryMap;
    
    for (const auto& block : blockchain) {
        if (block.status == "WORK_SESSION" && block.deviceName == config.deviceName) {
            WorkSession session;
            session.sessionId = block.sessionId;
            session.startTime = block.startTime;
            session.endTime = block.endTime;
            session.totalMinutes = block.workedMinutes;
            session.reason = block.reason;
            
            if (summaryMap.find(block.date) == summaryMap.end()) {
                summaryMap[block.date].date = block.date;
                summaryMap[block.date].totalMinutes = 0;
            }
            
            summaryMap[block.date].sessions.push_back(session);
            summaryMap[block.date].totalMinutes += block.workedMinutes;
        }
    }
    
    std::vector<DailyWorkSummary> summaries;
    for (const auto& pair : summaryMap) {
        summaries.push_back(pair.second);
    }
    
    // Sort by date
    std::sort(summaries.begin(), summaries.end(), 
              [](const DailyWorkSummary& a, const DailyWorkSummary& b) {
                  return a.date < b.date;
              });
    
    return summaries;
}

// Get peer status message
std::string getPeerStatusMessage() {
    std::stringstream ss;
    ss << "STATUS|" << config.deviceName << "|";
    
    if (running) {
        ss << "WORKING|" << getCurrentTimeString() << "|";
        ss << calculateWorkedHours() << "|";
        ss << getCurrentTimeString(); // Add local time for sync check
    } else {
        ss << "STOPPED|" << getCurrentTimeString() << "|0 uur en 0 minuten|";
        ss << getCurrentTimeString();
    }
    
    // Add our known peers
    ss << "|PEERS:";
    for (const auto& peer : config.peers) {
        ss << peer << ";";
    }
    
    return ss.str();
}

// Parse time string to timestamp
time_t parseTimeString(const std::string& timeStr) {
    struct tm tm = {0};
    if (sscanf(timeStr.c_str(), "%d-%d-%d %d:%d:%d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
        return mktime(&tm);
    }
    return 0;
}

// Discover new peers from known peers
void discoverPeers(const std::vector<std::string>& newPeers) {
    for (const auto& peerAddr : newPeers) {
        // Check if we already know this peer
        if (std::find(config.peers.begin(), config.peers.end(), peerAddr) == config.peers.end()) {
            // Check if it's not our own address
            if (peerAddr.find(":" + config.peerPort) == std::string::npos) {
                config.peers.push_back(peerAddr);
                std::cout << "Nieuwe peer ontdekt: " << peerAddr << "\n";
                
                // Save to config file
                std::ofstream configFile("config.txt", std::ios::app);
                if (configFile.is_open()) {
                    configFile << "peer=" << peerAddr << "\n";
                    configFile.close();
                }
            }
        }
    }
}

// Handle peer connection
void handlePeerConnection(SOCKET clientSocket) {
    char buffer[4096];
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (received > 0) {
        buffer[received] = '\0';
        std::string message(buffer);
        
        if (message.find("BLOCK|") == 0) {
            // Received new block
            Block newBlock = deserializeBlock(message);
            
            std::lock_guard<std::mutex> lock(blockchainMutex);
            if (isBlockValid(newBlock, blockchain.back())) {
                blockchain.push_back(newBlock);
                std::cout << "Nieuw block ontvangen van " << newBlock.deviceName 
                          << " - Status: " << newBlock.status;
                if (newBlock.status == "WORK_SESSION") {
                    std::cout << " - " << newBlock.workedMinutes << " minuten gewerkt";
                }
                std::cout << "\n";
            }
        }
        else if (message.find("STATUS|") == 0) {
            // Parse status message
            std::stringstream ss(message);
            std::string token;
            std::vector<std::string> parts;
            
            while (std::getline(ss, token, '|')) {
                parts.push_back(token);
            }
            
            if (parts.size() >= 6) {
                std::lock_guard<std::mutex> lock(peerMutex);
                PeerInfo& peer = peerNetwork[parts[1]];
                peer.deviceName = parts[1];
                peer.status = parts[2];
                peer.lastSeen = parts[3];
                peer.workedHours = parts[4];
                peer.localTime = parts[5];
                
                // Calculate time drift
                time_t ourTime = getOnlineTimestamp();
                time_t peerTime = parseTimeString(parts[5]);
                peer.timeDrift = abs(ourTime - peerTime);
                
                // Check for suspicious time drift (more than 5 minutes)
                if (peer.timeDrift > 300) {
                    std::cout << "WAARSCHUWING: " << peer.deviceName 
                              << " heeft een tijdverschil van " << peer.timeDrift 
                              << " seconden!\n";
                }
                
                // Parse known peers if available
                if (parts.size() > 6 && parts[6].find("PEERS:") == 0) {
                    std::string peersStr = parts[6].substr(6);
                    std::stringstream peerStream(peersStr);
                    std::string peerAddr;
                    std::vector<std::string> discoveredPeers;
                    
                    while (std::getline(peerStream, peerAddr, ';')) {
                        if (!peerAddr.empty()) {
                            peer.knownPeers.push_back(peerAddr);
                            discoveredPeers.push_back(peerAddr);
                        }
                    }
                    
                    // Discover new peers
                    discoverPeers(discoveredPeers);
                }
            }
            
            // Send our status back
            std::string response = getPeerStatusMessage();
            send(clientSocket, response.c_str(), response.length(), 0);
        }
        else if (message == "GETCHAIN") {
            // Send entire blockchain
            std::lock_guard<std::mutex> lock(blockchainMutex);
            for (const auto& block : blockchain) {
                std::string blockData = serializeBlock(block) + "\n";
                send(clientSocket, blockData.c_str(), blockData.length(), 0);
            }
        }
        else if (message == "TIMECHECK") {
            // Send our current time for synchronization check
            std::string timeResponse = "TIME|" + getCurrentTimeString() + "|" + config.deviceName;
            send(clientSocket, timeResponse.c_str(), timeResponse.length(), 0);
        }
    }
    
    CLOSE_SOCKET(clientSocket);
}

// Start peer server
void startPeerServer() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    
    peerServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (peerServerSocket == INVALID_SOCKET) return;
    
    // Allow socket reuse
    int opt = 1;
    setsockopt(peerServerSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(std::stoi(config.peerPort));
    
    if (bind(peerServerSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        CLOSE_SOCKET(peerServerSocket);
        return;
    }
    
    listen(peerServerSocket, 10);
    
    std::cout << "P2P server gestart op poort " << config.peerPort << "\n";
    
    while (running) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(peerServerSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket != INVALID_SOCKET) {
            std::thread clientThread(handlePeerConnection, clientSocket);
            clientThread.detach();
        }
    }
}

// Connect to peers periodically
void connectToPeers() {
    while (running) {
        for (const auto& peerAddr : config.peers) {
            size_t colonPos = peerAddr.find(':');
            if (colonPos == std::string::npos) continue;
            
            std::string host = peerAddr.substr(0, colonPos);
            std::string port = peerAddr.substr(colonPos + 1);
            
#ifdef _WIN32
            WSADATA wsaData;
            WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
            
            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) continue;
            
            struct sockaddr_in peerSockAddr;
            peerSockAddr.sin_family = AF_INET;
            peerSockAddr.sin_port = htons(std::stoi(port));
            inet_pton(AF_INET, host.c_str(), &peerSockAddr.sin_addr);
            
            if (connect(sock, (struct sockaddr*)&peerSockAddr, sizeof(peerSockAddr)) == 0) {
                // Send status request
                std::string message = getPeerStatusMessage();
                send(sock, message.c_str(), message.length(), 0);
                
                // Receive response
                char buffer[4096];
                int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Process response (similar to handlePeerConnection)
                }
            }
            
            CLOSE_SOCKET(sock);
#ifdef _WIN32
            WSACleanup();
#endif
        }
        
        // Wait 30 seconds before next update
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

// Broadcast block to all peers
void broadcastBlock(const Block& block) {
    std::string blockData = serializeBlock(block);
    
    for (const auto& peerAddr : config.peers) {
        size_t colonPos = peerAddr.find(':');
        if (colonPos == std::string::npos) continue;
        
        std::string host = peerAddr.substr(0, colonPos);
        std::string port = peerAddr.substr(colonPos + 1);
        
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
        
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) continue;
        
        struct sockaddr_in peerSockAddr;
        peerSockAddr.sin_family = AF_INET;
        peerSockAddr.sin_port = htons(std::stoi(port));
        inet_pton(AF_INET, host.c_str(), &peerSockAddr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&peerSockAddr, sizeof(peerSockAddr)) == 0) {
            send(sock, blockData.c_str(), blockData.length(), 0);
        }
        
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
    }
}

// Check if block is valid (enhanced for work sessions)
bool isBlockValid(const Block& newBlock, const Block& previousBlock) {
    if (previousBlock.index + 1 != newBlock.index) return false;
    if (previousBlock.hash != newBlock.previousHash) return false;
    if (calculateHash(newBlock) != newBlock.hash) return false;
    
    // Additional validation for work session blocks
    if (newBlock.status == "WORK_SESSION") {
        if (newBlock.workedMinutes < 0 || newBlock.workedMinutes > 1440) return false; // Max 24 hours
        if (newBlock.startTime.empty() || newBlock.endTime.empty()) return false;
    }
    
    return true;
}

// Show work history from blockchain
void showWorkHistory() {
    std::cout << "\n=== WERKUREN GESCHIEDENIS (uit blockchain) ===\n";
    
    std::vector<DailyWorkSummary> summaries = extractWorkSummariesFromBlockchain();
    
    if (summaries.empty()) {
        std::cout << "Geen werkuren gevonden in de blockchain.\n";
    } else {
        int totalMinutesAllTime = 0;
        
        for (const auto& summary : summaries) {
            std::cout << "\nDatum: " << summary.date << "\n";
            std::cout << "Totaal gewerkt: " << (summary.totalMinutes / 60) << " uur en " 
                      << (summary.totalMinutes % 60) << " minuten\n";
            std::cout << "Sessies: " << summary.sessions.size() << "\n";
            
            for (size_t i = 0; i < summary.sessions.size(); i++) {
                const auto& session = summary.sessions[i];
                std::cout << "  " << (i+1) << ". " << session.startTime.substr(11, 8) 
                          << " - " << session.endTime.substr(11, 8)
                          << " (" << session.totalMinutes << " min) - " 
                          << session.reason << "\n";
            }
            
            totalMinutesAllTime += summary.totalMinutes;
        }
        
        std::cout << "\nTotaal alle dagen: " << (totalMinutesAllTime / 60) << " uur en " 
                  << (totalMinutesAllTime % 60) << " minuten\n";
    }
    
    std::cout << "============================================\n\n";
}

// Show peer network status (enhanced with work hours)
void showPeerStatus() {
    std::lock_guard<std::mutex> lock(peerMutex);
    
    std::cout << "\n=== NETWERK STATUS ===\n";
    std::cout << "Eigen apparaat: " << config.deviceName << " - Status: WORKING\n";
    std::cout << "Gewerkte tijd: " << calculateWorkedHours() << "\n";
    std::cout << "Online tijd: " << getCurrentTimeString() << "\n\n";
    
    int suspiciousPeers = 0;
    for (const auto& pair : peerNetwork) {
        const PeerInfo& peer = pair.second;
        std::cout << "Apparaat: " << peer.deviceName << "\n";
        std::cout << "  Status: " << peer.status << "\n";
        std::cout << "  Laatste contact: " << peer.lastSeen << "\n";
        std::cout << "  Gewerkte tijd: " << peer.workedHours << "\n";
        std::cout << "  Tijd synchronisatie: ";
        
        if (peer.timeDrift <= 60) {
            std::cout << "OK (drift: " << peer.timeDrift << "s)\n";
        } else if (peer.timeDrift <= 300) {
            std::cout << "WAARSCHUWING (drift: " << peer.timeDrift << "s)\n";
        } else {
            std::cout << "VERDACHT! (drift: " << peer.timeDrift << "s)\n";
            suspiciousPeers++;
        }
        
        std::cout << "  Bekende peers: " << peer.knownPeers.size() << "\n\n";
    }
    
    std::cout << "Totaal aantal peers: " << config.peers.size() << "\n";
    std::cout << "Actieve verbindingen: " << peerNetwork.size() << "\n";
    if (suspiciousPeers > 0) {
        std::cout << "WAARSCHUWING: " << suspiciousPeers << " peers met verdachte tijdinstellingen!\n";
    }
    std::cout << "Blockchain lengte: " << blockchain.size() << " blocks\n";
    
    // Show today's work from blockchain
    std::string today = getCurrentDateString();
    int todayMinutes = 0;
    int workSessionCount = 0;
    
    {
        std::lock_guard<std::mutex> blockLock(blockchainMutex);
        for (const auto& block : blockchain) {
            if (block.status == "WORK_SESSION" && block.date == today && block.deviceName == config.deviceName) {
                todayMinutes += block.workedMinutes;
                workSessionCount++;
            }
        }
    }
    
    std::cout << "Vandaag gewerkt (blockchain): " << (todayMinutes / 60) << " uur en " 
              << (todayMinutes % 60) << " minuten in " << workSessionCount << " sessies\n";
    std::cout << "=====================\n\n";
}

// Perform time synchronization check with all peers
void performTimeSync() {
    std::cout << "\nTijd synchronisatie controle gestart...\n";
    std::map<std::string, int> timeDrifts;
    
    for (const auto& peerAddr : config.peers) {
        size_t colonPos = peerAddr.find(':');
        if (colonPos == std::string::npos) continue;
        
        std::string host = peerAddr.substr(0, colonPos);
        std::string port = peerAddr.substr(colonPos + 1);
        
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
        
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) continue;
        
        // Set timeout
#ifdef _WIN32
        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif
        
        struct sockaddr_in peerSockAddr;
        peerSockAddr.sin_family = AF_INET;
        peerSockAddr.sin_port = htons(std::stoi(port));
        inet_pton(AF_INET, host.c_str(), &peerSockAddr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&peerSockAddr, sizeof(peerSockAddr)) == 0) {
            // Send time check request
            std::string message = "TIMECHECK";
            send(sock, message.c_str(), message.length(), 0);
            
            // Receive response
            char buffer[4096];
            int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (received > 0) {
                buffer[received] = '\0';
                std::string response(buffer);
                
                if (response.find("TIME|") == 0) {
                    std::stringstream ss(response);
                    std::string token;
                    std::vector<std::string> parts;
                    
                    while (std::getline(ss, token, '|')) {
                        parts.push_back(token);
                    }
                    
                    if (parts.size() >= 3) {
                        time_t ourTime = getOnlineTimestamp();
                        time_t peerTime = parseTimeString(parts[1]);
                        int drift = abs(ourTime - peerTime);
                        timeDrifts[parts[2]] = drift;
                    }
                }
            }
        }
        
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    // Analyze results
    if (!timeDrifts.empty()) {
        std::cout << "\nTijd synchronisatie resultaten:\n";
        int maxDrift = 0;
        for (const auto& pair : timeDrifts) {
            std::cout << "  " << pair.first << ": ";
            if (pair.second <= 60) {
                std::cout << "OK (drift: " << pair.second << "s)\n";
            } else if (pair.second <= 300) {
                std::cout << "Waarschuwing (drift: " << pair.second << "s)\n";
            } else {
                std::cout << "VERDACHT! (drift: " << pair.second << "s)\n";
            }
            maxDrift = std::max(maxDrift, pair.second);
        }
        
        if (maxDrift > 300) {
            std::cout << "\nWAARSCHUWING: Een of meer peers hebben verdachte tijdinstellingen!\n";
            std::cout << "Dit kan duiden op manipulatie van werkuren.\n";
        }
    }
}

// Get time from NTP server
std::string getNTPTime() {
    const char* ntpServer = "pool.ntp.org";
    const int NTP_PORT = 123;
    const int NTP_PACKET_SIZE = 48;
    
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "";
    }
#endif
    
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }
    
    // Set timeout
#ifdef _WIN32
    DWORD timeout = 5000; // 5 seconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif
    
    struct hostent* host = gethostbyname(ntpServer);
    if (!host) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(NTP_PORT);
    memcpy(&serverAddr.sin_addr, host->h_addr_list[0], host->h_length);
    
    // Create NTP request packet
    unsigned char packet[NTP_PACKET_SIZE] = {0};
    packet[0] = 0x1B; // NTP version 3, client mode
    
    // Send request
    if (sendto(sock, (char*)packet, NTP_PACKET_SIZE, 0, 
               (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }
    
    // Receive response
    socklen_t addrLen = sizeof(serverAddr);
    int received = recvfrom(sock, (char*)packet, NTP_PACKET_SIZE, 0,
                           (struct sockaddr*)&serverAddr, &addrLen);
    
    CLOSE_SOCKET(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    
    if (received < NTP_PACKET_SIZE) {
        return "";
    }
    
    // Extract timestamp (seconds since 1900)
    unsigned long seconds = ntohl(*((unsigned long*)&packet[40]));
    
    // Convert to Unix timestamp (seconds since 1970)
    const unsigned long SEVENTY_YEARS = 2208988800UL;
    time_t unixTime = seconds - SEVENTY_YEARS;
    
    // Convert to string
    char buffer[100];
    struct tm* timeinfo = localtime(&unixTime);
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    return std::string(buffer);
}

// Get current time from online source
std::string getOnlineTime() {
    std::string timeStr = "";
    
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "";
    }
#endif
    
    // Try worldtimeapi.org first
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }
    
    struct hostent* host = gethostbyname("worldtimeapi.org");
    if (!host) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    memcpy(&serverAddr.sin_addr, host->h_addr_list[0], host->h_length);
    
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }
    
    // Send HTTP GET request
    std::string request = "GET /api/timezone/Europe/Amsterdam HTTP/1.1\r\n";
    request += "Host: worldtimeapi.org\r\n";
    request += "Connection: close\r\n\r\n";
    
    send(sock, request.c_str(), request.length(), 0);
    
    // Read response
    char buffer[4096];
    std::string response;
    int bytesReceived;
    
    while ((bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        response += buffer;
    }
    
    CLOSE_SOCKET(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    
    // Parse JSON response for datetime
    size_t datetimePos = response.find("\"datetime\":\"");
    if (datetimePos != std::string::npos) {
        datetimePos += 12;
        size_t endPos = response.find("\"", datetimePos);
        if (endPos != std::string::npos) {
            timeStr = response.substr(datetimePos, endPos - datetimePos);
            // Convert ISO format to readable format
            if (timeStr.length() >= 19) {
                timeStr = timeStr.substr(0, 10) + " " + timeStr.substr(11, 8);
            }
        }
    }
    
    // Fallback to NTP if HTTP fails
    if (timeStr.empty()) {
        timeStr = getNTPTime();
    }
    
    // Final fallback to system time
    if (timeStr.empty()) {
        auto now = std::chrono::system_clock::now();
        std::time_t tt = std::chrono::system_clock::to_time_t(now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
        timeStr = std::string(buffer) + " (lokale tijd - online tijd niet beschikbaar)";
    }
    
    return timeStr;
}

// Get current time as string (with online fallback)
std::string getCurrentTimeString() {
    return getOnlineTime();
}

// Get unix timestamp from online source
time_t getOnlineTimestamp() {
    // Try to parse timestamp from online time
    std::string onlineTime = getOnlineTime();
    
    if (!onlineTime.empty() && onlineTime.find("lokale tijd") == std::string::npos) {
        // Parse the datetime string (format: YYYY-MM-DD HH:MM:SS)
        struct tm tm = {0};
        if (sscanf(onlineTime.c_str(), "%d-%d-%d %d:%d:%d",
                   &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                   &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;
            return mktime(&tm);
        }
    }
    
    // Fallback to system time
    return time(nullptr);
}

// Base64 encode function for SMTP authentication
std::string base64_encode(const std::string& str) {
    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    const unsigned char* bytes = (const unsigned char*)str.c_str();
    size_t len = str.length();

    while (len--) {
        char_array_3[i++] = *(bytes++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

// Send email via SMTP directly
bool sendEmailDirect(const std::string& subject, const std::string& body) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
#endif

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    struct hostent* host = gethostbyname(config.smtpServer.c_str());
    if (!host) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(std::stoi(config.smtpPort));
    memcpy(&serverAddr.sin_addr, host->h_addr_list[0], host->h_length);

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    char buffer[1024];
    
    // Read greeting
    recv(sock, buffer, sizeof(buffer), 0);
    
    // HELO
    std::string cmd = "HELO localhost\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // AUTH LOGIN
    cmd = "AUTH LOGIN\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Username
    cmd = base64_encode(config.smtpUsername) + "\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Password
    cmd = base64_encode(config.smtpPassword) + "\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // MAIL FROM
    cmd = "MAIL FROM:<" + config.emailFrom + ">\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // RCPT TO
    cmd = "RCPT TO:<" + config.emailTo + ">\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // DATA
    cmd = "DATA\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Email content
    std::stringstream email;
    email << "From: " << config.emailFrom << "\r\n";
    email << "To: " << config.emailTo << "\r\n";
    email << "Subject: " << subject << "\r\n";
    email << "Content-Type: text/plain; charset=UTF-8\r\n";
    email << "\r\n";
    email << body << "\r\n";
    email << ".\r\n";
    
    send(sock, email.str().c_str(), email.str().length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // QUIT
    cmd = "QUIT\r\n";
    send(sock, cmd.c_str(), cmd.length(), 0);
    
    CLOSE_SOCKET(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return true;
}

// Alternative: Create PowerShell script for email (Windows only)
void sendEmailViaScript(const std::string& subject, const std::string& body) {
    // First try direct SMTP
    if (sendEmailDirect(subject, body)) {
        std::cout << "Email verzonden via directe SMTP verbinding\n";
        return;
    }
    
#ifdef _WIN32
    // Fallback to PowerShell on Windows
    std::string scriptFile = "send_email.ps1";
    std::ofstream script(scriptFile);
    if (script.is_open()) {
        script << "$EmailFrom = \"" << config.emailFrom << "\"\n";
        script << "$EmailTo = \"" << config.emailTo << "\"\n";
        script << "$Subject = \"" << subject << "\"\n";
        script << "$Body = @\"\n" << body << "\n\"@\n";
        script << "$SMTPServer = \"" << config.smtpServer << "\"\n";
        script << "$SMTPPort = " << config.smtpPort << "\n";
        script << "$SMTPClient = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)\n";
        script << "$SMTPClient.EnableSsl = $true\n";
        script << "$SMTPClient.Credentials = New-Object System.Net.NetworkCredential(\"" 
               << config.smtpUsername << "\", \"" << config.smtpPassword << "\")\n";
        script << "try {\n";
        script << "    $SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)\n";
        script << "    Write-Host \"Email sent successfully\"\n";
        script << "} catch {\n";
        script << "    Write-Host \"Failed to send email: $_\"\n";
        script << "}\n";
        script.close();
        
        // Execute PowerShell script
        std::string command = "powershell.exe -ExecutionPolicy Bypass -File " + scriptFile;
        system(command.c_str());
        
        // Delete script file
        std::remove(scriptFile.c_str());
    }
#else
    std::cout << "Email kon niet worden verzonden\n";
#endif
}

// Calculate worked hours
std::string calculateWorkedHours() {
    time_t currentTime = getOnlineTimestamp();
    time_t duration = currentTime - onlineStartTime;
    
    int hours = duration / 3600;
    int minutes = (duration % 3600) / 60;
    
    std::stringstream ss;
    ss << hours << " uur en " << minutes << " minuten";
    return ss.str();
}

// Save work session to log
void saveWorkSession(const std::string& startTimeStr, const std::string& endTimeStr, const std::string& duration) {
    std::ofstream logFile(config.logPath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "Datum: " << startTimeStr.substr(0, 10) << " | ";
        logFile << "Start: " << startTimeStr.substr(11) << " | ";
        logFile << "Einde: " << endTimeStr.substr(11) << " | ";
        logFile << "Duur: " << duration << " | ";
        logFile << "Apparaat: " << config.deviceName << "\n";
        logFile.close();
    }
}

// Function to handle cleanup and exit
void cleanup() {
    if (!running) return; // Prevent double cleanup
    running = false;
    
    // Get end time and calculate minutes
    std::string endTimeStr = getCurrentTimeString();
    time_t currentTime = getOnlineTimestamp();
    int workedMinutes = (currentTime - onlineStartTime) / 60;
    
    // Get start time as string
    char startBuffer[100];
    struct tm* timeinfo = localtime(&onlineStartTime);
    std::strftime(startBuffer, sizeof(startBuffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    std::string startTimeStr(startBuffer);
    
    // Add work session block to blockchain
    addWorkSessionBlock(startTimeStr, endTimeStr, workedMinutes, sessionEndReason);
    
    // Add final status block
    addBlock("STOPPED");
    
    // Save to traditional log as well
    std::string duration = calculateWorkedHours();
    saveWorkSession(startTimeStr, endTimeStr, duration);
    
    // Prepare email content with blockchain work summary
    std::string subject = "Werkuren rapport - " + endTimeStr.substr(0, 10);
    std::stringstream bodyStream;
    bodyStream << "Werkuren rapport voor " << config.deviceName << ":\n\n";
    bodyStream << "=== HUIDIGE SESSIE ===\n";
    bodyStream << "Start tijd: " << startTimeStr << " (online tijd)\n";
    bodyStream << "Eind tijd: " << endTimeStr << "\n";
    bodyStream << "Totale werktijd: " << duration << " (" << workedMinutes << " minuten)\n";
    bodyStream << "Sessie beëindigd door: " << sessionEndReason << "\n\n";
    
    // Add work history from blockchain
    bodyStream << "=== WERKUREN GESCHIEDENIS (BLOCKCHAIN) ===\n";
    std::vector<DailyWorkSummary> summaries = extractWorkSummariesFromBlockchain();
    
    // Show last 7 days
    int daysToShow = 7;
    int startIdx = std::max(0, (int)summaries.size() - daysToShow);
    
    for (int i = startIdx; i < summaries.size(); i++) {
        const auto& summary = summaries[i];
        bodyStream << "\n" << summary.date << ": " 
                   << (summary.totalMinutes / 60) << " uur " 
                   << (summary.totalMinutes % 60) << " min";
        if (summary.date == getCurrentDateString()) {
            bodyStream << " (vandaag)";
        }
        bodyStream << "\n";
    }
    
    // Calculate weekly total
    int weeklyMinutes = 0;
    for (int i = std::max(0, (int)summaries.size() - 7); i < summaries.size(); i++) {
        weeklyMinutes += summaries[i].totalMinutes;
    }
    bodyStream << "\nTotaal deze week: " << (weeklyMinutes / 60) << " uur en " 
               << (weeklyMinutes % 60) << " minuten\n\n";
    
    // Add network status
    bodyStream << "=== NETWERK STATUS ===\n";
    {
        std::lock_guard<std::mutex> lock(peerMutex);
        int suspiciousPeers = 0;
        for (const auto& pair : peerNetwork) {
            const PeerInfo& peer = pair.second;
            bodyStream << "Apparaat: " << peer.deviceName << " - Status: " << peer.status 
                      << " - Gewerkt: " << peer.workedHours;
            
            if (peer.timeDrift > 300) {
                bodyStream << " [VERDACHTE TIJD!]";
                suspiciousPeers++;
            }
            bodyStream << "\n";
        }
        
        if (suspiciousPeers > 0) {
            bodyStream << "\nWAARSCHUWING: " << suspiciousPeers 
                      << " apparaten met verdachte tijdinstellingen gedetecteerd!\n";
        }
    }
    bodyStream << "\nTotaal peers in netwerk: " << config.peers.size() << "\n";
    bodyStream << "Blockchain blocks: " << blockchain.size() << "\n";
    bodyStream << "\nDit is een automatisch gegenereerd rapport met blockchain verificatie.";
    
    // Send email
    std::cout << "\nVerstuurt email rapport met werkuren uit blockchain...\n";
    sendEmailViaScript(subject, bodyStream.str());
    
    std::cout << "Werkuren opgeslagen in blockchain: " << workedMinutes << " minuten\n";
    
    // Stop peer threads
    if (peerServerSocket != INVALID_SOCKET) {
        CLOSE_SOCKET(peerServerSocket);
    }
}

// Signal handler
void signalHandler(int signum) {
    cleanup();
    exit(0);
}

#ifdef _WIN32
// Windows console handler
BOOL WINAPI ConsoleHandler(DWORD dwType) {
    switch (dwType) {
    case CTRL_C_EVENT:
        sessionEndReason = "Ctrl+C gedrukt";
        break;
    case CTRL_CLOSE_EVENT:
        sessionEndReason = "Console venster gesloten";
        break;
    case CTRL_LOGOFF_EVENT:
        sessionEndReason = "Windows uitloggen";
        break;
    case CTRL_SHUTDOWN_EVENT:
        sessionEndReason = "Windows afsluiten";
        break;
    }
    cleanup();
    return TRUE;
}

// Windows message handler for lock/sleep events
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_POWERBROADCAST:
        switch (wParam) {
        case PBT_APMSUSPEND:
            // System is suspending (sleep/hibernate)
            sessionEndReason = "Computer slaapstand";
            addBlock("SLEEP");
            std::cout << "\nSysteem gaat in slaapstand - werk sessie wordt beëindigd...\n";
            cleanup();
            break;
        case PBT_APMRESUMESUSPEND:
            // System is resuming from sleep
            std::cout << "\nSysteem ontwaakt uit slaapstand - start nieuwe werk sessie...\n";
            onlineStartTime = getOnlineTimestamp();
            currentSessionId = generateSessionId();
            sessionEndReason = "Gebruiker actie";
            addBlock("RESUMED");
            break;
        }
        break;
    
    case WM_WTSSESSION_CHANGE:
        switch (wParam) {
        case WTS_SESSION_LOCK:
            // Workstation is locked - save work session
            {
                std::string endTimeStr = getCurrentTimeString();
                time_t currentTime = getOnlineTimestamp();
                int workedMinutes = (currentTime - onlineStartTime) / 60;
                
                char startBuffer[100];
                struct tm* timeinfo = localtime(&onlineStartTime);
                std::strftime(startBuffer, sizeof(startBuffer), "%Y-%m-%d %H:%M:%S", timeinfo);
                std::string startTimeStr(startBuffer);
                
                sessionEndReason = "Werkstation vergrendeld (Win+L)";
                addWorkSessionBlock(startTimeStr, endTimeStr, workedMinutes, sessionEndReason);
                addBlock("LOCKED");
                std::cout << "\nWerkstation vergrendeld - werk sessie opgeslagen in blockchain...\n";
            }
            break;
        case WTS_SESSION_UNLOCK:
            // Workstation is unlocked - start new session
            std::cout << "\nWerkstation ontgrendeld - start nieuwe werk sessie...\n";
            onlineStartTime = getOnlineTimestamp();
            currentSessionId = generateSessionId();
            sessionEndReason = "Gebruiker actie";
            addBlock("UNLOCKED");
            break;
        }
        break;
        
    case WM_QUERYENDSESSION:
        // Windows is shutting down or user is logging off
        sessionEndReason = "Windows afsluiten/uitloggen";
        std::cout << "\nWindows wordt afgesloten - werk sessie wordt beëindigd...\n";
        cleanup();
        return TRUE;
        
    case WM_ENDSESSION:
        if (wParam) {
            cleanup();
        }
        break;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Thread function to handle Windows messages
DWORD WINAPI MessageThread(LPVOID lpParam) {
    // Create invisible window to receive messages
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "UrenRegistratieClass";
    
    if (!RegisterClass(&wc)) {
        return 1;
    }
    
    HWND hwnd = CreateWindow(
        "UrenRegistratieClass",
        "Uren Registratie",
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwnd) {
        return 1;
    }
    
    // Register for session change notifications
    WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    WTSUnRegisterSessionNotification(hwnd);
    return 0;
}
#endif

int main() {
    // Read configuration
    config = readConfig("config.txt");
    
    std::cout << "Uren registratie tool - P2P Blockchain versie\n";
    std::cout << "=============================================\n";
    std::cout << "Apparaat naam: " << config.deviceName << "\n";
    std::cout << "Ophalen van online tijd...\n";
    
    // Initialize blockchain with genesis block
    blockchain.push_back(createGenesisBlock());
    
    // Generate session ID for this work session
    currentSessionId = generateSessionId();
    
    // Get start time from online source
    std::string startTimeStr = getCurrentTimeString();
    onlineStartTime = getOnlineTimestamp();
    
    if (startTimeStr.find("lokale tijd") != std::string::npos) {
        std::cout << "WAARSCHUWING: Kon geen online tijd ophalen, gebruikt lokale tijd als fallback.\n";
    }
    
    // Add start block to blockchain
    addBlock("STARTED");
    
    std::cout << "Uren registratie gestart om: " << startTimeStr << std::endl;
    std::cout << "Sessie ID: " << currentSessionId << std::endl;
    std::cout << "Configuratie geladen uit config.txt\n";
    std::cout << "\nHet programma registreert automatisch werkuren in blockchain bij:\n";
    std::cout << "- Afsluiten van het programma (Ctrl+C)\n";
    std::cout << "- Windows afsluiten of uitloggen\n";
    std::cout << "- Computer vergrendelen (Win+L)\n";
    std::cout << "- Slaapstand of hibernatie\n";
    std::cout << "\nP2P netwerk gestart - verbonden met " << config.peers.size() << " peers\n";
    std::cout << "Commands:\n";
    std::cout << "  'S' - Toon netwerk status\n";
    std::cout << "  'T' - Voer tijd synchronisatie controle uit\n";
    std::cout << "  'P' - Toon alle bekende peers\n";
    std::cout << "  'H' - Toon werkuren geschiedenis uit blockchain\n";
    std::cout << "  'B' - Toon blockchain info\n\n";
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    
    // Create thread for Windows message handling
    HANDLE hThread = CreateThread(NULL, 0, MessageThread, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Kon Windows message handler niet starten\n";
    }
#endif
    
    // Start P2P threads
    peerServerThread = std::thread(startPeerServer);
    peerClientThread = std::thread(connectToPeers);
    
    // Main loop
    int hourCounter = 0;
    auto lastStatusTime = std::chrono::steady_clock::now();
    auto lastSaveTime = std::chrono::steady_clock::now();
    
    while (running) {
        // Check for user input (non-blocking on Windows)
#ifdef _WIN32
        if (_kbhit()) {
            char key = _getch();
            if (key == 's' || key == 'S') {
                showPeerStatus();
            }
            else if (key == 't' || key == 'T') {
                performTimeSync();
            }
            else if (key == 'p' || key == 'P') {
                std::cout << "\n=== BEKENDE PEERS ===\n";
                for (size_t i = 0; i < config.peers.size(); i++) {
                    std::cout << i+1 << ". " << config.peers[i] << "\n";
                }
                std::cout << "Totaal: " << config.peers.size() << " peers\n";
                std::cout << "===================\n\n";
            }
            else if (key == 'h' || key == 'H') {
                showWorkHistory();
            }
            else if (key == 'b' || key == 'B') {
                std::cout << "\n=== BLOCKCHAIN INFO ===\n";
                std::cout << "Totaal blocks: " << blockchain.size() << "\n";
                std::cout << "Genesis block: " << blockchain[0].timestamp << "\n";
                std::cout << "Laatste block: " << blockchain.back().timestamp << "\n";
                std::cout << "Laatste hash: " << blockchain.back().hash.substr(0, 16) << "...\n";
                
                // Count work session blocks
                int workSessionCount = 0;
                int totalMinutesInChain = 0;
                for (const auto& block : blockchain) {
                    if (block.status == "WORK_SESSION" && block.deviceName == config.deviceName) {
                        workSessionCount++;
                        totalMinutesInChain += block.workedMinutes;
                    }
                }
                
                std::cout << "Work session blocks: " << workSessionCount << "\n";
                std::cout << "Totaal gewerkte tijd in chain: " << (totalMinutesInChain / 60) 
                          << " uur en " << (totalMinutesInChain % 60) << " minuten\n";
                std::cout << "======================\n\n";
            }
        }
#endif
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Show progress every hour
        time_t currentTime = getOnlineTimestamp();
        int elapsedHours = (currentTime - onlineStartTime) / 3600;
        
        if (elapsedHours > hourCounter) {
            hourCounter = elapsedHours;
            std::cout << "Status update: " << calculateWorkedHours() << " gewerkt.\n";
            std::cout << "Huidige online tijd: " << getCurrentTimeString() << "\n";
            addBlock("WORKING");
        }
        
        // Show peer status every 5 minutes
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastStatusTime).count() >= 5) {
            showPeerStatus();
            lastStatusTime = now;
        }
        
        // Auto-save work session every 30 minutes (as checkpoint)
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastSaveTime).count() >= 30) {
            std::cout << "Auto-save checkpoint naar blockchain...\n";
            
            std::string endTimeStr = getCurrentTimeString();
            time_t currentTime = getOnlineTimestamp();
            int workedMinutes = (currentTime - onlineStartTime) / 60;
            
            char startBuffer[100];
            struct tm* timeinfo = localtime(&onlineStartTime);
            std::strftime(startBuffer, sizeof(startBuffer), "%Y-%m-%d %H:%M:%S", timeinfo);
            std::string startTimeStr(startBuffer);
            
            addWorkSessionBlock(startTimeStr, endTimeStr, workedMinutes, "Auto-checkpoint");
            
            // Start new session for next checkpoint
            onlineStartTime = currentTime;
            currentSessionId = generateSessionId();
            lastSaveTime = now;
        }
    }
    
    // Clean up threads
    if (peerServerThread.joinable()) {
        peerServerThread.join();
    }
    if (peerClientThread.joinable()) {
        peerClientThread.join();
    }
    
#ifdef _WIN32
    if (hThread != NULL) {
        CloseHandle(hThread);
    }
#endif
    
    return 0;
}