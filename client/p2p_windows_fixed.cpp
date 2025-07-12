// p2p_blockchain_client.cpp - P2P Client with Blockchain-based Time Tracking
// Compile: x86_64-w64-mingw32-g++ -std=c++11 -static p2p_blockchain_client.cpp -o p2p_blockchain_client.exe -lws2_32 -lwtsapi32 -lpowrprof -ladvapi32 -lpsapi -pthread

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wtsapi32.h>
#include <powrprof.h>
#include <wincrypt.h>
#include <psapi.h>
#include <conio.h>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <chrono>
#include <ctime>
#include <fstream>
#include <queue>
#include <atomic>
#include <iomanip>
#include <set>
#include <cstring>
#include <signal.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

typedef int socklen_t;
#define CLOSE_SOCKET closesocket

// Constants
const int OFFLINE_SYNC_DEADLINE = 5 * 24 * 60 * 60; // 5 days in seconds
const int BLOCKCHAIN_SYNC_INTERVAL = 300; // 5 minutes
const std::string BLOCKCHAIN_FILE = "blockchain.dat";
const std::string PENDING_BLOCKS_FILE = "pending_blocks.dat";

// Event types for blockchain logging
enum EventType {
    EVENT_SYSTEM_START,
    EVENT_SYSTEM_SHUTDOWN,
    EVENT_SYSTEM_SLEEP,
    EVENT_SYSTEM_WAKE,
    EVENT_SESSION_LOCK,
    EVENT_SESSION_UNLOCK,
    EVENT_USER_LOGIN,
    EVENT_USER_LOGOUT,
    EVENT_WORK_START,
    EVENT_WORK_STOP,
    EVENT_WORK_PAUSE,
    EVENT_WORK_RESUME,
    EVENT_IDLE_START,
    EVENT_IDLE_STOP,
    EVENT_SUSPICIOUS_ACTIVITY,
    EVENT_WORK_SESSION,
    EVENT_OFFLINE_START,
    EVENT_OFFLINE_END,
    EVENT_PEER_VALIDATION,
    EVENT_FORCED_SYNC
};

// Configuration structure
struct Config {
    std::string relayHost = "51.178.139.139";
    int relayPort = 9999;
    int p2pPort = 8888;
    std::string deviceId = "WINPC001";
    std::string deviceName = "Windows-PC";
    int idleThreshold = 300;
    bool debugMode = false;
    bool offlineMode = false;
    time_t lastOnlineSync = 0;
};

// Forward declarations
std::string sha256(const std::string& data);
std::vector<std::string> split(const std::string& str, char delimiter);

// Block structure for blockchain
struct Block {
    int index;
    std::string timestamp;
    std::string deviceId;
    std::string deviceName;
    std::string eventType;
    std::string hash;
    std::string previousHash;
    int workedMinutes;
    std::string validatorId;  // Peer who validated this block
    bool isOfflineBlock;      // Was created during offline period
    std::map<std::string, std::string> metadata;
    
    std::string calculateHash() const {
        std::stringstream ss;
        ss << index << timestamp << deviceId << eventType << previousHash 
           << workedMinutes << validatorId << isOfflineBlock;
        for (const auto& pair : metadata) {
            ss << pair.first << pair.second;
        }
        return sha256(ss.str());
    }
    
    std::string serialize() const {
        std::stringstream ss;
        ss << "BLOCK|" << index << "|" << timestamp << "|" << deviceId << "|" 
           << eventType << "|" << previousHash << "|" << hash << "|"
           << workedMinutes << "|" << validatorId << "|" << isOfflineBlock << "|";
        for (const auto& pair : metadata) {
            ss << pair.first << "=" << pair.second << ";";
        }
        ss << "|" << deviceName;
        return ss.str();
    }
    
    static Block deserialize(const std::string& data) {
        Block block;
        std::vector<std::string> parts = split(data, '|');
        if (parts.size() >= 11 && parts[0] == "BLOCK") {
            block.index = std::stoi(parts[1]);
            block.timestamp = parts[2];
            block.deviceId = parts[3];
            block.eventType = parts[4];
            block.previousHash = parts[5];
            block.hash = parts[6];
            block.workedMinutes = std::stoi(parts[7]);
            block.validatorId = parts[8];
            block.isOfflineBlock = (parts[9] == "1");
            // Parse metadata
            if (!parts[10].empty()) {
                std::vector<std::string> metaPairs = split(parts[10], ';');
                for (const auto& pair : metaPairs) {
                    size_t pos = pair.find('=');
                    if (pos != std::string::npos) {
                        block.metadata[pair.substr(0, pos)] = pair.substr(pos + 1);
                    }
                }
            }
            if (parts.size() > 11) block.deviceName = parts[11];
        }
        return block;
    }
    
    bool isValid() const {
        return hash == calculateHash();
    }
};

// Blockchain class
class Blockchain {
private:
    std::vector<Block> chain;
    std::vector<Block> pendingBlocks;
    std::mutex chainMutex;
    std::mutex pendingMutex;
    
public:
    Blockchain() {
        // Create genesis block
        Block genesis;
        genesis.index = 0;
        genesis.timestamp = "2024-01-01 00:00:00";
        genesis.deviceId = "GENESIS";
        genesis.deviceName = "Genesis Block";
        genesis.eventType = "GENESIS";
        genesis.previousHash = "0";
        genesis.workedMinutes = 0;
        genesis.isOfflineBlock = false;
        genesis.hash = genesis.calculateHash();
        chain.push_back(genesis);
    }
    
    void addBlock(Block block, bool isPending = false) {
        if (isPending) {
            std::lock_guard<std::mutex> lock(pendingMutex);
            block.index = pendingBlocks.size();
            if (!pendingBlocks.empty()) {
                block.previousHash = pendingBlocks.back().hash;
            } else if (!chain.empty()) {
                block.previousHash = chain.back().hash;
            }
            block.hash = block.calculateHash();
            pendingBlocks.push_back(block);
        } else {
            std::lock_guard<std::mutex> lock(chainMutex);
            block.index = chain.size();
            block.previousHash = chain.back().hash;
            block.hash = block.calculateHash();
            chain.push_back(block);
        }
    }
    
    bool validateChain() {
        std::lock_guard<std::mutex> lock(chainMutex);
        for (size_t i = 1; i < chain.size(); i++) {
            if (!chain[i].isValid()) return false;
            if (chain[i].previousHash != chain[i-1].hash) return false;
        }
        return true;
    }
    
    void saveToFile(const std::string& filename) {
        std::lock_guard<std::mutex> lock(chainMutex);
        std::ofstream file(filename);
        for (const auto& block : chain) {
            file << block.serialize() << std::endl;
        }
        file.close();
    }
    
    void loadFromFile(const std::string& filename) {
        std::lock_guard<std::mutex> lock(chainMutex);
        std::ifstream file(filename);
        if (!file.is_open()) return;
        
        chain.clear();
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                Block block = Block::deserialize(line);
                if (block.index >= 0) {
                    chain.push_back(block);
                }
            }
        }
        file.close();
    }
    
    void savePendingBlocks(const std::string& filename) {
        std::lock_guard<std::mutex> lock(pendingMutex);
        std::ofstream file(filename);
        for (const auto& block : pendingBlocks) {
            file << block.serialize() << std::endl;
        }
        file.close();
    }
    
    void loadPendingBlocks(const std::string& filename) {
        std::lock_guard<std::mutex> lock(pendingMutex);
        std::ifstream file(filename);
        if (!file.is_open()) return;
        
        pendingBlocks.clear();
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                Block block = Block::deserialize(line);
                if (block.index >= 0) {
                    pendingBlocks.push_back(block);
                }
            }
        }
        file.close();
    }
    
    std::vector<Block> getPendingBlocks() {
        std::lock_guard<std::mutex> lock(pendingMutex);
        return pendingBlocks;
    }
    
    void commitPendingBlocks() {
        std::lock_guard<std::mutex> lockPending(pendingMutex);
        std::lock_guard<std::mutex> lockChain(chainMutex);
        
        for (auto& block : pendingBlocks) {
            block.index = chain.size();
            block.previousHash = chain.back().hash;
            block.hash = block.calculateHash();
            chain.push_back(block);
        }
        pendingBlocks.clear();
    }
    
    std::vector<Block> getRecentBlocks(int count) {
        std::lock_guard<std::mutex> lock(chainMutex);
        std::vector<Block> recent;
        int start = std::max(0, (int)chain.size() - count);
        for (int i = start; i < chain.size(); i++) {
            recent.push_back(chain[i]);
        }
        return recent;
    }
    
    std::string getChainHash() {
        std::lock_guard<std::mutex> lock(chainMutex);
        if (chain.empty()) return "0";
        return chain.back().hash;
    }
    
    int getChainLength() {
        std::lock_guard<std::mutex> lock(chainMutex);
        return chain.size();
    }
};

// Peer information with validation capability
struct Peer {
    std::string deviceId;
    std::string publicIP;
    int publicPort;
    std::string localIP;
    int localPort;
    time_t lastSeen;
    bool isLocal;
    bool isConnected;
    bool canValidate;      // Can this peer validate blocks?
    int validationScore;   // Reliability score
    SOCKET socket;
};

// Global variables
Config config;
std::map<std::string, Peer> peers;
std::mutex peersMutex;
volatile bool g_running = true;
SOCKET relaySocket = INVALID_SOCKET;
SOCKET udpSocket = INVALID_SOCKET;
Blockchain blockchain;
time_t lastOfflineCheck = 0;
std::queue<std::string> offlineQueue;

// Work session tracking
struct WorkSession {
    time_t startTime;
    time_t endTime;
    int idleMinutes;
    int activeMinutes;
    bool isActive;
};

WorkSession currentSession;
time_t lastActivityTime = 0;
bool isUserActive = true;
bool isWorkingHours = false;
std::mutex sessionMutex;

// Utility function to split strings
std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(str);
    std::string part;
    while (std::getline(ss, part, delimiter)) {
        parts.push_back(part);
    }
    return parts;
}

// SHA256 using Windows CryptoAPI
std::string sha256(const std::string& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;
    std::stringstream ss;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    if (!CryptHashData(hHash, (BYTE*)data.c_str(), data.length(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    return ss.str();
}

// Get current timestamp
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Event type to string conversion
std::string eventTypeToString(EventType type) {
    switch(type) {
        case EVENT_SYSTEM_START: return "SYSTEM_START";
        case EVENT_SYSTEM_SHUTDOWN: return "SYSTEM_SHUTDOWN";
        case EVENT_SYSTEM_SLEEP: return "SYSTEM_SLEEP";
        case EVENT_SYSTEM_WAKE: return "SYSTEM_WAKE";
        case EVENT_SESSION_LOCK: return "SESSION_LOCK";
        case EVENT_SESSION_UNLOCK: return "SESSION_UNLOCK";
        case EVENT_USER_LOGIN: return "USER_LOGIN";
        case EVENT_USER_LOGOUT: return "USER_LOGOUT";
        case EVENT_WORK_START: return "WORK_START";
        case EVENT_WORK_STOP: return "WORK_STOP";
        case EVENT_WORK_PAUSE: return "WORK_PAUSE";
        case EVENT_WORK_RESUME: return "WORK_RESUME";
        case EVENT_IDLE_START: return "IDLE_START";
        case EVENT_IDLE_STOP: return "IDLE_STOP";
        case EVENT_SUSPICIOUS_ACTIVITY: return "SUSPICIOUS_ACTIVITY";
        case EVENT_WORK_SESSION: return "WORK_SESSION";
        case EVENT_OFFLINE_START: return "OFFLINE_START";
        case EVENT_OFFLINE_END: return "OFFLINE_END";
        case EVENT_PEER_VALIDATION: return "PEER_VALIDATION";
        case EVENT_FORCED_SYNC: return "FORCED_SYNC";
        default: return "UNKNOWN";
    }
}

// Create and add block to blockchain
void createBlock(EventType eventType, int duration = 0, const std::string& validatorId = "") {
    Block block;
    block.timestamp = getCurrentTimestamp();
    block.deviceId = config.deviceId;
    block.deviceName = config.deviceName;
    block.eventType = eventTypeToString(eventType);
    block.workedMinutes = duration;
    block.validatorId = validatorId.empty() ? config.deviceId : validatorId;
    block.isOfflineBlock = config.offlineMode;
    
    // Add metadata
    block.metadata["offline_mode"] = config.offlineMode ? "true" : "false";
    block.metadata["local_time"] = getCurrentTimestamp();
    
    // Add to blockchain (pending if offline)
    blockchain.addBlock(block, config.offlineMode);
    
    // Save blockchain
    blockchain.saveToFile(BLOCKCHAIN_FILE);
    if (config.offlineMode) {
        blockchain.savePendingBlocks(PENDING_BLOCKS_FILE);
    }
    
    std::cout << "[BLOCKCHAIN] Block added: " << block.eventType 
              << (config.offlineMode ? " (pending)" : " (confirmed)") << std::endl;
}

// Check if offline sync is required
bool isOfflineSyncRequired() {
    time_t now = time(nullptr);
    return config.offlineMode && 
           (now - config.lastOnlineSync) >= OFFLINE_SYNC_DEADLINE;
}

// Force user to sync
void enforceOfflineSync() {
    if (!isOfflineSyncRequired()) return;
    
    std::cout << "\n[WARNING] You have been offline for more than 5 days!" << std::endl;
    std::cout << "You must sync with the server to continue using the system." << std::endl;
    
    createBlock(EVENT_FORCED_SYNC);
    
    // Show warning dialog
    MessageBoxA(NULL, 
                "You have been offline for more than 5 days.\n"
                "Please connect to the network to sync your time records.\n"
                "The application will continue trying to connect.",
                "Sync Required", 
                MB_OK | MB_ICONWARNING);
}

// Validate block with peer
bool validateBlockWithPeer(const Block& block, const std::string& peerId) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    auto it = peers.find(peerId);
    if (it == peers.end() || !it->second.isConnected) {
        return false;
    }
    
    // Send block for validation
    std::string validationRequest = "VALIDATE|" + block.serialize() + "\n";
    int result = send(it->second.socket, validationRequest.c_str(), 
                     validationRequest.length(), 0);
    
    if (result == SOCKET_ERROR) {
        return false;
    }
    
    // Wait for validation response
    char buffer[4096];
    int received = recv(it->second.socket, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        std::string response(buffer);
        
        if (response.find("VALIDATED|TRUE") == 0) {
            it->second.validationScore++;
            return true;
        }
    }
    
    return false;
}

// Request peer to validate behavior
void requestPeerValidation(const std::string& targetPeerId) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    // Find a peer that can validate
    for (auto& pair : peers) {
        if (pair.first != targetPeerId && pair.second.isConnected && 
            pair.second.canValidate) {
            
            std::string request = "OBSERVE|" + targetPeerId + "|" + 
                                 std::to_string(time(nullptr)) + "\n";
            send(pair.second.socket, request.c_str(), request.length(), 0);
            
            std::cout << "[VALIDATION] Requested " << pair.first 
                     << " to validate " << targetPeerId << std::endl;
            break;
        }
    }
}

// Sync blockchain with peers
void syncBlockchainWithPeers() {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    for (auto& pair : peers) {
        if (pair.second.isConnected) {
            // Request blockchain info
            std::string request = "BLOCKCHAIN|INFO|" + 
                                std::to_string(blockchain.getChainLength()) + "|" +
                                blockchain.getChainHash() + "\n";
            send(pair.second.socket, request.c_str(), request.length(), 0);
        }
    }
}

// Process blockchain sync response
void processBlockchainSync(const std::string& peerId, const std::string& message) {
    std::vector<std::string> parts = split(message, '|');
    if (parts.size() < 4) return;
    
    int peerLength = std::stoi(parts[2]);
    std::string peerHash = parts[3];
    
    // If peer has longer chain, request missing blocks
    if (peerLength > blockchain.getChainLength()) {
        std::lock_guard<std::mutex> lock(peersMutex);
        if (peers.find(peerId) != peers.end() && peers[peerId].isConnected) {
            std::string request = "BLOCKCHAIN|GET_BLOCKS|" + 
                                std::to_string(blockchain.getChainLength()) + "\n";
            send(peers[peerId].socket, request.c_str(), request.length(), 0);
        }
    }
}

// Sync pending blocks when coming online
void syncPendingBlocks() {
    if (!config.offlineMode) {
        std::vector<Block> pending = blockchain.getPendingBlocks();
        
        if (!pending.empty()) {
            std::cout << "[SYNC] Syncing " << pending.size() 
                     << " offline blocks..." << std::endl;
            
            // Validate and commit pending blocks
            for (auto& block : pending) {
                // Try to get peer validation
                bool validated = false;
                for (const auto& pair : peers) {
                    if (pair.second.canValidate && 
                        validateBlockWithPeer(block, pair.first)) {
                        block.validatorId = pair.first;
                        validated = true;
                        break;
                    }
                }
                
                if (!validated) {
                    block.validatorId = "SELF_VALIDATED";
                }
            }
            
            // Commit all pending blocks
            blockchain.commitPendingBlocks();
            blockchain.saveToFile(BLOCKCHAIN_FILE);
            
            // Clear pending blocks file
            std::ofstream file(PENDING_BLOCKS_FILE, std::ios::trunc);
            file.close();
            
            config.lastOnlineSync = time(nullptr);
            createBlock(EVENT_OFFLINE_END);
            
            std::cout << "[SYNC] Offline blocks synced successfully" << std::endl;
        }
    }
}

// Send blockchain blocks to relay
void sendBlockchainToRelay() {
    if (relaySocket == INVALID_SOCKET || config.offlineMode) return;
    
    std::vector<Block> recentBlocks = blockchain.getRecentBlocks(100);
    
    for (const auto& block : recentBlocks) {
        std::string blockMsg = "BLOCKCHAIN|BLOCK|" + block.serialize() + "\n";
        send(relaySocket, blockMsg.c_str(), blockMsg.length(), 0);
    }
}

// Detect user activity
bool detectUserActivity() {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    
    if (!GetLastInputInfo(&lii)) {
        return true;
    }
    
    DWORD currentTick = GetTickCount();
    DWORD idleTime = (currentTick - lii.dwTime) / 1000;
    
    return idleTime < config.idleThreshold;
}

// Monitor work status
void monitorWorkStatus() {
    // Check if user logged in
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId != 0xFFFFFFFF) {
        LPWSTR userName = nullptr;
        DWORD size = 0;
        
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, 
            WTSUserName, &userName, &size)) {
            if (userName && wcslen(userName) > 0) {
                if (!isWorkingHours) {
                    isWorkingHours = true;
                    createBlock(EVENT_USER_LOGIN);
                    createBlock(EVENT_WORK_START);
                    
                    std::lock_guard<std::mutex> lock(sessionMutex);
                    currentSession.startTime = time(nullptr);
                    currentSession.isActive = true;
                }
            }
            WTSFreeMemory(userName);
        }
    }
    
    // Check for idle/active transitions
    bool currentlyActive = detectUserActivity();
    
    if (currentlyActive != isUserActive) {
        isUserActive = currentlyActive;
        
        if (isUserActive) {
            createBlock(EVENT_IDLE_STOP);
            lastActivityTime = time(nullptr);
        } else {
            createBlock(EVENT_IDLE_START);
            
            if (isWorkingHours) {
                std::lock_guard<std::mutex> lock(sessionMutex);
                int workDuration = (time(nullptr) - currentSession.startTime) / 60;
                createBlock(EVENT_WORK_SESSION, workDuration);
            }
        }
    }
    
    if (currentlyActive) {
        lastActivityTime = time(nullptr);
    }
}

// Window procedure for system events
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_WTSSESSION_CHANGE:
            switch (wParam) {
                case WTS_SESSION_LOCK:
                    createBlock(EVENT_SESSION_LOCK);
                    if (isWorkingHours) {
                        int duration = (time(nullptr) - currentSession.startTime) / 60;
                        createBlock(EVENT_WORK_SESSION, duration);
                        isWorkingHours = false;
                    }
                    break;
                    
                case WTS_SESSION_UNLOCK:
                    createBlock(EVENT_SESSION_UNLOCK);
                    createBlock(EVENT_WORK_START);
                    currentSession.startTime = time(nullptr);
                    isWorkingHours = true;
                    break;
                    
                case WTS_SESSION_LOGOFF:
                case WTS_REMOTE_DISCONNECT:
                    createBlock(EVENT_USER_LOGOUT);
                    if (isWorkingHours) {
                        int duration = (time(nullptr) - currentSession.startTime) / 60;
                        createBlock(EVENT_WORK_SESSION, duration);
                        createBlock(EVENT_WORK_STOP);
                        isWorkingHours = false;
                    }
                    break;
            }
            break;
            
        case WM_POWERBROADCAST:
            switch (wParam) {
                case PBT_APMSUSPEND:
                    createBlock(EVENT_SYSTEM_SLEEP);
                    if (isWorkingHours) {
                        int duration = (time(nullptr) - currentSession.startTime) / 60;
                        createBlock(EVENT_WORK_SESSION, duration);
                    }
                    break;
                    
                case PBT_APMRESUMEAUTOMATIC:
                case PBT_APMRESUMESUSPEND:
                    createBlock(EVENT_SYSTEM_WAKE);
                    break;
            }
            break;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Blockchain sync thread
void runBlockchainSync() {
    while (g_running) {
        // Check offline sync requirement
        enforceOfflineSync();
        
        // Try to sync with peers
        if (!config.offlineMode) {
            syncBlockchainWithPeers();
            sendBlockchainToRelay();
        }
        
        // Check if we need to come online
        if (config.offlineMode && relaySocket != INVALID_SOCKET) {
            config.offlineMode = false;
            syncPendingBlocks();
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(BLOCKCHAIN_SYNC_INTERVAL));
    }
}

// Time tracking thread
void runTimeTracking() {
    // Create hidden window for system events
    WNDCLASSA wc = {0};  // Use ANSI version
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "TimeTrackerWindow";  // ANSI string
    RegisterClassA(&wc);  // Use ANSI version
    
    HWND hwnd = CreateWindowA(wc.lpszClassName, "", 0, 0, 0, 0, 0, 
                            HWND_MESSAGE, NULL, wc.hInstance, NULL);
    
    // Register for session notifications
    WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
    
    // Initial status
    createBlock(EVENT_SYSTEM_START);
    
    MSG msg;
    while (g_running) {
        // Process Windows messages
        while (PeekMessage(&msg, hwnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        // Monitor work status
        monitorWorkStatus();
        
        Sleep(1000);
    }
    
    // Cleanup
    if (isWorkingHours) {
        int duration = (time(nullptr) - currentSession.startTime) / 60;
        createBlock(EVENT_WORK_SESSION, duration);
        createBlock(EVENT_WORK_STOP);
    }
    createBlock(EVENT_SYSTEM_SHUTDOWN);
    
    WTSUnRegisterSessionNotification(hwnd);
    DestroyWindow(hwnd);
}

// Connect to relay (with offline handling)
void connectToRelay() {
    if (relaySocket != INVALID_SOCKET) {
        CLOSE_SOCKET(relaySocket);
    }
    
    relaySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (relaySocket == INVALID_SOCKET) {
        config.offlineMode = true;
        createBlock(EVENT_OFFLINE_START);
        std::cout << "[OFFLINE] Failed to create socket - entering offline mode" << std::endl;
        return;
    }
    
    // Set non-blocking mode
    u_long mode = 1;
    ioctlsocket(relaySocket, FIONBIO, &mode);
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.relayPort);
    inet_pton(AF_INET, config.relayHost.c_str(), &serverAddr.sin_addr);
    
    connect(relaySocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    
    // Wait for connection
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(relaySocket, &writeSet);
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    if (select(0, NULL, &writeSet, NULL, &timeout) > 0) {
        // Connected successfully
        config.offlineMode = false;
        std::cout << "[ONLINE] Connected to relay server" << std::endl;
        
        // Register with relay
        std::string regMsg = "RELAY|REGISTER|" + config.deviceId + "|" + 
                           std::to_string(config.p2pPort) + "\n";
        send(relaySocket, regMsg.c_str(), regMsg.length(), 0);
        
        // Sync pending blocks
        syncPendingBlocks();
    } else {
        // Connection failed
        CLOSE_SOCKET(relaySocket);
        relaySocket = INVALID_SOCKET;
        config.offlineMode = true;
        
        if (config.lastOnlineSync == 0) {
            config.lastOnlineSync = time(nullptr);
        }
        
        createBlock(EVENT_OFFLINE_START);
        std::cout << "[OFFLINE] Cannot connect to relay - entering offline mode" << std::endl;
    }
}

// Main function
int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    // Get computer name
    char computerName[256];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        config.deviceName = computerName;
    }
    
    // Load existing blockchain
    blockchain.loadFromFile(BLOCKCHAIN_FILE);
    blockchain.loadPendingBlocks(PENDING_BLOCKS_FILE);
    
    std::cout << "P2P Blockchain Time Tracking Client" << std::endl;
    std::cout << "Device: " << config.deviceName << " (" << config.deviceId << ")" << std::endl;
    std::cout << "Blockchain length: " << blockchain.getChainLength() << " blocks" << std::endl;
    
    // Start threads
    std::thread timeTrackingThread(runTimeTracking);
    std::thread blockchainSyncThread(runBlockchainSync);
    
    // Try to connect to relay
    connectToRelay();
    
    // Main loop
    std::cout << "Press 'q' to quit, 's' to show status" << std::endl;
    
    while (g_running) {
        if (_kbhit()) {
            char ch = _getch();
            if (ch == 'q' || ch == 'Q') {
                g_running = false;
                break;
            } else if (ch == 's' || ch == 'S') {
                std::cout << "\n[STATUS]" << std::endl;
                std::cout << "Mode: " << (config.offlineMode ? "OFFLINE" : "ONLINE") << std::endl;
                std::cout << "Blockchain blocks: " << blockchain.getChainLength() << std::endl;
                std::cout << "Pending blocks: " << blockchain.getPendingBlocks().size() << std::endl;
                std::cout << "Connected peers: " << peers.size() << std::endl;
                if (config.offlineMode) {
                    int offlineDays = (time(nullptr) - config.lastOnlineSync) / (24 * 60 * 60);
                    std::cout << "Offline for: " << offlineDays << " days" << std::endl;
                    std::cout << "Sync required in: " << (5 - offlineDays) << " days" << std::endl;
                }
            }
        }
        
        // Try to reconnect if offline
        if (config.offlineMode && relaySocket == INVALID_SOCKET) {
            static time_t lastReconnectAttempt = 0;
            if (time(nullptr) - lastReconnectAttempt > 30) {
                lastReconnectAttempt = time(nullptr);
                connectToRelay();
            }
        }
        
        Sleep(100);
    }

    // Cleanup
    g_running = false;
    
    if (timeTrackingThread.joinable()) timeTrackingThread.join();
    if (blockchainSyncThread.joinable()) blockchainSyncThread.join();

    if (relaySocket != INVALID_SOCKET) CLOSE_SOCKET(relaySocket);
    if (udpSocket != INVALID_SOCKET) CLOSE_SOCKET(udpSocket);
    
    WSACleanup();
    return 0;
}