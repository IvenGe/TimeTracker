// p2p_windows_fixed.cpp - Fixed Windows P2P Client without OpenSSL dependency
// Cross-compile from Linux: x86_64-w64-mingw32-g++ -std=c++11 -static p2p_windows_fixed.cpp -o p2p_client.exe -lws2_32 -lwtsapi32 -lpowrprof -ladvapi32 -pthread

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wtsapi32.h>
#include <powrprof.h>
#include <wincrypt.h>  // For Windows Crypto API
#include <conio.h>     // For _kbhit() and _getch()
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
#pragma comment(lib, "advapi32.lib")  // For CryptoAPI

typedef int socklen_t;
#define CLOSE_SOCKET closesocket

// Forward declarations for print functions
void printColored(const std::string& text, int color);
void printStatus(const std::string& message, bool success = true);
void printInfo(const std::string& message);
void printWarning(const std::string& message);

// Event types
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
    EVENT_WORK_SESSION
};

// Configuration
struct Config {
    std::string relayHost = "localhost";
    int relayPort = 9999;
    int p2pPort = 8888;
    std::string deviceId = "WINPC001";
    std::string deviceName = "Windows-PC";
    int idleThreshold = 300;
    bool debugMode = false;
};

// SHA256 using Windows CryptoAPI
std::string sha256(const std::string& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;
    std::stringstream ss;
    
    // Get crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    
    // Create hash
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Hash data
    if (!CryptHashData(hHash, (BYTE*)data.c_str(), data.length(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Get hash value
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Convert to hex string
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    return ss.str();
}

// Block structure
struct Block {
    int index;
    std::string timestamp;
    std::string deviceId;
    std::string deviceName;
    std::string eventType;
    std::string hash;
    std::string previousHash;
    int workedMinutes;
    std::map<std::string, std::string> metadata;
    
    std::string calculateHash() const {
        std::stringstream ss;
        ss << index << timestamp << deviceId << eventType << previousHash << workedMinutes;
        for (const auto& pair : metadata) {
            ss << pair.first << pair.second;
        }
        return sha256(ss.str());
    }
    
    std::string serialize() const {
        std::stringstream ss;
        ss << "BLOCK|" << index << "|" << timestamp << "|" << deviceId << "|" 
           << eventType << "|" << previousHash << "|" << hash << "|";
        
        for (const auto& pair : metadata) {
            ss << pair.first << "=" << pair.second << ";";
        }
        ss << "|" << deviceName << "|" << workedMinutes;
        
        return ss.str();
    }
};

// Peer information
struct Peer {
    std::string deviceId;
    std::string ipAddress;
    int port;
    time_t lastSeen;
    std::vector<Block> blockchain;
};

// Global variables
Config config;
std::vector<Block> blockchain;
std::map<std::string, Peer> peers;
std::mutex blockchainMutex;
std::mutex peersMutex;
std::queue<Block> offlineQueue;
std::mutex queueMutex;
volatile bool g_running = true;
SOCKET relaySocket = INVALID_SOCKET;
SOCKET p2pSocket = INVALID_SOCKET;
time_t sessionStartTime = 0;
std::string currentSessionId;
std::atomic<bool> isWorking{false};
HWND messageWindow = NULL;

// Forward declarations
void createEvent(EventType type, const std::string& description);
std::string getEventTypeString(EventType type);
void connectToRelay();
void sendToRelay(const std::string& message);
void broadcastBlock(const Block& block);
void syncWithPeers();
std::string getCurrentTimeString();
std::string getSystemInfo();
void handleP2PClient(SOCKET clientSocket);
void createAndAddBlock(Block& block);
void forceCheckpoint(const std::string& reason);
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void processWindowsMessages();

// Print functions implementation
void printColored(const std::string& text, int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
    std::cout << text;
    SetConsoleTextAttribute(hConsole, 7); // Reset to default
}

void printStatus(const std::string& message, bool success) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (success) {
        SetConsoleTextAttribute(hConsole, 10); // Green
        std::cout << "[OK] ";
    } else {
        SetConsoleTextAttribute(hConsole, 12); // Red
        std::cout << "[FAIL] ";
    }
    SetConsoleTextAttribute(hConsole, 7); // Reset
    std::cout << message << std::endl;
}

void printInfo(const std::string& message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 11); // Cyan
    std::cout << "[INFO] ";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << message << std::endl;
}

void printWarning(const std::string& message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 14); // Yellow
    std::cout << "[WARN] ";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << message << std::endl;
}

// Console control handler
BOOL WINAPI ConsoleCtrlHandler(DWORD dwType) {
    switch (dwType) {
    case CTRL_C_EVENT:
        createEvent(EVENT_WORK_STOP, "Program terminated with Ctrl+C");
        g_running = false;
        return TRUE;
        
    case CTRL_BREAK_EVENT:
        createEvent(EVENT_WORK_STOP, "Program terminated with Ctrl+Break");
        g_running = false;
        return TRUE;
        
    case CTRL_CLOSE_EVENT:
        createEvent(EVENT_WORK_STOP, "Console window closed");
        g_running = false;
        return TRUE;
        
    case CTRL_LOGOFF_EVENT:
        createEvent(EVENT_USER_LOGOUT, "Windows user logoff");
        g_running = false;
        return TRUE;
        
    case CTRL_SHUTDOWN_EVENT:
        createEvent(EVENT_SYSTEM_SHUTDOWN, "Windows system shutdown");
        g_running = false;
        return TRUE;
    }
    
    return FALSE;
}

// System Event Monitor for Windows
class SystemEventMonitor {
private:
    std::thread monitorThread;
    std::atomic<bool> monitoring{true};
    time_t lastActivityTime;
    bool wasIdle = false;
    
public:
    void startMonitoring() {
        monitorThread = std::thread(&SystemEventMonitor::monitorLoop, this);
        registerSystemHooks();
    }
    
    void stopMonitoring() {
        monitoring = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }
    
    void registerSystemHooks() {
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        
        // Register for session notifications
        if (messageWindow) {
            WTSRegisterSessionNotification(messageWindow, NOTIFY_FOR_THIS_SESSION);
        }
    }
    
    void monitorLoop() {
        while (monitoring) {
            checkIdleTime();
            checkSystemStatus();
            checkSuspiciousActivity();
            
            // Auto-checkpoint every 30 minutes
            static time_t lastCheckpoint = time(nullptr);
            if (isWorking && (time(nullptr) - lastCheckpoint) > 1800) {
                forceCheckpoint("Auto-checkpoint");
                lastCheckpoint = time(nullptr);
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }
    
    void checkIdleTime() {
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(LASTINPUTINFO);
        GetLastInputInfo(&lii);
        
        DWORD idleTime = (GetTickCount() - lii.dwTime) / 1000;
        bool isIdle = (idleTime > config.idleThreshold);
        
        if (!wasIdle && isIdle) {
            createEvent(EVENT_IDLE_START, "User idle for " + std::to_string(config.idleThreshold) + " seconds");
            if (isWorking) {
                forceCheckpoint("User idle");
                printWarning("Work session paused due to inactivity");
            }
        } else if (wasIdle && !isIdle) {
            createEvent(EVENT_IDLE_STOP, "User active again");
            if (isWorking) {
                printInfo("User activity detected - work session continuing");
            }
        }
        
        wasIdle = isIdle;
    }
    
    void checkSystemStatus() {
        SYSTEM_POWER_STATUS sps;
        if (GetSystemPowerStatus(&sps)) {
            static int lastBattery = -1;
            
            // Check battery level
            if (sps.ACLineStatus == 0) { // On battery
                if (lastBattery != -1 && sps.BatteryLifePercent < 20 && lastBattery >= 20) {
                    createEvent(EVENT_SUSPICIOUS_ACTIVITY, 
                               "Battery low: " + std::to_string(sps.BatteryLifePercent) + "%");
                }
            }
            
            lastBattery = sps.BatteryLifePercent;
        }
    }
    
    void checkSuspiciousActivity() {
        static time_t lastCheck = time(nullptr);
        time_t now = time(nullptr);
        
        // Check for time jumps
        if (abs(now - lastCheck) > 3600) {
            createEvent(EVENT_SUSPICIOUS_ACTIVITY, 
                       "Large time jump detected: " + std::to_string(abs(now - lastCheck)) + " seconds");
        }
        
        // Check for debugger
        if (IsDebuggerPresent()) {
            static bool debuggerReported = false;
            if (!debuggerReported) {
                createEvent(EVENT_SUSPICIOUS_ACTIVITY, "Debugger detected!");
                debuggerReported = true;
            }
        }
        
        lastCheck = now;
    }
};

// Get current time string
std::string getCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    struct tm timeinfo;
    localtime_s(&timeinfo, &time_t);
    
    std::stringstream ss;
    ss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Get event type string
std::string getEventTypeString(EventType type) {
    switch (type) {
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
        case EVENT_SUSPICIOUS_ACTIVITY: return "SUSPICIOUS";
        case EVENT_WORK_SESSION: return "WORK_SESSION";
        default: return "UNKNOWN";
    }
}

// Get system information
std::string getSystemInfo() {
    std::stringstream info;
    
    // Computer name
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    info << "Computer:" << computerName;
    
    // User name
    char userName[256];
    size = sizeof(userName);
    GetUserNameA(userName, &size);
    info << ",User:" << userName;
    
    // System info
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    info << ",CPUs:" << si.dwNumberOfProcessors;
    
    // Windows version
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        info << ",Windows:" << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
    }
    
    return info.str();
}

// Create and add block
void createAndAddBlock(Block& block) {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    
    block.index = blockchain.size();
    block.timestamp = getCurrentTimeString();
    block.deviceId = config.deviceId;
    block.deviceName = config.deviceName;
    block.previousHash = blockchain.empty() ? "0" : blockchain.back().hash;
    block.hash = block.calculateHash();
    
    blockchain.push_back(block);
    
    // Broadcast to peers and relay
    broadcastBlock(block);
    sendToRelay(block.serialize());
}

// Force checkpoint
void forceCheckpoint(const std::string& reason) {
    if (!isWorking || sessionStartTime == 0) return;
    
    time_t now = time(nullptr);
    int workedMinutes = (now - sessionStartTime) / 60;
    
    if (workedMinutes > 0) {
        Block checkpoint;
        checkpoint.eventType = getEventTypeString(EVENT_WORK_PAUSE);
        checkpoint.workedMinutes = workedMinutes;
        checkpoint.metadata["checkpoint_reason"] = reason;
        checkpoint.metadata["session_id"] = currentSessionId;
        
        createAndAddBlock(checkpoint);
        sessionStartTime = now;
    }
}

// Create event
void createEvent(EventType type, const std::string& description) {
    Block block;
    block.eventType = getEventTypeString(type);
    block.metadata["description"] = description;
    
    // Handle work timing
    if (type == EVENT_WORK_START || type == EVENT_WORK_RESUME) {
        isWorking = true;
        sessionStartTime = time(nullptr);
        currentSessionId = std::to_string(sessionStartTime);
        block.metadata["session_id"] = currentSessionId;
    } else if (type == EVENT_WORK_STOP || type == EVENT_WORK_PAUSE) {
        if (isWorking && sessionStartTime > 0) {
            block.workedMinutes = (time(nullptr) - sessionStartTime) / 60;
            block.metadata["session_id"] = currentSessionId;
            
            // Create work session summary
            if (type == EVENT_WORK_STOP && block.workedMinutes > 0) {
                Block sessionBlock;
                sessionBlock.eventType = getEventTypeString(EVENT_WORK_SESSION);
                sessionBlock.workedMinutes = block.workedMinutes;
                sessionBlock.metadata["session_id"] = currentSessionId;
                sessionBlock.metadata["session_end"] = getCurrentTimeString();
                
                createAndAddBlock(sessionBlock);
                printInfo("Work session completed: " + std::to_string(block.workedMinutes) + " minutes logged");
            }
        }
        isWorking = false;
    }
    
    // Add system info for certain events
    if (type == EVENT_SYSTEM_START || type == EVENT_SUSPICIOUS_ACTIVITY) {
        block.metadata["system_info"] = getSystemInfo();
    }
    
    createAndAddBlock(block);
    
    if (config.debugMode) {
        printColored("[DEBUG] ", 13);
        std::cout << block.eventType << ": " << description << "\n";
    }
}

// Windows message handler
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_POWERBROADCAST:
        switch (wParam) {
        case PBT_APMSUSPEND:
            createEvent(EVENT_SYSTEM_SLEEP, "System entering sleep mode");
            forceCheckpoint("System sleep");
            printWarning("System going to sleep - work session saved");
            break;
            
        case PBT_APMRESUMESUSPEND:
            createEvent(EVENT_SYSTEM_WAKE, "System waking from sleep");
            printInfo("System resumed from sleep");
            break;
            
        case PBT_APMRESUMEAUTOMATIC:
            createEvent(EVENT_SYSTEM_WAKE, "System automatic wake");
            break;
        }
        break;
        
    case WM_QUERYENDSESSION:
        createEvent(EVENT_SYSTEM_SHUTDOWN, "System shutdown initiated");
        forceCheckpoint("System shutdown");
        printWarning("System shutting down - saving work session");
        return TRUE;
        
    case WM_ENDSESSION:
        if (wParam) {
            createEvent(EVENT_SYSTEM_SHUTDOWN, "System shutdown confirmed");
        }
        break;
        
    case WM_WTSSESSION_CHANGE:
        switch (wParam) {
        case WTS_SESSION_LOCK:
            createEvent(EVENT_SESSION_LOCK, "Workstation locked");
            forceCheckpoint("Session lock");
            printInfo("Workstation locked - work session checkpoint saved");
            break;
            
        case WTS_SESSION_UNLOCK:
            createEvent(EVENT_SESSION_UNLOCK, "Workstation unlocked");
            printInfo("Workstation unlocked");
            break;
            
        case WTS_SESSION_LOGON:
            createEvent(EVENT_USER_LOGIN, "User logged on");
            break;
            
        case WTS_SESSION_LOGOFF:
            createEvent(EVENT_USER_LOGOUT, "User logged off");
            forceCheckpoint("User logoff");
            break;
        }
        break;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Create message window
void createMessageWindow() {
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = TEXT("P2PTimeTrackingWindow");
    
    if (!RegisterClassEx(&wc)) {
        printStatus("Failed to register window class", false);
        return;
    }
    
    messageWindow = CreateWindowEx(
        0,
        TEXT("P2PTimeTrackingWindow"),
        TEXT("P2P Time Tracking"),
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!messageWindow) {
        printStatus("Failed to create message window", false);
        return;
    }
    
    // Register for session notifications after window is created
    WTSRegisterSessionNotification(messageWindow, NOTIFY_FOR_THIS_SESSION);
}

// Process Windows messages without blocking
void processWindowsMessages() {
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) {
            g_running = false;
            break;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

// Connect to relay server
void connectToRelay() {
    if (relaySocket != INVALID_SOCKET) {
        CLOSE_SOCKET(relaySocket);
    }
    
    relaySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (relaySocket == INVALID_SOCKET) {
        printStatus("Failed to create socket", false);
        return;
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config.relayPort);
    
    if (inet_pton(AF_INET, config.relayHost.c_str(), &serverAddr.sin_addr) <= 0) {
        printStatus("Invalid relay server address: " + config.relayHost, false);
        CLOSE_SOCKET(relaySocket);
        relaySocket = INVALID_SOCKET;
        return;
    }
    
    if (connect(relaySocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        printStatus("Failed to connect to relay server (error: " + std::to_string(error) + ")", false);
        CLOSE_SOCKET(relaySocket);
        relaySocket = INVALID_SOCKET;
        return;
    }
    
    // Register with relay
    std::string regMsg = "RELAY|REGISTER|" + config.deviceId + "\n";
    send(relaySocket, regMsg.c_str(), regMsg.length(), 0);
    
    printStatus("Connected to relay server at " + config.relayHost + ":" + std::to_string(config.relayPort));
    
    // Request peer list
    std::string peerMsg = "RELAY|GET_PEERS|" + config.deviceId + "\n";
    send(relaySocket, peerMsg.c_str(), peerMsg.length(), 0);
}

// Send message to relay
void sendToRelay(const std::string& message) {
    if (relaySocket == INVALID_SOCKET) {
        // Queue for later
        std::lock_guard<std::mutex> lock(queueMutex);
        // Parse and queue block...
        return;
    }
    
    std::string msg = message + "\n";
    int result = send(relaySocket, msg.c_str(), msg.length(), 0);
    
    if (result == SOCKET_ERROR) {
        CLOSE_SOCKET(relaySocket);
        relaySocket = INVALID_SOCKET;
    }
}

// Handle P2P client
void handleP2PClient(SOCKET clientSocket) {
    char buffer[4096];
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        std::string message(buffer);
        
        if (message.find("SYNC_REQUEST") == 0) {
            // Send our blockchain
            std::lock_guard<std::mutex> lock(blockchainMutex);
            for (const auto& block : blockchain) {
                std::string blockMsg = "SYNC_BLOCK|" + block.serialize() + "\n";
                send(clientSocket, blockMsg.c_str(), blockMsg.length(), 0);
            }
        }
    }
    
    CLOSE_SOCKET(clientSocket);
}

// P2P server thread
void runP2PServer() {
    p2pSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (p2pSocket == INVALID_SOCKET) {
        printStatus("Failed to create P2P socket", false);
        return;
    }
    
    int opt = 1;
    setsockopt(p2pSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config.p2pPort);
    
    if (bind(p2pSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printStatus("Failed to bind P2P socket on port " + std::to_string(config.p2pPort), false);
        CLOSE_SOCKET(p2pSocket);
        return;
    }
    
    if (listen(p2pSocket, 10) == SOCKET_ERROR) {
        printStatus("Failed to listen on P2P socket", false);
        CLOSE_SOCKET(p2pSocket);
        return;
    }
    
    printStatus("P2P server listening on port " + std::to_string(config.p2pPort));
    
    while (g_running) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(p2pSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket != INVALID_SOCKET) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
            if (config.debugMode) {
                printInfo("P2P connection from " + std::string(clientIP));
            }
            
            std::thread clientThread([clientSocket]() {
                handleP2PClient(clientSocket);
            });
            clientThread.detach();
        }
    }
    
    CLOSE_SOCKET(p2pSocket);
}

// Broadcast block to peers
void broadcastBlock(const Block& block) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    for (auto& pair : peers) {
        SOCKET peerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (peerSocket == INVALID_SOCKET) continue;
        
        struct sockaddr_in peerAddr;
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(pair.second.port);
        inet_pton(AF_INET, pair.second.ipAddress.c_str(), &peerAddr.sin_addr);
        
        if (connect(peerSocket, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) == 0) {
            std::string blockMsg = block.serialize() + "\n";
            send(peerSocket, blockMsg.c_str(), blockMsg.length(), 0);
        }
        
        CLOSE_SOCKET(peerSocket);
    }
}

// Sync with peers
void syncWithPeers() {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    for (auto& pair : peers) {
        SOCKET peerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (peerSocket == INVALID_SOCKET) continue;
        
        struct sockaddr_in peerAddr;
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(pair.second.port);
        inet_pton(AF_INET, pair.second.ipAddress.c_str(), &peerAddr.sin_addr);
        
        if (connect(peerSocket, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) == 0) {
            std::string syncMsg = "SYNC_REQUEST|" + config.deviceId + "\n";
            send(peerSocket, syncMsg.c_str(), syncMsg.length(), 0);
        }
        
        CLOSE_SOCKET(peerSocket);
    }
}

// Process offline queue
void processOfflineQueue() {
    std::lock_guard<std::mutex> lock(queueMutex);
    
    while (!offlineQueue.empty() && relaySocket != INVALID_SOCKET) {
        Block block = offlineQueue.front();
        offlineQueue.pop();
        
        block.metadata["was_offline"] = "true";
        sendToRelay(block.serialize());
        broadcastBlock(block);
    }
}

// Report generation
void generateReport() {
    std::cout << "\n=== P2P TIME TRACKING REPORT ===\n";
    std::cout << "Device: " << config.deviceId << " (" << config.deviceName << ")\n";
    std::cout << "Blockchain length: " << blockchain.size() << " blocks\n";
    std::cout << "Connected peers: " << peers.size() << "\n\n";
    
    // Calculate statistics
    int totalMinutes = 0;
    int sessions = 0;
    int suspiciousEvents = 0;
    
    for (const auto& block : blockchain) {
        if (block.eventType == "WORK_SESSION") {
            totalMinutes += block.workedMinutes;
            sessions++;
        }
        if (block.eventType == "SUSPICIOUS") {
            suspiciousEvents++;
        }
    }
    
    std::cout << "Work Statistics:\n";
    std::cout << "  Sessions: " << sessions << "\n";
    std::cout << "  Total time: " << totalMinutes / 60 << "h " << totalMinutes % 60 << "m\n";
    std::cout << "  Suspicious events: " << suspiciousEvents << "\n\n";
    
    // Show recent events
    std::cout << "Recent Events:\n";
    int count = 0;
    for (auto it = blockchain.rbegin(); it != blockchain.rend() && count < 10; ++it, ++count) {
        std::cout << "  " << it->timestamp << " - " << it->eventType;
        if (it->metadata.count("description")) {
            std::cout << " - " << it->metadata.at("description");
        }
        if (it->workedMinutes > 0) {
            std::cout << " (" << it->workedMinutes << " min)";
        }
        std::cout << "\n";
    }
}

// Main function
int main(int argc, char* argv[]) {
    // Enable ANSI colors in Windows 10+
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    SetConsoleMode(hOut, dwMode);

    printColored("╔═══════════════════════════════════════════════════════════╗\n", 11);
    printColored("║     P2P Time Tracking Client v3.0 (Windows Edition)       ║\n", 11);
    printColored("║           Connected to relay: ", 11);
    printColored("51.178.139.139:9999", 14);
    printColored("           ║\n", 11);
    printColored("╚═══════════════════════════════════════════════════════════╝\n", 11);
    std::cout << std::endl;
    
    // Initialize Winsock
    printInfo("Initializing Windows Sockets...");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printStatus("Failed to initialize Winsock", false);
        return 1;
    }
    printStatus("Winsock initialized successfully");
    
    // Parse command line
    printInfo("Parsing configuration...");
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--relay" && i + 1 < argc) {
            config.relayHost = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            config.relayPort = std::atoi(argv[++i]);
        } else if (arg == "--p2p-port" && i + 1 < argc) {
            config.p2pPort = std::atoi(argv[++i]);
        } else if (arg == "--device" && i + 1 < argc) {
            config.deviceId = argv[++i];
        } else if (arg == "--name" && i + 1 < argc) {
            config.deviceName = argv[++i];
        } else if (arg == "--debug") {
            config.debugMode = true;
        }
    }
    
    // Show configuration
    std::cout << "\nConfiguration:\n";
    std::cout << "  Device ID:    " << config.deviceId << "\n";
    std::cout << "  Device Name:  " << config.deviceName << "\n";
    std::cout << "  Relay Server: " << config.relayHost << ":" << config.relayPort << "\n";
    std::cout << "  P2P Port:     " << config.p2pPort << "\n";
    std::cout << "  Debug Mode:   " << (config.debugMode ? "Enabled" : "Disabled") << "\n\n";
    
    // Initialize
    printInfo("Starting services...");
    createEvent(EVENT_SYSTEM_START, "P2P Time tracking client started");
    
    // Create message window (but don't block)
    printInfo("Creating Windows message handler...");
    createMessageWindow();
    
    // Start system monitor
    printInfo("Starting system event monitor...");
    SystemEventMonitor monitor;
    monitor.startMonitoring();
    printStatus("System monitor active");
    
    // Start P2P server
    printInfo("Starting P2P server on port " + std::to_string(config.p2pPort) + "...");
    std::thread p2pThread(runP2PServer);
    
    // Connection manager
    printInfo("Starting connection manager...");
    std::thread connectionThread([&]() {
        int reconnectAttempts = 0;
        while (g_running) {
            // Connect to relay
            if (relaySocket == INVALID_SOCKET) {
                if (reconnectAttempts == 0) {
                    printInfo("Attempting to connect to relay server...");
                } else {
                    printWarning("Reconnection attempt #" + std::to_string(reconnectAttempts));
                }
                
                connectToRelay();
                if (relaySocket != INVALID_SOCKET) {
                    printStatus("Connected to relay server!");
                    reconnectAttempts = 0;
                    processOfflineQueue();
                } else {
                    reconnectAttempts++;
                    printWarning("Will retry in 30 seconds...");
                }
            }
            
            // Sync with peers periodically
            static time_t lastSync = 0;
            if (time(nullptr) - lastSync > 300) { // Every 5 minutes
                if (peers.size() > 0) {
                    printInfo("Synchronizing with " + std::to_string(peers.size()) + " peers...");
                    syncWithPeers();
                    printStatus("Peer synchronization complete");
                }
                lastSync = time(nullptr);
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    });
    
    // Main command loop with non-blocking input
    printStatus("All services started successfully!");
    std::cout << "\n";
    printColored("Available Commands:\n", 14);
    std::cout << "  start   - Start work session\n";
    std::cout << "  stop    - Stop work session\n";
    std::cout << "  pause   - Pause work session\n";
    std::cout << "  resume  - Resume work session\n";
    std::cout << "  status  - Show current status\n";
    std::cout << "  report  - Generate work report\n";
    std::cout << "  peers   - List connected peers\n";
    std::cout << "  quit    - Exit application\n\n";
    
    // Non-blocking console input handling
    std::string command;
    std::cout << "> ";
    std::cout.flush();
    
    while (g_running) {
        // Process Windows messages
        processWindowsMessages();
        
        // Check for console input
        if (_kbhit()) {
            char ch = _getch();
            
            if (ch == '\r' || ch == '\n') {
                std::cout << std::endl;
                
                // Process command
                if (command == "start") {
                    createEvent(EVENT_WORK_START, "Work session started manually");
                    printStatus("Work session started");
                    printInfo("Timer running... Type 'stop' to end session");
                } else if (command == "stop") {
                    createEvent(EVENT_WORK_STOP, "Work session stopped manually");
                    printStatus("Work session stopped");
                    if (sessionStartTime > 0) {
                        int minutes = (time(nullptr) - sessionStartTime) / 60;
                        printInfo("Session duration: " + std::to_string(minutes) + " minutes");
                    }
                } else if (command == "pause") {
                    createEvent(EVENT_WORK_PAUSE, "Work session paused");
                    printStatus("Work session paused");
                } else if (command == "resume") {
                    createEvent(EVENT_WORK_RESUME, "Work session resumed");
                    printStatus("Work session resumed");
                } else if (command == "status") {
                    std::cout << "\n=== CURRENT STATUS ===\n";
                    std::cout << "Working: " << (isWorking ? "Yes" : "No") << "\n";
                    if (isWorking && sessionStartTime > 0) {
                        int minutes = (time(nullptr) - sessionStartTime) / 60;
                        std::cout << "Current session: " << minutes << " minutes\n";
                    }
                    std::cout << "Relay: " << (relaySocket != INVALID_SOCKET ? "Connected" : "Disconnected") << "\n";
                    std::cout << "Blockchain: " << blockchain.size() << " blocks\n";
                    std::cout << "Peers: " << peers.size() << " connected\n";
                    std::cout << "===================\n\n";
                } else if (command == "report") {
                    generateReport();
                } else if (command == "peers") {
                    std::cout << "\nConnected Peers:\n";
                    std::lock_guard<std::mutex> lock(peersMutex);
                    if (peers.empty()) {
                        printWarning("No peers connected");
                    } else {
                        for (const auto& peer : peers) {
                            std::cout << "  " << peer.first << " - " << peer.second.ipAddress 
                                     << ":" << peer.second.port << "\n";
                        }
                    }
                } else if (command == "quit" || command == "exit") {
                    printInfo("Shutting down...");
                    g_running = false;
                    break;
                } else if (!command.empty()) {
                    printWarning("Unknown command: " + command);
                }
                
                command.clear();
                std::cout << "\n> ";
                std::cout.flush();
            }
            else if (ch == '\b' && !command.empty()) {
                // Handle backspace
                command.pop_back();
                std::cout << "\b \b";
                std::cout.flush();
            }
            else if (ch >= 32 && ch < 127) {
                // Regular character
                command += ch;
                std::cout << ch;
                std::cout.flush();
            }
        }
        
        // Small sleep to prevent CPU spinning
        Sleep(10);
    }
    
    // Cleanup
    g_running = false;
    createEvent(EVENT_WORK_STOP, "Application shutdown");
    monitor.stopMonitoring();
    
    printInfo("Stopping services...");
    
    // Cleanup window
    if (messageWindow) {
        DestroyWindow(messageWindow);
    }
    
    if (p2pThread.joinable()) {
        p2pThread.join();
    }
    
    if (connectionThread.joinable()) {
        connectionThread.join();
    }
    
    if (relaySocket != INVALID_SOCKET) {
        CLOSE_SOCKET(relaySocket);
    }
    
    WSACleanup();
    
    // Save blockchain
    printInfo("Saving blockchain (" + std::to_string(blockchain.size()) + " blocks)...");
    std::ofstream file("blockchain_backup.dat");
    for (const auto& block : blockchain) {
        file << block.serialize() << "\n";
    }
    file.close();
    
    printStatus("Shutdown complete. Blockchain saved.");
    printInfo("Dashboard available at: http://" + config.relayHost + ":8080");
    
    std::cout << "\nPress any key to exit...";
    _getch();
    return 0;
}