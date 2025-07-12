// timetracking_server.cpp - Complete P2P Time Tracking Relay Server
// Compile: g++ -std=c++11 -pthread timetracking_server.cpp -o timetracking_server -lsqlite3

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
#include <sqlite3.h>
#include <signal.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <set>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define CLOSE_SOCKET close
#endif

// Global flag for shutdown
volatile bool g_running = true;

// Signal handler
void signalHandler(int sig) {
    std::cout << "\nShutting down server..." << std::endl;
    g_running = false;
}

// Main server class
class TimeTrackingServer {
private:
    // Configuration
    int relayPort;
    int httpPort;
    std::string dbPath;
    std::string adminPassword;
    
    // Sockets
    SOCKET relaySocket;
    SOCKET httpSocket;
    
    // Database
    sqlite3* database;
    
    // Client management
    struct ClientInfo {
        std::string deviceId;
        std::string deviceName;
        std::string publicIP;
        SOCKET socket;
        time_t lastSeen;
        int workedMinutes;
        int p2pPort;
    };
    
    std::map<std::string, ClientInfo> clients;
    std::mutex clientMutex;
    std::mutex dbMutex;
    
    // Statistics
    int totalConnections;
    int totalBlocks;
    std::chrono::steady_clock::time_point startTime;
    
public:
    TimeTrackingServer() : 
        relayPort(9999),
        httpPort(8080),
        dbPath("/app/data/timetracking.db"),
        adminPassword("admin123"),
        relaySocket(INVALID_SOCKET),
        httpSocket(INVALID_SOCKET),
        database(nullptr),
        totalConnections(0),
        totalBlocks(0),
        startTime(std::chrono::steady_clock::now()) {
        
        // Read environment variables if set
        const char* envPort = std::getenv("RELAY_PORT");
        if (envPort) relayPort = std::atoi(envPort);
        
        const char* envHttp = std::getenv("HTTP_PORT");
        if (envHttp) httpPort = std::atoi(envHttp);
        
        const char* envDb = std::getenv("DB_PATH");
        if (envDb) dbPath = envDb;
        
        const char* envPass = std::getenv("ADMIN_PASSWORD");
        if (envPass) adminPassword = envPass;
    }
    
    ~TimeTrackingServer() {
        cleanup();
    }
    
    void start() {
        std::cout << "================================================\n";
        std::cout << "   P2P Time Tracking Relay Server v2.0\n";
        std::cout << "================================================\n";
        std::cout << "Relay Port: " << relayPort << "\n";
        std::cout << "HTTP Port: " << httpPort << "\n";
        std::cout << "Database: " << dbPath << "\n";
        std::cout << "Dashboard: http://0.0.0.0:" << httpPort << "\n";
        std::cout << "================================================\n\n";
        
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed\n";
            return;
        }
#endif
        
        if (!initDatabase()) {
            std::cerr << "Failed to initialize database\n";
            return;
        }
        
        // Start servers
        std::thread relayThread(&TimeTrackingServer::runRelayServer, this);
        std::thread httpThread(&TimeTrackingServer::runHttpServer, this);
        
        // Periodic cleanup thread
        std::thread cleanupThread(&TimeTrackingServer::periodicCleanup, this);
        
        // Wait for threads
        relayThread.join();
        httpThread.join();
        cleanupThread.join();
        
        cleanup();
    }
    
private:
    bool initDatabase() {
        int rc = sqlite3_open(dbPath.c_str(), &database);
        if (rc != SQLITE_OK) {
            std::cerr << "Cannot open database: " << sqlite3_errmsg(database) << "\n";
            return false;
        }
        
        const char* createTables = R"(
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                device_name TEXT,
                event_type TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                worked_minutes INTEGER DEFAULT 0,
                block_hash TEXT,
                block_data TEXT,
                ip_address TEXT
            );
            
            CREATE TABLE IF NOT EXISTS daily_summary (
                device_id TEXT,
                date DATE,
                total_minutes INTEGER DEFAULT 0,
                sessions INTEGER DEFAULT 0,
                first_activity DATETIME,
                last_update DATETIME,
                PRIMARY KEY (device_id, date)
            );
            
            CREATE TABLE IF NOT EXISTS peer_connections (
                device_id TEXT PRIMARY KEY,
                ip_address TEXT,
                p2p_port INTEGER,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        )";
        
        char* errMsg = nullptr;
        rc = sqlite3_exec(database, createTables, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error: " << errMsg << "\n";
            sqlite3_free(errMsg);
            return false;
        }
        
        std::cout << "Database initialized successfully\n";
        return true;
    }
    
    void runRelayServer() {
        relaySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (relaySocket == INVALID_SOCKET) {
            std::cerr << "Failed to create relay socket\n";
            return;
        }
        
        // Allow socket reuse
        int opt = 1;
        setsockopt(relaySocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        // Bind socket
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(relayPort);
        
        if (bind(relaySocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "Failed to bind relay socket to port " << relayPort << "\n";
            CLOSE_SOCKET(relaySocket);
            return;
        }
        
        if (listen(relaySocket, 50) == SOCKET_ERROR) {
            std::cerr << "Failed to listen on relay socket\n";
            CLOSE_SOCKET(relaySocket);
            return;
        }
        
        std::cout << "Relay server listening on port " << relayPort << "\n";
        
        // Accept connections
        while (g_running) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(relaySocket, (struct sockaddr*)&clientAddr, &clientLen);
            if (clientSocket != INVALID_SOCKET) {
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
                
                totalConnections++;
                std::cout << "[" << getCurrentTimeString() << "] New connection from " << clientIP 
                          << " (Total: " << totalConnections << ")\n";
                
                std::thread clientThread(&TimeTrackingServer::handleRelayClient, this, clientSocket, std::string(clientIP));
                clientThread.detach();
            }
        }
        
        CLOSE_SOCKET(relaySocket);
    }
    
    void handleRelayClient(SOCKET clientSocket, const std::string& clientIP) {
        char buffer[4096];
        std::string deviceId;
        
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = 300;  // 5 minute timeout
        tv.tv_usec = 0;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
        
        while (g_running) {
            int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (received <= 0) break;
            
            buffer[received] = '\0';
            std::string message(buffer);
            
            // Handle multiple messages in one buffer
            std::stringstream ss(message);
            std::string line;
            
            while (std::getline(ss, line)) {
                if (line.empty()) continue;
                
                // Process different message types
                if (line.find("BLOCK|") == 0) {
                    processBlockMessage(line, clientIP, deviceId);
                }
                else if (line.find("RELAY|") == 0) {
                    processRelayMessage(line, clientIP, clientSocket, deviceId);
                }
                else if (line.find("STATUS|") == 0) {
                    processStatusMessage(line, clientIP);
                }
            }
        }
        
        CLOSE_SOCKET(clientSocket);
        if (!deviceId.empty()) {
            removeClient(deviceId);
            std::cout << "[" << getCurrentTimeString() << "] Client disconnected: " << deviceId << "\n";
        }
    }
    
    void processBlockMessage(const std::string& message, const std::string& clientIP, const std::string& deviceId) {
        // Parse blockchain block
        std::vector<std::string> parts = split(message, '|');
        if (parts.size() < 8) return;
        
        std::string blockDeviceId = parts[3];
        std::string eventType = parts[4];
        std::string timestamp = parts[2];
        std::string blockHash = parts[6];
        
        std::string deviceName = blockDeviceId; // Default to deviceId
        if (parts.size() > 8 && !parts[8].empty()) {
            deviceName = parts[8];
        }
        
        int workedMinutes = 0;
        if (parts.size() > 9 && !parts[9].empty()) {
            try {
                workedMinutes = std::stoi(parts[9]);
            } catch (...) {}
        }
        
        // Update client info
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            ClientInfo& client = clients[blockDeviceId];
            client.deviceId = blockDeviceId;
            client.deviceName = deviceName;
            client.publicIP = clientIP;
            client.lastSeen = time(nullptr);
            if (workedMinutes > 0) {
                client.workedMinutes += workedMinutes;
            }
        }
        
        // Store in database
        storeEvent(blockDeviceId, deviceName, eventType, workedMinutes, blockHash, message, clientIP);
        
        // Update daily summary
        updateDailySummary(blockDeviceId, eventType, workedMinutes);
        
        totalBlocks++;
        std::cout << "[" << getCurrentTimeString() << "] Block: " << blockDeviceId 
                  << " - " << eventType;
        if (workedMinutes > 0) {
            std::cout << " (" << workedMinutes << " min)";
        }
        std::cout << " [Total blocks: " << totalBlocks << "]\n";
    }
    
    void processRelayMessage(const std::string& message, const std::string& clientIP, SOCKET socket, std::string& deviceId) {
        std::vector<std::string> parts = split(message, '|');
        if (parts.size() < 3) return;
        
        std::string command = parts[1];
        deviceId = parts[2];
        
        if (command == "REGISTER") {
            int p2pPort = 8888; // default
            if (parts.size() > 3) {
                try {
                    p2pPort = std::stoi(parts[3]);
                } catch (...) {}
            }
            
            {
                std::lock_guard<std::mutex> lock(clientMutex);
                ClientInfo& client = clients[deviceId];
                client.deviceId = deviceId;
                client.deviceName = deviceId;
                client.publicIP = clientIP;
                client.socket = socket;
                client.lastSeen = time(nullptr);
                client.p2pPort = p2pPort;
            }
            
            // Update peer connections in database
            updatePeerConnection(deviceId, clientIP, p2pPort);
            
            std::cout << "[" << getCurrentTimeString() << "] Device registered: " << deviceId 
                      << " from " << clientIP << ":" << p2pPort << "\n";
            
            // Send acknowledgment
            std::string ack = "RELAY|ACK|SERVER|Registration successful\n";
            send(socket, ack.c_str(), ack.length(), 0);
            
            // Send current peer list
            sendPeerList(socket, deviceId);
        }
        else if (command == "GET_PEERS") {
            sendPeerList(socket, deviceId);
        }
    }
    
    void sendPeerList(SOCKET socket, const std::string& requestingDevice) {
        std::stringstream response;
        response << "RELAY|PEER_LIST|SERVER";
        
        std::lock_guard<std::mutex> lock(clientMutex);
        for (const auto& pair : clients) {
            if (pair.first != requestingDevice) {  // Don't send device its own info
                const ClientInfo& peer = pair.second;
                if (time(nullptr) - peer.lastSeen < 300) { // Only active peers (5 min)
                    response << "|" << peer.deviceId << ";" << peer.publicIP << ";" << peer.p2pPort;
                }
            }
        }
        response << "\n";
        
        std::string responseStr = response.str();
        send(socket, responseStr.c_str(), responseStr.length(), 0);
        
        // Log peer list sent
        int peerCount = std::count(responseStr.begin(), responseStr.end(), ';');
        std::cout << "[" << getCurrentTimeString() << "] Sent " << peerCount 
                  << " peers to " << requestingDevice << "\n";
    }
    
    void processStatusMessage(const std::string& message, const std::string& clientIP) {
        // Update client status
        std::vector<std::string> parts = split(message, '|');
        if (parts.size() < 3) return;
        
        std::string deviceId = parts[1];
        std::string status = parts[2];
        
        std::lock_guard<std::mutex> lock(clientMutex);
        if (clients.find(deviceId) != clients.end()) {
            clients[deviceId].lastSeen = time(nullptr);
        }
    }
    
    void updatePeerConnection(const std::string& deviceId, const std::string& ip, int port) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        const char* sql = R"(
            INSERT OR REPLACE INTO peer_connections (device_id, ip_address, p2p_port, last_seen)
            VALUES (?, ?, ?, datetime('now'))
        )";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, deviceId.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, port);
            
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    void periodicCleanup() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            
            // Clean up inactive clients
            {
                std::lock_guard<std::mutex> lock(clientMutex);
                time_t now = time(nullptr);
                
                for (auto it = clients.begin(); it != clients.end(); ) {
                    if (now - it->second.lastSeen > 600) { // 10 minutes
                        std::cout << "[" << getCurrentTimeString() << "] Removing inactive client: " 
                                  << it->first << "\n";
                        it = clients.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            
            // Log server stats
            std::cout << "[" << getCurrentTimeString() << "] Server stats - Active clients: " 
                      << clients.size() << ", Total blocks: " << totalBlocks 
                      << ", Total connections: " << totalConnections << "\n";
        }
    }
    
    void runHttpServer() {
        httpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (httpSocket == INVALID_SOCKET) {
            std::cerr << "Failed to create HTTP socket\n";
            return;
        }
        
        // Allow socket reuse
        int opt = 1;
        setsockopt(httpSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        // Bind socket
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(httpPort);
        
        if (bind(httpSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "Failed to bind HTTP socket to port " << httpPort << "\n";
            CLOSE_SOCKET(httpSocket);
            return;
        }
        
        if (listen(httpSocket, 10) == SOCKET_ERROR) {
            std::cerr << "Failed to listen on HTTP socket\n";
            CLOSE_SOCKET(httpSocket);
            return;
        }
        
        std::cout << "HTTP server listening on port " << httpPort << "\n";
        std::cout << "Dashboard available at: http://0.0.0.0:" << httpPort << "\n";
        
        // Accept connections
        while (g_running) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(httpSocket, (struct sockaddr*)&clientAddr, &clientLen);
            if (clientSocket != INVALID_SOCKET) {
                std::thread clientThread(&TimeTrackingServer::handleHttpClient, this, clientSocket);
                clientThread.detach();
            }
        }
        
        CLOSE_SOCKET(httpSocket);
    }
    
    void handleHttpClient(SOCKET clientSocket) {
        char buffer[4096];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            CLOSE_SOCKET(clientSocket);
            return;
        }
        
        buffer[received] = '\0';
        std::string request(buffer);
        
        // Parse HTTP request
        std::string method, path, version;
        std::stringstream ss(request);
        ss >> method >> path >> version;
        
        // Route request
        if (path == "/" || path == "/dashboard") {
            serveDashboard(clientSocket);
        }
        else if (path == "/api/status") {
            serveApiStatus(clientSocket);
        }
        else if (path == "/api/events" || path.find("/api/events?") == 0) {
            serveApiEvents(clientSocket);
        }
        else if (path == "/api/summary") {
            serveApiSummary(clientSocket);
        }
        else if (path == "/api/peers") {
            serveApiPeers(clientSocket);
        }
        else if (path == "/health") {
            serveHealth(clientSocket);
        }
        else {
            serve404(clientSocket);
        }
        
        CLOSE_SOCKET(clientSocket);
    }
    
void serveDashboard(SOCKET socket) {
    std::stringstream html;
    
    // Build enhanced HTML dashboard with per-peer view
    html << "<!DOCTYPE html>\n<html>\n<head>\n";
    html << "<title>P2P Time Tracking Dashboard</title>\n";
    html << "<meta charset=\"UTF-8\">\n";
    html << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html << "<style>\n";
    html << "body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }\n";
    html << ".container { max-width: 1400px; margin: 0 auto; }\n";
    html << "h1, h2 { color: #333; }\n";
    html << ".header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }\n";
    html << ".stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }\n";
    html << ".stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }\n";
    html << ".stat-value { font-size: 36px; font-weight: bold; color: #2563eb; }\n";
    html << ".stat-label { color: #666; margin-top: 5px; }\n";
    html << ".peer-section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n";
    html << ".peer-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }\n";
    html << ".peer-name { font-size: 20px; font-weight: bold; color: #2563eb; }\n";
    html << ".peer-status { display: flex; gap: 20px; align-items: center; }\n";
    html << ".status-badge { padding: 5px 15px; border-radius: 20px; font-size: 14px; font-weight: bold; }\n";
    html << ".online { background: #10b981; color: white; }\n";
    html << ".offline { background: #ef4444; color: white; }\n";
    html << ".peer-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }\n";
    html << ".peer-stat { background: #f9fafb; padding: 15px; border-radius: 6px; text-align: center; }\n";
    html << ".peer-stat-value { font-size: 24px; font-weight: bold; color: #374151; }\n";
    html << ".peer-stat-label { font-size: 12px; color: #6b7280; margin-top: 5px; }\n";
    html << "table { width: 100%; border-collapse: collapse; }\n";
    html << "th { background: #f3f4f6; padding: 12px; text-align: left; font-weight: 600; color: #374151; }\n";
    html << "td { padding: 12px; border-top: 1px solid #e5e7eb; }\n";
    html << ".event-type { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }\n";
    html << ".work-event { background: #dbeafe; color: #1e40af; }\n";
    html << ".system-event { background: #fef3c7; color: #92400e; }\n";
    html << ".idle-event { background: #e5e7eb; color: #374151; }\n";
    html << ".suspicious-event { background: #fee2e2; color: #991b1b; }\n";
    html << ".timeline { position: relative; padding-left: 30px; }\n";
    html << ".timeline-item { position: relative; padding-bottom: 20px; }\n";
    html << ".timeline-item::before { content: ''; position: absolute; left: -25px; top: 5px; width: 10px; height: 10px; border-radius: 50%; background: #2563eb; }\n";
    html << ".timeline-line { position: absolute; left: -20px; top: 15px; bottom: 0; width: 2px; background: #e5e7eb; }\n";
    html << ".refresh-btn { background: #2563eb; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }\n";
    html << ".tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 2px solid #e5e7eb; }\n";
    html << ".tab { padding: 10px 20px; background: transparent; border: none; cursor: pointer; transition: all 0.3s; font-weight: 500; color: #6b7280; border-bottom: 2px solid transparent; margin-bottom: -2px; }\n";
    html << ".tab.active { color: #2563eb; border-bottom-color: #2563eb; }\n";
    html << ".tab:hover { color: #1e40af; }\n";
    html << ".tab-content { display: none; }\n";
    html << ".tab-content.active { display: block; }\n";
    html << ".server-info { background: #f3f4f6; padding: 10px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; }\n";
    html << ".chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }\n";
    html << ".activity-heatmap { display: grid; grid-template-columns: repeat(24, 1fr); gap: 2px; margin-top: 10px; }\n";
    html << ".hour-cell { height: 30px; background: #e5e7eb; border-radius: 2px; position: relative; cursor: pointer; }\n";
    html << ".hour-cell.active { background: #3b82f6; }\n";
    html << ".hour-cell:hover::after { content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: #1f2937; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; white-space: nowrap; z-index: 10; }\n";
    html << "</style>\n</head>\n<body>\n";
    
    html << "<div class=\"container\">\n";
    html << "<div class=\"header\">\n";
    html << "<h1>P2P Time Tracking Dashboard</h1>\n";
    html << "<button class=\"refresh-btn\" onclick=\"location.reload()\">Refresh</button>\n";
    html << "</div>\n";
    
    // Server info
    html << "<div class=\"server-info\">\n";
    html << "Relay Server: <strong>51.178.139.139:9999</strong> | ";
    html << "Dashboard: <strong>http://51.178.139.139:8080</strong> | ";
    html << "Server Time: <strong><span id=\"serverTime\"></span></strong> | ";
    html << "Uptime: <strong><span id=\"uptime\"></span></strong>\n";
    html << "</div>\n";
    
    // Global statistics
    html << "<div class=\"stats\">\n";
    html << "<div class=\"stat-card\"><div class=\"stat-value\" id=\"totalDevices\">0</div><div class=\"stat-label\">Total Devices</div></div>\n";
    html << "<div class=\"stat-card\"><div class=\"stat-value\" id=\"onlineDevices\">0</div><div class=\"stat-label\">Online Now</div></div>\n";
    html << "<div class=\"stat-card\"><div class=\"stat-value\" id=\"totalHours\">0</div><div class=\"stat-label\">Total Hours Today</div></div>\n";
    html << "<div class=\"stat-card\"><div class=\"stat-value\" id=\"totalBlocks\">0</div><div class=\"stat-label\">Total Blocks</div></div>\n";
    html << "</div>\n";
    
    // Tabs for different views
    html << "<div class=\"tabs\">\n";
    html << "<button class=\"tab active\" onclick=\"showTab('peers')\">Peers</button>\n";
    html << "<button class=\"tab\" onclick=\"showTab('timeline')\">Timeline</button>\n";
    html << "<button class=\"tab\" onclick=\"showTab('summary')\">Summary</button>\n";
    html << "<button class=\"tab\" onclick=\"showTab('analytics')\">Analytics</button>\n";
    html << "</div>\n";
    
    // Peers tab content
    html << "<div id=\"peers\" class=\"tab-content active\">\n";
    html << "<h2>Connected Peers</h2>\n";
    html << "<div id=\"peersContainer\"></div>\n";
    html << "</div>\n";
    
    // Timeline tab content
    html << "<div id=\"timeline\" class=\"tab-content\">\n";
    html << "<h2>Global Timeline</h2>\n";
    html << "<div id=\"timelineContainer\" class=\"timeline\"></div>\n";
    html << "</div>\n";
    
    // Summary tab content
    html << "<div id=\"summary\" class=\"tab-content\">\n";
    html << "<h2>Daily Summary</h2>\n";
    html << "<table><thead><tr><th>Device</th><th>Total Hours</th><th>Sessions</th><th>First Activity</th><th>Last Activity</th><th>Status</th></tr></thead>\n";
    html << "<tbody id=\"summaryBody\"></tbody></table>\n";
    html << "</div>\n";
    
    // Analytics tab content
    html << "<div id=\"analytics\" class=\"tab-content\">\n";
    html << "<h2>Analytics</h2>\n";
    html << "<div class=\"chart-container\">\n";
    html << "<h3>Activity Heatmap (24 Hours)</h3>\n";
    html << "<div id=\"activityHeatmap\" class=\"activity-heatmap\"></div>\n";
    html << "<div style=\"margin-top: 10px; font-size: 12px; color: #6b7280;\">\n";
    html << "Hour: ";
    for (int i = 0; i < 24; i++) {
        html << "<span style=\"margin: 0 5px;\">" << i << "</span>";
    }
    html << "</div>\n";
    html << "</div>\n";
    html << "<div class=\"chart-container\">\n";
    html << "<h3>Top Workers Today</h3>\n";
    html << "<div id=\"topWorkers\"></div>\n";
    html << "</div>\n";
    html << "</div>\n";
    
    html << "</div>\n";
    
    // JavaScript
    html << "<script>\n";
    
    // Server time and uptime
    html << "let serverStartTime = " << std::chrono::duration_cast<std::chrono::milliseconds>(
        startTime.time_since_epoch()).count() << ";\n";
    
    html << "function updateServerInfo() {\n";
    html << "  const now = new Date();\n";
    html << "  document.getElementById('serverTime').textContent = now.toLocaleString();\n";
    html << "  const uptime = Math.floor((now.getTime() - serverStartTime) / 1000);\n";
    html << "  const days = Math.floor(uptime / 86400);\n";
    html << "  const hours = Math.floor((uptime % 86400) / 3600);\n";
    html << "  const minutes = Math.floor((uptime % 3600) / 60);\n";
    html << "  document.getElementById('uptime').textContent = `${days}d ${hours}h ${minutes}m`;\n";
    html << "}\n";
    html << "updateServerInfo();\n";
    html << "setInterval(updateServerInfo, 1000);\n";
    
    // Tab switching
    html << "function showTab(tabName) {\n";
    html << "  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));\n";
    html << "  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));\n";
    html << "  event.target.classList.add('active');\n";
    html << "  document.getElementById(tabName).classList.add('active');\n";
    html << "}\n";
    
    // Event type styling
    html << "function getEventClass(eventType) {\n";
    html << "  if (eventType.includes('WORK')) return 'work-event';\n";
    html << "  if (eventType.includes('SYSTEM') || eventType.includes('SESSION')) return 'system-event';\n";
    html << "  if (eventType.includes('IDLE')) return 'idle-event';\n";
    html << "  if (eventType.includes('SUSPICIOUS')) return 'suspicious-event';\n";
    html << "  return '';\n";
    html << "}\n";
    
    // Format duration
    html << "function formatDuration(minutes) {\n";
    html << "  const hours = Math.floor(minutes / 60);\n";
    html << "  const mins = minutes % 60;\n";
    html << "  return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;\n";
    html << "}\n";
    
    // Load data
    html << "function loadData() {\n";
    
    // Load status
    html << "  fetch('/api/status').then(r => r.json()).then(data => {\n";
    html << "    document.getElementById('totalDevices').textContent = data.totalDevices || 0;\n";
    html << "    document.getElementById('onlineDevices').textContent = data.onlineDevices || 0;\n";
    html << "    document.getElementById('totalBlocks').textContent = data.totalBlocks || 0;\n";
    html << "  }).catch(err => console.error('Failed to load status:', err));\n";
    
    // Load peer data
    html << "  fetch('/api/peers').then(r => r.json()).then(peers => {\n";
    html << "    const container = document.getElementById('peersContainer');\n";
    html << "    container.innerHTML = '';\n";
    html << "    let totalHours = 0;\n";
    html << "    \n";
    html << "    if (peers.length === 0) {\n";
    html << "      container.innerHTML = '<div style=\"text-align: center; padding: 40px; color: #6b7280;\">No peers connected yet</div>';\n";
    html << "      return;\n";
    html << "    }\n";
    html << "    \n";
    html << "    peers.forEach(peer => {\n";
    html << "      const peerHtml = `\n";
    html << "        <div class=\"peer-section\">\n";
    html << "          <div class=\"peer-header\">\n";
    html << "            <div class=\"peer-name\">${peer.device_name || peer.device_id} (${peer.device_id})</div>\n";
    html << "            <div class=\"peer-status\">\n";
    html << "              <span class=\"status-badge ${peer.is_online ? 'online' : 'offline'}\">\n";
    html << "                ${peer.is_online ? 'Online' : 'Offline'}\n";
    html << "              </span>\n";
    html << "              <span style=\"color: #6b7280;\">IP: ${peer.ip_address || 'N/A'}</span>\n";
    html << "              <span style=\"color: #6b7280;\">Port: ${peer.p2p_port || 'N/A'}</span>\n";
    html << "            </div>\n";
    html << "          </div>\n";
    html << "          <div class=\"peer-stats\">\n";
    html << "            <div class=\"peer-stat\">\n";
    html << "              <div class=\"peer-stat-value\">${formatDuration(peer.today_minutes || 0)}</div>\n";
    html << "              <div class=\"peer-stat-label\">Today</div>\n";
    html << "            </div>\n";
    html << "            <div class=\"peer-stat\">\n";
    html << "              <div class=\"peer-stat-value\">${peer.total_blocks || 0}</div>\n";
    html << "              <div class=\"peer-stat-label\">Events</div>\n";
    html << "            </div>\n";
    html << "            <div class=\"peer-stat\">\n";
    html << "              <div class=\"peer-stat-value\">${peer.sessions_today || 0}</div>\n";
    html << "              <div class=\"peer-stat-label\">Sessions</div>\n";
    html << "            </div>\n";
    html << "            <div class=\"peer-stat\">\n";
    html << "              <div class=\"peer-stat-value\">${peer.suspicious_events || 0}</div>\n";
    html << "              <div class=\"peer-stat-label\">Suspicious</div>\n";
    html << "            </div>\n";
    html << "          </div>\n";
    html << "          <h4>Recent Activity</h4>\n";
    html << "          <div class=\"timeline\">\n";
    html << "            ${peer.recent_events && peer.recent_events.length > 0 ? peer.recent_events.map((e, i) => `\n";
    html << "              <div class=\"timeline-item\">\n";
    html << "                ${i < peer.recent_events.length - 1 ? '<div class=\"timeline-line\"></div>' : ''}\n";
    html << "                <strong>${new Date(e.timestamp).toLocaleTimeString()}</strong>\n";
    html << "                <span class=\"event-type ${getEventClass(e.event_type)}\">${e.event_type}</span>\n";
    html << "                ${e.description ? `<br><small style=\"color: #6b7280;\">${e.description}</small>` : ''}\n";
    html << "                ${e.worked_minutes > 0 ? `<br><small style=\"color: #059669;\">⏱ ${e.worked_minutes} minutes</small>` : ''}\n";
    html << "              </div>\n";
    html << "            `).join('') : '<div style=\"color: #6b7280;\">No recent activity</div>'}\n";
    html << "          </div>\n";
    html << "        </div>\n";
    html << "      `;\n";
    html << "      container.innerHTML += peerHtml;\n";
    html << "      totalHours += (peer.today_minutes || 0);\n";
    html << "    });\n";
    html << "    document.getElementById('totalHours').textContent = Math.floor(totalHours / 60);\n";
    html << "  }).catch(err => console.error('Failed to load peers:', err));\n";
    
    // Load timeline
    html << "  fetch('/api/events?limit=50').then(r => r.json()).then(events => {\n";
    html << "    const container = document.getElementById('timelineContainer');\n";
    html << "    if (events.length === 0) {\n";
    html << "      container.innerHTML = '<div style=\"color: #6b7280;\">No events recorded yet</div>';\n";
    html << "      return;\n";
    html << "    }\n";
    html << "    container.innerHTML = events.map((e, i) => `\n";
    html << "      <div class=\"timeline-item\">\n";
    html << "        ${i < events.length - 1 ? '<div class=\"timeline-line\"></div>' : ''}\n";
    html << "        <strong>${new Date(e.timestamp).toLocaleString()}</strong>\n";
    html << "        <span class=\"event-type ${getEventClass(e.event_type)}\">${e.event_type}</span>\n";
    html << "        <strong style=\"color: #2563eb;\">${e.device_name || e.device_id}</strong>\n";
    html << "        ${e.description ? `<br><small style=\"color: #6b7280;\">${e.description}</small>` : ''}\n";
    html << "        ${e.worked_minutes > 0 ? `<br><small style=\"color: #059669;\">⏱ ${e.worked_minutes} minutes</small>` : ''}\n";
    html << "      </div>\n";
    html << "    `).join('');\n";
    html << "  }).catch(err => console.error('Failed to load timeline:', err));\n";
    
    // Load summary
    html << "  fetch('/api/summary').then(r => r.json()).then(data => {\n";
    html << "    const tbody = document.getElementById('summaryBody');\n";
    html << "    if (data.length === 0) {\n";
    html << "      tbody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align: center; color: #6b7280;\">No activity today</td></tr>';\n";
    html << "      return;\n";
    html << "    }\n";
    html << "    tbody.innerHTML = data.map(s => `\n";
    html << "      <tr>\n";
    html << "        <td><strong>${s.device_name || s.device_id}</strong><br><small style=\"color: #6b7280;\">${s.device_id}</small></td>\n";
    html << "        <td>${formatDuration(s.minutes || 0)}</td>\n";
    html << "        <td>${s.sessions || 0}</td>\n";
    html << "        <td>${s.first_activity ? new Date(s.first_activity).toLocaleTimeString() : '-'}</td>\n";
    html << "        <td>${s.last_seen ? new Date(s.last_seen).toLocaleTimeString() : '-'}</td>\n";
    html << "        <td><span class=\"status-badge ${s.is_online ? 'online' : 'offline'}\">${s.is_online ? 'Online' : 'Offline'}</span></td>\n";
    html << "      </tr>\n";
    html << "    `).join('');\n";
    html << "    \n";
    html << "    // Update analytics\n";
    html << "    updateAnalytics(data);\n";
    html << "  }).catch(err => console.error('Failed to load summary:', err));\n";
    html << "}\n";
    
    // Update analytics
    html << "function updateAnalytics(summaryData) {\n";
    html << "  // Activity heatmap\n";
    html << "  fetch('/api/events?limit=1000').then(r => r.json()).then(events => {\n";
    html << "    const hourCounts = new Array(24).fill(0);\n";
    html << "    const today = new Date().toDateString();\n";
    html << "    \n";
    html << "    events.forEach(e => {\n";
    html << "      const eventDate = new Date(e.timestamp);\n";
    html << "      if (eventDate.toDateString() === today && e.event_type.includes('WORK')) {\n";
    html << "        hourCounts[eventDate.getHours()]++;\n";
    html << "      }\n";
    html << "    });\n";
    html << "    \n";
    html << "    const maxCount = Math.max(...hourCounts, 1);\n";
    html << "    const heatmapHtml = hourCounts.map((count, hour) => {\n";
    html << "      const intensity = count / maxCount;\n";
    html << "      const opacity = 0.2 + (intensity * 0.8);\n";
    html << "      return `<div class=\"hour-cell\" style=\"background: rgba(59, 130, 246, ${opacity});\" data-tooltip=\"${hour}:00 - ${count} events\"></div>`;\n";
    html << "    }).join('');\n";
    html << "    \n";
    html << "    document.getElementById('activityHeatmap').innerHTML = heatmapHtml;\n";
    html << "  });\n";
    html << "  \n";
    html << "  // Top workers\n";
    html << "  const sorted = [...summaryData].sort((a, b) => (b.minutes || 0) - (a.minutes || 0)).slice(0, 5);\n";
    html << "  const topWorkersHtml = sorted.map((s, i) => `\n";
    html << "    <div style=\"display: flex; justify-content: space-between; padding: 10px; background: ${i % 2 === 0 ? '#f9fafb' : 'white'};\">\n";
    html << "      <span>${i + 1}. ${s.device_name || s.device_id}</span>\n";
    html << "      <strong>${formatDuration(s.minutes || 0)}</strong>\n";
    html << "    </div>\n";
    html << "  `).join('');\n";
    html << "  \n";
    html << "  document.getElementById('topWorkers').innerHTML = topWorkersHtml || '<div style=\"color: #6b7280; padding: 20px; text-align: center;\">No data available</div>';\n";
    html << "}\n";
    
    html << "loadData();\n";
    html << "setInterval(loadData, 30000);\n";
    html << "</script>\n";
    
    html << "</body>\n</html>\n";
    
    sendHttpResponse(socket, html.str());
}
    
    void serveApiStatus(SOCKET socket) {
        int onlineCount = 0;
        time_t now = time(nullptr);
        
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            for (const auto& pair : clients) {
                if (now - pair.second.lastSeen < 300) { // 5 minutes timeout
                    onlineCount++;
                }
            }
        }
        
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();
        
        std::stringstream json;
        json << "{";
        json << "\"totalDevices\":" << clients.size() << ",";
        json << "\"onlineDevices\":" << onlineCount << ",";
        json << "\"totalBlocks\":" << totalBlocks << ",";
        json << "\"totalConnections\":" << totalConnections << ",";
        json << "\"uptime\":" << uptime;
        json << "}";
        
        sendHttpResponse(socket, json.str(), "application/json");
    }
    
    void serveApiEvents(SOCKET socket) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        const char* sql = "SELECT device_id, device_name, event_type, timestamp, worked_minutes, block_data FROM events ORDER BY timestamp DESC LIMIT 50";
        sqlite3_stmt* stmt;
        
        std::stringstream json;
        json << "[";
        
        if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                if (!first) json << ",";
                json << "{";
                json << "\"device_id\":\"" << sqlite3_column_text(stmt, 0) << "\",";
                json << "\"device_name\":\"" << (sqlite3_column_text(stmt, 1) ? (const char*)sqlite3_column_text(stmt, 1) : "") << "\",";
                json << "\"event_type\":\"" << sqlite3_column_text(stmt, 2) << "\",";
                json << "\"timestamp\":\"" << sqlite3_column_text(stmt, 3) << "\",";
                json << "\"worked_minutes\":" << sqlite3_column_int(stmt, 4);
                
                // Parse description from block data
                const char* blockData = (const char*)sqlite3_column_text(stmt, 5);
                if (blockData) {
                    std::string data(blockData);
                    size_t descPos = data.find("description=");
                    if (descPos != std::string::npos) {
                        descPos += 12;
                        size_t endPos = data.find(";", descPos);
                        if (endPos != std::string::npos) {
                            json << ",\"description\":\"" << data.substr(descPos, endPos - descPos) << "\"";
                        }
                    }
                }
                
                json << "}";
                first = false;
            }
            sqlite3_finalize(stmt);
        }
        
        json << "]";
        sendHttpResponse(socket, json.str(), "application/json");
    }
    
    void serveApiSummary(SOCKET socket) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        char today[11];
        time_t now = time(nullptr);
        strftime(today, sizeof(today), "%Y-%m-%d", localtime(&now));
        
        const char* sql = R"(
            SELECT 
                ds.device_id,
                MAX(e.device_name) as device_name,
                ds.total_minutes as minutes,
                ds.sessions,
                ds.first_activity,
                ds.last_update as last_seen
            FROM daily_summary ds
            LEFT JOIN events e ON ds.device_id = e.device_id
            WHERE ds.date = ?
            GROUP BY ds.device_id
            ORDER BY ds.total_minutes DESC
        )";
        
        sqlite3_stmt* stmt;
        
        std::stringstream json;
        json << "[";
        
        if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, today, -1, SQLITE_STATIC);
            
            bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                if (!first) json << ",";
                
                std::string deviceId = (const char*)sqlite3_column_text(stmt, 0);
                bool isOnline = false;
                
                // Check if device is online
                {
                    std::lock_guard<std::mutex> lock2(clientMutex);
                    auto it = clients.find(deviceId);
                    if (it != clients.end() && (now - it->second.lastSeen < 300)) {
                        isOnline = true;
                    }
                }
                
                json << "{";
                json << "\"device_id\":\"" << deviceId << "\",";
                json << "\"device_name\":\"" << (sqlite3_column_text(stmt, 1) ? (const char*)sqlite3_column_text(stmt, 1) : "") << "\",";
                json << "\"minutes\":" << sqlite3_column_int(stmt, 2) << ",";
                json << "\"sessions\":" << sqlite3_column_int(stmt, 3) << ",";
                json << "\"first_activity\":\"" << (sqlite3_column_text(stmt, 4) ? (const char*)sqlite3_column_text(stmt, 4) : "") << "\",";
                json << "\"last_seen\":\"" << (sqlite3_column_text(stmt, 5) ? (const char*)sqlite3_column_text(stmt, 5) : "") << "\",";
                json << "\"is_online\":" << (isOnline ? "true" : "false");
                json << "}";
                first = false;
            }
            sqlite3_finalize(stmt);
        }
        
        json << "]";
        sendHttpResponse(socket, json.str(), "application/json");
    }
    
    void serveApiPeers(SOCKET socket) {
        std::lock_guard<std::mutex> lock1(clientMutex);
        std::lock_guard<std::mutex> lock2(dbMutex);
        
        std::stringstream json;
        json << "[";
        
        bool first = true;
        time_t now = time(nullptr);
        char today[11];
        strftime(today, sizeof(today), "%Y-%m-%d", localtime(&now));
        
        // Get all unique devices from the database
        std::set<std::string> allDevices;
        const char* deviceSql = "SELECT DISTINCT device_id, device_name FROM events";
        sqlite3_stmt* deviceStmt;
        
        if (sqlite3_prepare_v2(database, deviceSql, -1, &deviceStmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(deviceStmt) == SQLITE_ROW) {
                std::string deviceId = (const char*)sqlite3_column_text(deviceStmt, 0);
                allDevices.insert(deviceId);
            }
            sqlite3_finalize(deviceStmt);
        }
        
        // Process each device
        for (const auto& deviceId : allDevices) {
            if (!first) json << ",";
            json << "{";
            json << "\"device_id\":\"" << deviceId << "\",";
            
            // Get device info
            std::string deviceName = deviceId;
            std::string ipAddress = "N/A";
            int p2pPort = 0;
            bool isOnline = false;
            
            auto clientIt = clients.find(deviceId);
            if (clientIt != clients.end()) {
                deviceName = clientIt->second.deviceName;
                ipAddress = clientIt->second.publicIP;
                p2pPort = clientIt->second.p2pPort;
                isOnline = (now - clientIt->second.lastSeen < 300);
            }
            
            json << "\"device_name\":\"" << deviceName << "\",";
            json << "\"ip_address\":\"" << ipAddress << "\",";
            json << "\"p2p_port\":" << p2pPort << ",";
            json << "\"is_online\":" << (isOnline ? "true" : "false") << ",";
            
            // Get today's stats for this device
            const char* statsSql = R"(
                SELECT 
                    COUNT(DISTINCT CASE WHEN event_type = 'WORK_SESSION' THEN id END) as sessions,
                    SUM(CASE WHEN date(timestamp) = ? THEN worked_minutes ELSE 0 END) as today_minutes,
                    COUNT(*) as total_blocks,
                    COUNT(CASE WHEN event_type = 'SUSPICIOUS' THEN 1 END) as suspicious_events
                FROM events 
                WHERE device_id = ?
            )";
            
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(database, statsSql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, today, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, deviceId.c_str(), -1, SQLITE_STATIC);
                
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    json << "\"sessions_today\":" << sqlite3_column_int(stmt, 0) << ",";
                    json << "\"today_minutes\":" << sqlite3_column_int(stmt, 1) << ",";
                    json << "\"total_blocks\":" << sqlite3_column_int(stmt, 2) << ",";
                    json << "\"suspicious_events\":" << sqlite3_column_int(stmt, 3) << ",";
                }
                sqlite3_finalize(stmt);
            }
            
            // Get recent events for this device
            json << "\"recent_events\":[";
            const char* eventsSql = R"(
                SELECT event_type, timestamp, worked_minutes, block_data
                FROM events 
                WHERE device_id = ?
                ORDER BY timestamp DESC 
                LIMIT 10
            )";
            
            if (sqlite3_prepare_v2(database, eventsSql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, deviceId.c_str(), -1, SQLITE_STATIC);
                
                bool firstEvent = true;
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    if (!firstEvent) json << ",";
                    json << "{";
                    json << "\"event_type\":\"" << sqlite3_column_text(stmt, 0) << "\",";
                    json << "\"timestamp\":\"" << sqlite3_column_text(stmt, 1) << "\",";
                    json << "\"worked_minutes\":" << sqlite3_column_int(stmt, 2);
                    
                    // Parse description from block data if available
                    const char* blockData = (const char*)sqlite3_column_text(stmt, 3);
                    if (blockData) {
                        std::string data(blockData);
                        size_t descPos = data.find("description=");
                        if (descPos != std::string::npos) {
                            descPos += 12; // length of "description="
                            size_t endPos = data.find(";", descPos);
                            if (endPos != std::string::npos) {
                                json << ",\"description\":\"" << data.substr(descPos, endPos - descPos) << "\"";
                            }
                        }
                    }
                    
                    json << "}";
                    firstEvent = false;
                }
                sqlite3_finalize(stmt);
            }
            
            json << "]}";
            first = false;
        }
        
        json << "]";
        sendHttpResponse(socket, json.str(), "application/json");
    }
    
    void serveHealth(SOCKET socket) {
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();
        
        std::stringstream json;
        json << "{\"status\":\"healthy\",\"uptime\":" << uptime << ",\"version\":\"2.0\"}";
        sendHttpResponse(socket, json.str(), "application/json");
    }
    
    void serve404(SOCKET socket) {
        std::string html = "<html><body><h1>404 Not Found</h1></body></html>";
        std::stringstream response;
        response << "HTTP/1.1 404 Not Found\r\n";
        response << "Content-Length: " << html.length() << "\r\n";
        response << "Connection: close\r\n\r\n";
        response << html;
        
        std::string responseStr = response.str();
        send(socket, responseStr.c_str(), responseStr.length(), 0);
    }
    
    void sendHttpResponse(SOCKET socket, const std::string& content, const std::string& contentType = "text/html") {
        std::stringstream response;
        response << "HTTP/1.1 200 OK\r\n";
        response << "Content-Type: " << contentType << "; charset=utf-8\r\n";
        response << "Content-Length: " << content.length() << "\r\n";
        response << "Connection: close\r\n";
        response << "Access-Control-Allow-Origin: *\r\n";
        response << "Cache-Control: no-cache\r\n\r\n";
        response << content;
        
        std::string responseStr = response.str();
        send(socket, responseStr.c_str(), responseStr.length(), 0);
    }
    
    void storeEvent(const std::string& deviceId, const std::string& deviceName, 
                    const std::string& eventType, int workedMinutes, 
                    const std::string& blockHash, const std::string& blockData,
                    const std::string& ipAddress) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        const char* sql = "INSERT INTO events (device_id, device_name, event_type, worked_minutes, block_hash, block_data, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, deviceId.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, deviceName.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, eventType.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 4, workedMinutes);
            sqlite3_bind_text(stmt, 5, blockHash.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, blockData.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 7, ipAddress.c_str(), -1, SQLITE_STATIC);
            
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    void updateDailySummary(const std::string& deviceId, const std::string& eventType, int minutes) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        char today[11];
        time_t now = time(nullptr);
        strftime(today, sizeof(today), "%Y-%m-%d", localtime(&now));
        
        // For WORK_SESSION events, update total minutes and session count
        if (eventType == "WORK_SESSION" && minutes > 0) {
            const char* sql = R"(
                INSERT OR REPLACE INTO daily_summary (device_id, date, total_minutes, sessions, first_activity, last_update)
                VALUES (?, ?, 
                    COALESCE((SELECT total_minutes FROM daily_summary WHERE device_id = ? AND date = ?), 0) + ?,
                    COALESCE((SELECT sessions FROM daily_summary WHERE device_id = ? AND date = ?), 0) + 1,
                    COALESCE((SELECT first_activity FROM daily_summary WHERE device_id = ? AND date = ?), datetime('now')),
                    datetime('now')
                )
            )";
            
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, today, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 4, today, -1, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 5, minutes);
                sqlite3_bind_text(stmt, 6, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 7, today, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 8, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 9, today, -1, SQLITE_STATIC);
                
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        // For other events, just update last activity time
        else {
            const char* sql = R"(
                INSERT OR REPLACE INTO daily_summary (device_id, date, total_minutes, sessions, first_activity, last_update)
                VALUES (?, ?, 
                    COALESCE((SELECT total_minutes FROM daily_summary WHERE device_id = ? AND date = ?), 0),
                    COALESCE((SELECT sessions FROM daily_summary WHERE device_id = ? AND date = ?), 0),
                    COALESCE((SELECT first_activity FROM daily_summary WHERE device_id = ? AND date = ?), datetime('now')),
                    datetime('now')
                )
            )";
            
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, today, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 4, today, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 5, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 6, today, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 7, deviceId.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 8, today, -1, SQLITE_STATIC);
                
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    void removeClient(const std::string& deviceId) {
        std::lock_guard<std::mutex> lock(clientMutex);
        clients.erase(deviceId);
    }
    
    std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> parts;
        std::stringstream ss(str);
        std::string part;
        while (std::getline(ss, part, delimiter)) {
            parts.push_back(part);
        }
        return parts;
    }
    
    std::string getCurrentTimeString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    void cleanup() {
        g_running = false;
        
        if (relaySocket != INVALID_SOCKET) {
            CLOSE_SOCKET(relaySocket);
            relaySocket = INVALID_SOCKET;
        }
        
        if (httpSocket != INVALID_SOCKET) {
            CLOSE_SOCKET(httpSocket);
            httpSocket = INVALID_SOCKET;
        }
        
        if (database) {
            sqlite3_close(database);
            database = nullptr;
        }
        
#ifdef _WIN32
        WSACleanup();
#endif
        
        std::cout << "Server shutdown complete\n";
    }
};

// Main function
int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Create and start server
    TimeTrackingServer server;
    server.start();
    
    return 0;
}