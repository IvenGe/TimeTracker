// windows_timetracking_client.cpp
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
#include <random>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wtsapi32.h>
#include <powrprof.h>

// Configuration structure
struct Config {
    std::string deviceName;
    std::string deviceId;
    std::string logPath;
    std::vector<std::string> bootstrapNodes;
    bool enableRelay;
};

// Block structure
struct Block {
    int index;
    std::string timestamp;
    std::string deviceName;
    std::string deviceId;
    std::string status;
    std::string previousHash;
    std::string hash;
    int nonce;
    int workedMinutes;
    std::string date;
    std::string reason;
};

// Global variables
Config config;
bool running = true;
time_t onlineStartTime = 0;
std::string sessionEndReason = "User action";
std::string currentSessionId = "";
std::vector<Block> blockchain;
std::mutex blockchainMutex;
SOCKET relaySocket = INVALID_SOCKET;

// Function to read config
Config readConfig(const std::string& filename) {
    Config cfg;
    cfg.enableRelay = true;
    cfg.logPath = "work_hours.log";
    cfg.bootstrapNodes.push_back("51.178.139.139:9999");
    
    // Get computer name
    char computerName[256];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        cfg.deviceName = computerName;
    } else {
        cfg.deviceName = "Unknown-PC";
    }
    
    // Generate device ID
    std::srand(std::time(nullptr));
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << (std::rand() % 16);
    }
    cfg.deviceId = ss.str();
    
    // Try to read config file
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                if (key == "device_name") cfg.deviceName = value;
                else if (key == "device_id") cfg.deviceId = value;
                else if (key == "bootstrap") cfg.bootstrapNodes[0] = value;
            }
        }
        file.close();
    }
    
    return cfg;
}

// Get current time string
std::string getCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
    return std::string(buffer);
}

// Calculate worked hours
std::string calculateWorkedHours() {
    time_t currentTime = time(nullptr);
    time_t duration = currentTime - onlineStartTime;
    int hours = duration / 3600;
    int minutes = (duration % 3600) / 60;
    std::stringstream ss;
    ss << hours << " hours and " << minutes << " minutes";
    return ss.str();
}

// Send data to relay
void sendToRelay(const std::string& message) {
    if (relaySocket != INVALID_SOCKET) {
        send(relaySocket, message.c_str(), message.length(), 0);
    }
}

// Connect to relay
void connectToRelay() {
    while (running) {
        std::string relay = config.bootstrapNodes[0];
        size_t colonPos = relay.find(':');
        if (colonPos == std::string::npos) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            continue;
        }
        
        std::string host = relay.substr(0, colonPos);
        int port = std::stoi(relay.substr(colonPos + 1));
        
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        
        relaySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (relaySocket == INVALID_SOCKET) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            continue;
        }
        
        struct hostent* hostent = gethostbyname(host.c_str());
        if (!hostent) {
            closesocket(relaySocket);
            relaySocket = INVALID_SOCKET;
            std::this_thread::sleep_for(std::chrono::seconds(10));
            continue;
        }
        
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        memcpy(&serverAddr.sin_addr, hostent->h_addr_list[0], hostent->h_length);
        
        if (connect(relaySocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
            std::cout << "Connected to relay server: " << relay << "\n";
            
            // Register
            std::string regMsg = "RELAY|REGISTER|" + config.deviceId + "|" + config.deviceName + "\n";
            sendToRelay(regMsg);
            
            // Keep alive loop
            while (running && relaySocket != INVALID_SOCKET) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                std::string keepalive = "STATUS|" + config.deviceId + "|WORKING|" + getCurrentTimeString() + "\n";
                if (send(relaySocket, keepalive.c_str(), keepalive.length(), 0) == SOCKET_ERROR) {
                    break;
                }
            }
        }
        
        closesocket(relaySocket);
        relaySocket = INVALID_SOCKET;
        WSACleanup();
        
        if (!running) break;
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

// Save work session
void saveWorkSession() {
    std::string endTime = getCurrentTimeString();
    time_t currentTime = time(nullptr);
    int workedMinutes = (currentTime - onlineStartTime) / 60;
    
    // Create work session block message
    std::stringstream ss;
    ss << "BLOCK|1|" << endTime << "|" << config.deviceId << "|WORK_SESSION|";
    ss << "0|hash|0|session|" << getCurrentTimeString() << "|" << endTime << "|";
    ss << workedMinutes << "|" << getCurrentTimeString().substr(0, 10) << "|" << sessionEndReason << "\n";
    
    sendToRelay(ss.str());
    
    // Save to local log
    std::ofstream log(config.logPath, std::ios::app);
    if (log.is_open()) {
        log << getCurrentTimeString() << " - Worked: " << workedMinutes << " minutes\n";
        log.close();
    }
    
    std::cout << "Work session saved: " << workedMinutes << " minutes\n";
}

// Console handler
BOOL WINAPI ConsoleHandler(DWORD dwType) {
    switch (dwType) {
    case CTRL_C_EVENT:
        sessionEndReason = "User stopped";
        break;
    case CTRL_CLOSE_EVENT:
        sessionEndReason = "Window closed";
        break;
    }
    running = false;
    saveWorkSession();
    return TRUE;
}

// Main function
int main() {
    SetConsoleTitle("Time Tracking Client");
    
    config = readConfig("config.txt");
    
    std::cout << "Time Tracking Client v1.0\n";
    std::cout << "========================\n";
    std::cout << "Device: " << config.deviceName << "\n";
    std::cout << "ID: " << config.deviceId << "\n";
    std::cout << "Relay: " << config.bootstrapNodes[0] << "\n\n";
    
    onlineStartTime = time(nullptr);
    std::cout << "Tracking started at: " << getCurrentTimeString() << "\n\n";
    
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    
    // Start relay connection thread
    std::thread relayThread(connectToRelay);
    
    // Simple main loop
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        std::cout << "Working: " << calculateWorkedHours() << "\n";
    }
    
    relayThread.join();
    
    if (relaySocket != INVALID_SOCKET) {
        closesocket(relaySocket);
        WSACleanup();
    }
    
    return 0;
}
