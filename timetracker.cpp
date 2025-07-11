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

// Platform specific includes
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
};

// Global variables
Config config;
std::chrono::system_clock::time_point startTime;
bool running = true;
time_t onlineStartTime = 0;

// Forward declarations
std::string getNTPTime();
std::string getOnlineTime();
time_t getOnlineTimestamp();

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
        newFile.close();
        
        cfg.emailFrom = "your_email@example.com";
        cfg.emailTo = "recipient@example.com";
        cfg.smtpServer = "smtp.gmail.com";
        cfg.smtpPort = "587";
        cfg.smtpUsername = "your_email@example.com";
        cfg.smtpPassword = "your_app_password";
        cfg.logPath = "work_hours.log";
        cfg.timeServer = "worldtimeapi.org";
        
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
        }
    }
    file.close();
    return cfg;
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

// Alternative: Create PowerShell script for email
void sendEmailViaScript(const std::string& subject, const std::string& body) {
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
        logFile << "Duur: " << duration << "\n";
        logFile.close();
    }
}

// Function to handle cleanup and exit
void cleanup() {
    if (!running) return; // Prevent double cleanup
    running = false;
    
    // Get end time
    std::string endTimeStr = getCurrentTimeString();
    std::string duration = calculateWorkedHours();
    
    // Get start time as string
    char startBuffer[100];
    struct tm* timeinfo = localtime(&onlineStartTime);
    std::strftime(startBuffer, sizeof(startBuffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    std::string startTimeStr(startBuffer);
    
    // Save to log
    saveWorkSession(startTimeStr, endTimeStr, duration);
    
    // Prepare email content
    std::string subject = "Werkuren rapport - " + endTimeStr.substr(0, 10);
    std::stringstream bodyStream;
    bodyStream << "Werkuren rapport:\n\n";
    bodyStream << "Start tijd: " << startTimeStr << " (online tijd)\n";
    bodyStream << "Eind tijd: " << endTimeStr << "\n";
    bodyStream << "Totale werktijd: " << duration << "\n\n";
    bodyStream << "Dit is een automatisch gegenereerd rapport met online tijdverificatie.";
    
    // Send email
    std::cout << "\nVerstuurt email rapport...\n";
    sendEmailViaScript(subject, bodyStream.str());
    
    std::cout << "Werkuren opgeslagen: " << duration << "\n";
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
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        cleanup();
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

int main() {
    // Read configuration
    config = readConfig("config.txt");
    
    std::cout << "Uren registratie tool - Online tijd versie\n";
    std::cout << "==========================================\n";
    std::cout << "Ophalen van online tijd...\n";
    
    // Get start time from online source
    std::string startTimeStr = getCurrentTimeString();
    onlineStartTime = getOnlineTimestamp();
    
    if (startTimeStr.find("lokale tijd") != std::string::npos) {
        std::cout << "WAARSCHUWING: Kon geen online tijd ophalen, gebruikt lokale tijd als fallback.\n";
    }
    
    std::cout << "Uren registratie gestart om: " << startTimeStr << std::endl;
    std::cout << "Configuratie geladen uit config.txt\n";
    std::cout << "Druk op Ctrl+C om te stoppen of sluit de laptop af.\n\n";
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
#endif
    
    // Main loop
    int hourCounter = 0;
    while (running) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
        
        // Show progress every hour
        time_t currentTime = getOnlineTimestamp();
        int elapsedHours = (currentTime - onlineStartTime) / 3600;
        
        if (elapsedHours > hourCounter) {
            hourCounter = elapsedHours;
            std::cout << "Status update: " << calculateWorkedHours() << " gewerkt.\n";
            std::cout << "Huidige online tijd: " << getCurrentTimeString() << "\n";
        }
    }
    
    return 0;
}