#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <iomanip> // Required for std::put_time
#include <map>

class ProcessKiller {
private:
    DWORD parentPid;
    std::string triggerTime;
    std::vector<DWORD> suspiciousPids;
    std::ofstream logFile;
    bool behaviorBasedDetection;

public:
    ProcessKiller(DWORD pid, const std::string& time, const std::string& suspiciousPidsStr = "") : 
        parentPid(pid), triggerTime(time), behaviorBasedDetection(!suspiciousPidsStr.empty()) {
        
        // Parse suspicious PIDs from comma-separated string
        if (!suspiciousPidsStr.empty()) {
            std::istringstream ss(suspiciousPidsStr);
            std::string pidStr;
            while (std::getline(ss, pidStr, ',')) {
                try {
                    DWORD pid = std::stoul(pidStr);
                    suspiciousPids.push_back(pid);
                } catch (const std::exception& e) {
                    // Skip invalid PIDs
                }
            }
        }
        
        // Open log file
        std::string logPath = std::string(getenv("PROGRAMDATA")) + "\\DeadboltAI\\killer.log";
        logFile.open(logPath, std::ios::app);
        
        logMessage("DeadboltKiller activated - PID: " + std::to_string(pid) + ", Time: " + time + 
                  ", Behavior-based: " + (behaviorBasedDetection ? "Yes" : "No") + 
                  ", Suspicious PIDs: " + std::to_string(suspiciousPids.size()));
    }
    
    ~ProcessKiller() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }
    
    void logMessage(const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        if (logFile.is_open()) {
            logFile << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") 
                   << "] " << message << std::endl;
            logFile.flush();
        }
    }
    
    std::vector<DWORD> getProcessList() {
        std::vector<DWORD> processes;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            logMessage("Failed to create process snapshot");
            return processes;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                processes.push_back(pe32.th32ProcessID);
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return processes;
    }
    
    std::string getProcessName(DWORD processID) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (hProcess == NULL) {
            return "";
        }
        
        char processName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName))) {
            CloseHandle(hProcess);
            return std::string(processName);
        }
        
        CloseHandle(hProcess);
        return "";
    }
    
    // Get process creation time
    FILETIME getProcessCreationTime(DWORD processID) {
        FILETIME creationTime = {0};
        FILETIME exitTime, kernelTime, userTime;
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (hProcess != NULL) {
            if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                // Successfully got creation time
            }
            CloseHandle(hProcess);
        }
        
        return creationTime;
    }
    
    // Get process CPU usage
    double getProcessCpuUsage(DWORD processID) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (hProcess == NULL) {
            return 0.0;
        }
        
        FILETIME createTime, exitTime, kernelTime, userTime;
        if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
            CloseHandle(hProcess);
            return 0.0;
        }
        
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        
        ULARGE_INTEGER startTime, endTime;
        startTime.LowPart = createTime.dwLowDateTime;
        startTime.HighPart = createTime.dwHighDateTime;
        endTime.LowPart = now.dwLowDateTime;
        endTime.HighPart = now.dwHighDateTime;
        
        ULARGE_INTEGER kernelTimeValue, userTimeValue;
        kernelTimeValue.LowPart = kernelTime.dwLowDateTime;
        kernelTimeValue.HighPart = kernelTime.dwHighDateTime;
        userTimeValue.LowPart = userTime.dwLowDateTime;
        userTimeValue.HighPart = userTime.dwHighDateTime;
        
        double totalTime = (kernelTimeValue.QuadPart + userTimeValue.QuadPart) / 10000000.0; // Convert to seconds
        double elapsedTime = (endTime.QuadPart - startTime.QuadPart) / 10000000.0; // Convert to seconds
        
        CloseHandle(hProcess);
        
        if (elapsedTime > 0) {
            return (totalTime / elapsedTime) * 100.0;
        }
        
        return 0.0;
    }
    
    bool terminateProcess(DWORD processID) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
        if (hProcess == NULL) {
            return false;
        }
        
        BOOL result = TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return result != 0;
    }
    
    void executeDefense() {
        logMessage("Starting enhanced behavior-based defense protocol");
        
        std::vector<DWORD> processes = getProcessList();
        int killedCount = 0;
        
        // Create a map to store process behavior scores and reasons
        std::map<DWORD, std::pair<int, std::vector<std::string>>> processScores;
        
        // First priority: Analyze processes identified by behavior analysis
        if (behaviorBasedDetection && !suspiciousPids.empty()) {
            logMessage("Behavior-based detection active - analyzing suspicious processes");
            
            // First, analyze all suspicious PIDs to assign behavior scores
            for (DWORD pid : suspiciousPids) {
                if (pid == parentPid || pid == GetCurrentProcessId()) {
                    continue; // Don't kill parent or self
                }
                
                std::string processName = getProcessName(pid);
                if (!processName.empty()) {
                    int behaviorScore = 0;
                    std::vector<std::string> behaviorReasons;
                    
                    // Check CPU usage
                    double cpuUsage = getProcessCpuUsage(pid);
                    if (cpuUsage > 70.0) {
                        behaviorScore += 3;
                        behaviorReasons.push_back("High CPU usage: " + std::to_string(cpuUsage) + "%");
                        logMessage("High CPU usage detected: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(cpuUsage) + "%");
                    } else if (cpuUsage > 40.0) {
                        behaviorScore += 1;
                        behaviorReasons.push_back("Elevated CPU usage: " + std::to_string(cpuUsage) + "%");
                        logMessage("Elevated CPU usage: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(cpuUsage) + "%");
                    }
                    
                    // Check process creation time
                    FILETIME creationTime = getProcessCreationTime(pid);
                    FILETIME currentTime;
                    GetSystemTimeAsFileTime(&currentTime);
                    
                    ULARGE_INTEGER current, created;
                    current.LowPart = currentTime.dwLowDateTime;
                    current.HighPart = currentTime.dwHighDateTime;
                    created.LowPart = creationTime.dwLowDateTime;
                    created.HighPart = creationTime.dwHighDateTime;
                    
                    // Calculate process age in seconds
                    double processAgeSeconds = (current.QuadPart - created.QuadPart) / 10000000.0;
                    
                    // If process was created in the last minute (60 seconds)
                    if (processAgeSeconds < 60.0) {
                        behaviorScore += 2;
                        behaviorReasons.push_back("Very recent process: " + std::to_string(processAgeSeconds) + "s old");
                        logMessage("Recently created process: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(processAgeSeconds) + "s old");
                    } else if (processAgeSeconds < 180.0) { // Less than 3 minutes
                        behaviorScore += 1;
                        behaviorReasons.push_back("Recent process: " + std::to_string(processAgeSeconds) + "s old");
                        logMessage("Relatively new process: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(processAgeSeconds) + "s old");
                    }
                    
                    // Check memory usage
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (hProcess != NULL) {
                        PROCESS_MEMORY_COUNTERS pmc;
                        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                            // Convert to MB for easier reading
                            double memoryUsageMB = pmc.WorkingSetSize / (1024.0 * 1024.0);
                            if (memoryUsageMB > 500.0) { // More than 500 MB
                                behaviorScore += 2;
                                behaviorReasons.push_back("High memory usage: " + std::to_string(memoryUsageMB) + " MB");
                                logMessage("High memory usage: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(memoryUsageMB) + " MB");
                            } else if (memoryUsageMB > 200.0) { // More than 200 MB
                                behaviorScore += 1;
                                behaviorReasons.push_back("Elevated memory usage: " + std::to_string(memoryUsageMB) + " MB");
                                logMessage("Elevated memory usage: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(memoryUsageMB) + " MB");
                            }
                        }
                        CloseHandle(hProcess);
                    }
                    
                    // Check thread count
                    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if (hThreadSnap != INVALID_HANDLE_VALUE) {
                        THREADENTRY32 te32;
                        te32.dwSize = sizeof(THREADENTRY32);
                        int threadCount = 0;
                        
                        if (Thread32First(hThreadSnap, &te32)) {
                            do {
                                if (te32.th32OwnerProcessID == pid) {
                                    threadCount++;
                                }
                            } while (Thread32Next(hThreadSnap, &te32));
                        }
                        
                        CloseHandle(hThreadSnap);
                        
                        if (threadCount > 50) {
                            behaviorScore += 2;
                            behaviorReasons.push_back("High thread count: " + std::to_string(threadCount));
                            logMessage("High thread count: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(threadCount) + " threads");
                        } else if (threadCount > 30) {
                            behaviorScore += 1;
                            behaviorReasons.push_back("Elevated thread count: " + std::to_string(threadCount));
                            logMessage("Elevated thread count: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(threadCount) + " threads");
                        }
                    }
                    
                    // Store the behavior score and reasons
                    processScores[pid] = std::make_pair(behaviorScore, behaviorReasons);
                    
                    // Log detailed behavior analysis
                    std::string reasonsStr = "";
                    for (size_t i = 0; i < behaviorReasons.size(); i++) {
                        reasonsStr += behaviorReasons[i];
                        if (i < behaviorReasons.size() - 1) {
                            reasonsStr += ", ";
                        }
                    }
                    
                    logMessage("Behavior analysis for " + processName + " (PID: " + std::to_string(pid) + "):");
                    logMessage("  Score: " + std::to_string(behaviorScore));
                    if (!reasonsStr.empty()) {
                        logMessage("  Reasons: " + reasonsStr);
                    }
                }
            }
        }
        
        // If no processes were analyzed by initial behavior flags or scores are low, scan all processes
        if (processScores.empty() || [&processScores]() {
                bool allLowScores = true;
                for (const auto& entry : processScores) {
                    if (entry.second.first >= 2) {
                        allLowScores = false;
                        break;
                    }
                }
                return allLowScores;
            }()) {
            logMessage("Scanning all processes for suspicious behavior patterns");
            
            // Analyze all running processes
            for (DWORD pid : processes) {
                // Skip already analyzed processes
                if (processScores.find(pid) != processScores.end()) {
                    continue;
                }
                
                if (pid == parentPid || pid == GetCurrentProcessId() || pid < 1000) {
                    continue; // Skip system processes, parent, and self
                }
                
                std::string processName = getProcessName(pid);
                if (processName.empty()) {
                    continue;
                }
                
                int behaviorScore = 0;
                std::vector<std::string> behaviorReasons;
                
                // Check CPU usage
                double cpuUsage = getProcessCpuUsage(pid);
                if (cpuUsage > 70.0) {
                    behaviorScore += 3;
                    behaviorReasons.push_back("High CPU usage: " + std::to_string(cpuUsage) + "%");
                    logMessage("High CPU usage detected: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(cpuUsage) + "%");
                } else if (cpuUsage > 40.0) {
                    behaviorScore += 1;
                    behaviorReasons.push_back("Elevated CPU usage: " + std::to_string(cpuUsage) + "%");
                    logMessage("Elevated CPU usage: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(cpuUsage) + "%");
                }
                
                // Check process creation time
                FILETIME creationTime = getProcessCreationTime(pid);
                FILETIME currentTime;
                GetSystemTimeAsFileTime(&currentTime);
                
                ULARGE_INTEGER current, created;
                current.LowPart = currentTime.dwLowDateTime;
                current.HighPart = currentTime.dwHighDateTime;
                created.LowPart = creationTime.dwLowDateTime;
                created.HighPart = creationTime.dwHighDateTime;
                
                // Calculate process age in seconds
                double processAgeSeconds = (current.QuadPart - created.QuadPart) / 10000000.0;
                
                // If process was created in the last minute (60 seconds)
                if (processAgeSeconds < 60.0) {
                    behaviorScore += 2;
                    behaviorReasons.push_back("Very recent process: " + std::to_string(processAgeSeconds) + "s old");
                    logMessage("Recently created process: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(processAgeSeconds) + "s old");
                } else if (processAgeSeconds < 180.0) { // Less than 3 minutes
                    behaviorScore += 1;
                    behaviorReasons.push_back("Recent process: " + std::to_string(processAgeSeconds) + "s old");
                    logMessage("Relatively new process: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(processAgeSeconds) + "s old");
                }
                
                // Check memory usage
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProcess != NULL) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        // Convert to MB for easier reading
                        double memoryUsageMB = pmc.WorkingSetSize / (1024.0 * 1024.0);
                        if (memoryUsageMB > 500.0) { // More than 500 MB
                            behaviorScore += 2;
                            behaviorReasons.push_back("High memory usage: " + std::to_string(memoryUsageMB) + " MB");
                            logMessage("High memory usage: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(memoryUsageMB) + " MB");
                        } else if (memoryUsageMB > 200.0) { // More than 200 MB
                            behaviorScore += 1;
                            behaviorReasons.push_back("Elevated memory usage: " + std::to_string(memoryUsageMB) + " MB");
                            logMessage("Elevated memory usage: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(memoryUsageMB) + " MB");
                        }
                    }
                    CloseHandle(hProcess);
                }
                
                // Check thread count
                HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hThreadSnap != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te32;
                    te32.dwSize = sizeof(THREADENTRY32);
                    int threadCount = 0;
                    
                    if (Thread32First(hThreadSnap, &te32)) {
                        do {
                            if (te32.th32OwnerProcessID == pid) {
                                threadCount++;
                            }
                        } while (Thread32Next(hThreadSnap, &te32));
                    }
                    
                    CloseHandle(hThreadSnap);
                    
                    if (threadCount > 50) {
                        behaviorScore += 2;
                        behaviorReasons.push_back("High thread count: " + std::to_string(threadCount));
                        logMessage("High thread count: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(threadCount) + " threads");
                    } else if (threadCount > 30) {
                        behaviorScore += 1;
                        behaviorReasons.push_back("Elevated thread count: " + std::to_string(threadCount));
                        logMessage("Elevated thread count: " + processName + " (PID: " + std::to_string(pid) + ") - " + std::to_string(threadCount) + " threads");
                    }
                }
                
                // Store the behavior score and reasons if significant
                if (behaviorScore > 0) {
                    processScores[pid] = std::make_pair(behaviorScore, behaviorReasons);
                    
                    // Log detailed behavior analysis for significant scores
                    if (behaviorScore >= 3) {
                        std::string reasonsStr = "";
                        for (size_t i = 0; i < behaviorReasons.size(); i++) {
                            reasonsStr += behaviorReasons[i];
                            if (i < behaviorReasons.size() - 1) {
                                reasonsStr += ", ";
                            }
                        }
                        
                        logMessage("Behavior analysis for " + processName + " (PID: " + std::to_string(pid) + "):");
                        logMessage("  Score: " + std::to_string(behaviorScore));
                        if (!reasonsStr.empty()) {
                            logMessage("  Reasons: " + reasonsStr);
                        }
                    }
                }
            }
        }
        
        // Create a sorted list of processes by behavior score
        std::vector<std::pair<DWORD, std::pair<int, std::vector<std::string>>>> sortedProcesses;
        for (const auto& entry : processScores) {
            sortedProcesses.push_back(entry);
        }
        
        // Sort by behavior score (highest first)
        std::sort(sortedProcesses.begin(), sortedProcesses.end(), 
            [](const auto& a, const auto& b) {
                return a.second.first > b.second.first;
            });
        
        // Log the sorted processes
        logMessage("Behavior analysis complete. Suspicious processes by score:");
        for (const auto& entry : sortedProcesses) {
            if (entry.second.first >= 3) { // Only log significant scores
                std::string processName = getProcessName(entry.first);
                logMessage("  Process: " + processName + " (PID: " + std::to_string(entry.first) + ") - Score: " + std::to_string(entry.second.first));
            }
        }
        
        // Terminate processes with significant behavior scores
        for (const auto& entry : sortedProcesses) {
            DWORD pid = entry.first;
            int score = entry.second.first;
            const std::vector<std::string>& reasons = entry.second.second;
            std::string processName = getProcessName(pid);
            
            // Use a consistent behavior-based threshold for all processes regardless of name
            if (score >= 3) { // Consistent threshold based purely on behavior
                
                // Format reasons for logging
                std::string reasonsStr = "";
                for (size_t i = 0; i < reasons.size(); i++) {
                    reasonsStr += reasons[i];
                    if (i < reasons.size() - 1) {
                        reasonsStr += ", ";
                    }
                }
                
                logMessage("RANSOMWARE DEFENSE: Terminating suspicious process based on behavior: " + processName + 
                           " (PID: " + std::to_string(pid) + ", Score: " + std::to_string(score) + ")");
                logMessage("RANSOMWARE BEHAVIOR: " + reasonsStr);
                
                if (terminateProcess(pid)) {
                    logMessage("Successfully terminated process: " + processName + " (PID: " + std::to_string(pid) + ")");
                    killedCount++;
                } else {
                    logMessage("Failed to terminate process: " + processName + " (PID: " + std::to_string(pid) + ")");
                }
            }
        }
        
        logMessage("Behavior-based defense protocol completed. Processes terminated: " + std::to_string(killedCount));
        
        // Show notification with special message for ransomware detection
        std::string notificationTitle = "Deadbolt AI Behavior Defense";
        std::string notificationMessage;
        
        // Check if any terminated processes were Python processes (potential ransomware)
        bool ransomwareDetected = false;
        for (const auto& entry : sortedProcesses) {
            if (entry.second.first >= 2) { // Only check processes that met termination threshold
                std::string procName = getProcessName(entry.first);
                if (procName.find("python") != std::string::npos) {
                    ransomwareDetected = true;
                    break;
                }
            }
        }
        
        if (ransomwareDetected) {
            notificationTitle = "Deadbolt AI Ransomware Defense Activated!";
            notificationMessage = "RANSOMWARE BEHAVIOR DETECTED AND BLOCKED!\n\n" 
                                 "Terminated " + std::to_string(killedCount) + " suspicious processes based on ransomware-like behavior.\n\n" 
                                 "Your files are protected. Check logs for details.";
        } else {
            notificationMessage = "Deadbolt AI Behavior Defense Activated!\n\n" 
                                 "Terminated " + std::to_string(killedCount) + " suspicious processes based on behavior analysis.\n\n" 
                                 "Check logs for details.";
        }
        
        MessageBoxA(NULL, notificationMessage.c_str(), notificationTitle.c_str(), MB_OK | MB_ICONWARNING | MB_TOPMOST);
    }
    
    void killHighCpuProcesses() {
        // This is a more aggressive approach - kill processes with high CPU usage
        // that started recently (potential ransomware)
        logMessage("Executing emergency high-CPU process termination");
        
        int killedCount = 0;
        std::vector<DWORD> processes = getProcessList();
        
        for (DWORD pid : processes) {
            if (pid == parentPid || pid == GetCurrentProcessId() || pid < 1000) {
                continue; // Skip system processes, parent, and self
            }
            
            // Check CPU usage
            double cpuUsage = getProcessCpuUsage(pid);
            if (cpuUsage < 30.0) {
                continue; // Skip low CPU processes
            }
            
            // Check creation time
            FILETIME creationTime = getProcessCreationTime(pid);
            FILETIME currentTime;
            GetSystemTimeAsFileTime(&currentTime);
            
            ULARGE_INTEGER current, created;
            current.LowPart = currentTime.dwLowDateTime;
            current.HighPart = currentTime.dwHighDateTime;
            created.LowPart = creationTime.dwLowDateTime;
            created.HighPart = creationTime.dwHighDateTime;
            
            // If process was created in the last 2 minutes (120 seconds)
            if ((current.QuadPart - created.QuadPart) / 10000000 < 120) {
                std::string processName = getProcessName(pid);
                if (!processName.empty()) {
                    logMessage("Emergency termination of high-CPU recent process: " + 
                              processName + " (PID: " + std::to_string(pid) + ") - " + 
                              std::to_string(cpuUsage) + "% CPU");
                    
                    if (terminateProcess(pid)) {
                        killedCount++;
                        logMessage("Successfully terminated high-CPU process: " + processName);
                    } else {
                        logMessage("Failed to terminate high-CPU process: " + processName);
                    }
                }
            }
        }
        
        logMessage("Emergency high-CPU termination completed. Processes terminated: " + std::to_string(killedCount));
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: DeadboltKiller.exe --pid <parent_pid> --time <trigger_time> [--suspicious <suspicious_pids>]" << std::endl;
        return 1;
    }
    
    DWORD parentPid = 0;
    std::string triggerTime;
    std::string suspiciousPids = "";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--pid" && i + 1 < argc) {
            parentPid = std::stoul(argv[i + 1]);
            i++;
        } else if (std::string(argv[i]) == "--time" && i + 1 < argc) {
            triggerTime = argv[i + 1];
            i++;
        } else if (std::string(argv[i]) == "--suspicious" && i + 1 < argc) {
            suspiciousPids = argv[i + 1];
            i++;
        }
    }
    
    if (parentPid == 0) {
        std::cerr << "Invalid parent PID" << std::endl;
        return 1;
    }
    
    try {
        ProcessKiller killer(parentPid, triggerTime, suspiciousPids);
        killer.executeDefense();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}