// DhcpServ.cpp : Definiert den Einstiegspunkt für die Konsolenanwendung.
//

#include <iostream>
#include <iomanip>
#include <map>
#include <memory>
#include <string>
#include <sstream>
#include <array>
#include <chrono>
#include <codecvt>
#include <regex>
#include <fstream>

#include "socketlib/SocketLib.h"
#include "ConfFile.h"

#if defined(_WIN32) || defined(_WIN64)
#include <Ws2tcpip.h>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#define FN_STR(x) x.c_str()

#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "x64/Debug/socketlib64d")
#else
#pragma comment(lib, "Debug/socketlib32d")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "x64/Release/socketlib64")
#else
#pragma comment(lib, "Release/socketlib32")
#endif
#endif
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#else
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#define FN_STR(x) wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(x).c_str()
#endif

using namespace std::placeholders;

template <size_t N, size_t ... Is>
array<uint8_t, N> to_array(uint8_t(&a)[N], index_sequence<Is...>)
{
    return{ { a[Is]... } };
}

template <size_t N>
array<uint8_t, N> to_array(uint8_t(&a)[N])
{
    return to_array(a, make_index_sequence<N>());
}

class DhcpProtokol
{
public:
    typedef struct
    {
        uint8_t op;         // Message op code / message type
        uint8_t htype;      // Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet.
        uint8_t hlen;       // Hardware address length (e.g.  '6' for 10mb ethernet).
        uint8_t hops;       // Client sets to zero, optionally used by relay agents when booting via a relay agent.
        uint32_t xid;       // Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server.
        uint16_t secs;      // Filled in by client, seconds elapsed since client began address acquisition or renewal process.
        uint16_t flags;     // Flags
        uint32_t ciaddr;    // Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests.
        uint32_t yiaddr;    // 'your' (client) IP address.
        uint32_t siaddr;    // IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
        uint32_t giaddr;    // Relay agent IP address, used in booting via a relay agent.
        uint8_t chaddr[16]; // Client hardware address
        uint8_t sname[64];  // Optional server host name, null terminated string.
        uint8_t file[128];  // Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory - path name in DHCPOFFER.
        uint8_t option[4];  // magic cookie [99,130,83,99]
    }DHCPHEADER;

    enum OPCODE : char
    {
        BOOTREQUEST = 0x1,
        BOOTREPLY   = 0x2
    };
    enum DHCPMESSAGE : unsigned char
    {
        DHCPDISCOVER = 1,
        DHCPOFFER,
        DHCPREQUEST,
        DHCPDECLINE,
        DHCPACK,
        DHCPNAK,
        DHCPRELEASE,
        DHCPINFORM
    };

public:
    DhcpProtokol() : m_DhcpHeader({ 0 }), m_cDhcpType(0)
    {
    };
    DhcpProtokol(uint8_t* szBuffer, size_t nBytInBuf)
    {
        copy(&szBuffer[0], &szBuffer[sizeof(DHCPHEADER)], reinterpret_cast<unsigned char*>(&m_DhcpHeader));

        uint8_t* pOtionCode = szBuffer + sizeof(DHCPHEADER);

        while (*pOtionCode != 255 && pOtionCode < szBuffer + nBytInBuf)
        {
            uint8_t cCode = *pOtionCode++;
            uint8_t cLen  = *pOtionCode++;
//            OutputDebugString(wstring(L"Options-Code: " + to_wstring(cCode) + L", Länge: " + to_wstring(cLen) + L"\r\n").c_str());
            char caAddrBuf[INET6_ADDRSTRLEN + 1] = { 0 };

            switch (cCode)
            {
            case 0:     pOtionCode--; continue;
            case 12:    //Host Name Option
                m_strHostName = string(reinterpret_cast<const char*>(pOtionCode), cLen);
                break;
            case 43:    //Vendor Specific Information
                break;
            case 50:    //Requested IP Address
                //m_strRequestIp = inet_ntoa(*(reinterpret_cast<const struct in_addr*>(pOtionCode)));
                m_strRequestIp = inet_ntop(AF_INET, reinterpret_cast<struct in_addr*>(pOtionCode), caAddrBuf, sizeof(caAddrBuf));
                break;
            case 53:    //DHCP Message Type
                m_cDhcpType = *pOtionCode;
                break;
            case 54:    //Server Identifier
                //m_strServerIdent = inet_ntoa(*(reinterpret_cast<const struct in_addr*>(pOtionCode)));
                m_strServerIdent = inet_ntop(AF_INET, reinterpret_cast<struct in_addr*>(pOtionCode), caAddrBuf, sizeof(caAddrBuf));
                break;
            case 55:    //Parameter Request List
                m_vOptionRequest = vector<uint8_t>(pOtionCode, pOtionCode+ cLen);
                break;
            case 60:    //Class-identifier
                m_strClassIdent = string(reinterpret_cast<const char*>(pOtionCode), cLen);
                break;
            case 61:    //Client-identifier
                m_strClientIdent = string(reinterpret_cast<const char*>(pOtionCode), cLen);
                break;
            case 81:    // Client FQDN Option (RFC 4702)
                break;
            default:
                OutputDebugString(L"Unhandled option code\r\n");
            }

            pOtionCode += cLen;
        }
    }

    virtual ~DhcpProtokol()
    {
    }

public:
    DHCPHEADER  m_DhcpHeader;
    uint8_t     m_cDhcpType;
    string      m_strHostName;
    vector<uint8_t> m_vOptionRequest;
    string      m_strClassIdent;
    string      m_strClientIdent;
    string      m_strRequestIp;
    string      m_strServerIdent;
};

class DhcpServer
{
    typedef vector<string> strlist;
    typedef struct
    {
        uint32_t nLeaseTime;    // = 3600
        string strIP_From;      // = 192.168.214.100
        string strIP_To;        // = 192.168.214.120
        string strSubnet;       // = 255.255.255.0
        strlist vstrIP_Blocked; // = Komma getrennte Liste mit IP Adressen die nicht vergeben werden sollen
        string strRouter_IP;    // = 192.168.16.1
        string strDNS_IP;       // = 192.168.16.1 [,192.168.16.254]
        string strDomainName;   // = "benzinger.local"
        strlist vstrHW_Blocked; // = Komma getrennte Liste mit MAC Adressen die nicht bedient werden sollen
    }CONFIG;

    typedef struct
    {
        int    iAddrFamily;
        string strIpAddr;
        int    nInterfaceIndex;
    }SOCKET_ENTRY;

    enum IP_FLAGS : uint32_t
    {
        IP_OFFERT = 1,
        IP_LEASE = 2,
        IP_RELEASE = 4,
        IP_DECLINE = 8
    };

    typedef struct
    {
        string strClientId;
        string strIP;
        IP_FLAGS nFlag;
        chrono::system_clock::time_point tLeaseTime;
    }IP_ENTRY;

public:
    DhcpServer()
    {
        m_strModulePath = wstring(FILENAME_MAX, 0);
#if defined(_WIN32) || defined(_WIN64)
        if (GetModuleFileName(NULL, &m_strModulePath[0], FILENAME_MAX) > 0)
            m_strModulePath.erase(m_strModulePath.find_last_of(L'\\') + 1); // Sollte der Backslash nicht gefunden werden wird der ganz String gelöscht

        if (_wchdir(m_strModulePath.c_str()) != 0)
            m_strModulePath = L"./";
#else
        string strTmpPath(FILENAME_MAX, 0);
        if (readlink(string("/proc/" + to_string(getpid()) + "/exe").c_str(), &strTmpPath[0], FILENAME_MAX) > 0)
            strTmpPath.erase(strTmpPath.find_last_of('/'));

        //Change Directory
        //If we cant find the directory we exit with failure.
        if ((chdir(strTmpPath.c_str())) < 0) // if ((chdir("/")) < 0)
            strTmpPath = ".";
        m_strModulePath = wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().from_bytes(strTmpPath) + L"/";
#endif
        const ConfFile& conf = ConfFile::GetInstance(m_strModulePath + L"DhcpServ.cfg");
        vector<wstring> vSections = conf.get();
        for (const auto& strSection : vSections)
        {
            vector<wstring> vKeys = conf.get(strSection);
            if (vKeys.size() > 0)
            {
                auto itRet = m_maConfig.emplace(wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strSection), CONFIG());
                if (itRet.second == true)
                {
                    for (const auto& strKey : vKeys)
                    {
                        wstring strItem = conf.getUnique(strSection, strKey);
                        if (strItem.empty() == false)
                        {
                            const static regex SpaceSeperator(",");

                            if (strKey == L"LeaseTime")
                                itRet.first->second.nLeaseTime = stoi(strItem);
                            if (strKey == L"IP_From")
                                itRet.first->second.strIP_From = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                            if (strKey == L"IP_To")
                                itRet.first->second.strIP_To = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                            if (strKey == L"Subnet")
                                itRet.first->second.strSubnet = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                            if (strKey == L"IP_Blocked")
                            {
                                string strIpBlocked = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                                sregex_token_iterator token(begin(strIpBlocked), end(strIpBlocked), SpaceSeperator, -1);
                                while (token != sregex_token_iterator())
                                    itRet.first->second.vstrIP_Blocked.push_back(*token++);
                            }
                            if (strKey == L"Router_IP")
                                itRet.first->second.strRouter_IP = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                            if (strKey == L"DNS_IP")
                                itRet.first->second.strDNS_IP = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                            if (strKey == L"DomainName")
                                itRet.first->second.strDomainName = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                            if (strKey == L"HW_Blocked")
                            {
                                string strHwBlocked = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strItem);
                                sregex_token_iterator token(begin(strHwBlocked), end(strHwBlocked), SpaceSeperator, -1);
                                while (token != sregex_token_iterator())
                                    itRet.first->second.vstrHW_Blocked.push_back(*token++);
                            }
                        }
                    }
                }
            }
        }

        ifstream fin;
        fin.open(FN_STR(wstring(m_strModulePath + L"DhcpServ.ini")), ios::in | ios::binary);
        if (fin.is_open() == true)
        {
            fin.imbue(std::locale(fin.getloc(), new codecvt_utf8<wchar_t>));

            while (fin.eof() == false)
            {
                string strLine;
                getline(fin, strLine);

                size_t nPos = strLine.find_first_of("#;\r\n");
                if (nPos != string::npos) strLine.erase(nPos);   // erase commends from line
                if (strLine.empty() == false)
                {
                    const static regex KommaSeperator(",");
                    vector<string> vTmp;
                    sregex_token_iterator token(begin(strLine), end(strLine), KommaSeperator, -1);
                    while (token != sregex_token_iterator())
                    {
                        vTmp.push_back(*token++);
                        vTmp.back().erase(vTmp.back().find_last_not_of("\" \t") + 1);   // Trim Whitespace and " character on the right
                        vTmp.back().erase(0, vTmp.back().find_first_not_of("\" \t"));   // Trim Whitespace and " character on the left
                    }
                    if (vTmp.size() == 5)
                    {
                        uint8_t chaddr[16] = { 0 };
                        for (uint8_t n = 0, i = 0; n < vTmp[0].size(); ++n)
                        {
                            if (vTmp[0][n] == ':') continue;
                            chaddr[i++] = stoi(vTmp[0].substr(n++, 2), 0, 16);
                        }

                        //ClientIdent
                        size_t nPos = vTmp[1].find("=");
                        if (nPos != string::npos)
                        {
                            vTmp[1][0] = stoi(vTmp[1].substr(0, nPos));
                            size_t i = 1;
                            for (size_t n = nPos + 1; n < vTmp[1].size(); ++n)
                            {
                                if (vTmp[1][n] == ':') continue;
                                vTmp[1][i++] = stoi(vTmp[1].substr(n++, 2), 0, 16);
                            }
                            vTmp[1].resize(i);
                        }
                        array<uint8_t, 16> arHwAddr({ to_array(chaddr) });
                        m_maIpLeases.emplace(arHwAddr, IP_ENTRY({ vTmp[1], vTmp[2], static_cast<IP_FLAGS>(stoul(vTmp[3])), chrono::system_clock::from_time_t(stoi(vTmp[4])) }));
                    }
                }
            }

            fin.close();
        }
    }

    ~DhcpServer()
    {
        ofstream fout;
        fout.open(FN_STR(wstring(m_strModulePath + L"DhcpServ.ini")), ios::in | ios::binary);
        if (fout.is_open() == true)
        {
            fout.imbue(std::locale(fout.getloc(), new codecvt_utf8<wchar_t>));
            fout.write("# HW Addr , \"Client IDent\", Ip Address, Flag, Time\r\n", 52);
            for (auto iter : m_maIpLeases)
            {
                stringstream ssCI;
                ssCI << to_string(iter.second.strClientId[0]);
                for (size_t n = 1; n < iter.second.strClientId.size(); ++n)
                    ssCI << (n > 1 ? ":" : "=") << setfill('0') << hex << setw(2) << (static_cast<unsigned int>(iter.second.strClientId[n]) & 0x000000ff);

                stringstream ssOut;
                for (uint8_t n = 0; n < 6; ++n)
                    ssOut << (n > 0 ? ":" : "") << setfill('0') << hex << setw(2) << static_cast<unsigned int>(iter.first[n]);
                ssOut << ", \"" << ssCI.str() << "\", " << iter.second.strIP << ", " << dec << iter.second.nFlag << ", " << chrono::system_clock::to_time_t(iter.second.tLeaseTime) << "\r\n";
                fout.write(ssOut.str().c_str(), ssOut.str().size());
            }
            fout.close();
        }
    }

    void Start()
    {
/*        BaseSocket::EnumIpAddresses([&](int adrFamily, const string& strIpAddr, int nInterfaceIndex, void*) -> int
        {
            wcout << strIpAddr.c_str() << endl;//OutputDebugStringA(strIpAddr.c_str()); OutputDebugStringA("\r\n");

            if (m_maConfig.find(strIpAddr) != end(m_maConfig))
                ;//return 0;

            if (adrFamily == AF_INET)
            {
                pair<map<UdpSocket*, SOCKET_ENTRY>::iterator, bool>paRet = m_maSockets.emplace(new UdpSocket(), SOCKET_ENTRY({ adrFamily, strIpAddr, nInterfaceIndex }));
                if (paRet.second == true)
                {
                    paRet.first->first->BindErrorFunction(bind(&DhcpServer::SocketError, this, _1));
                    paRet.first->first->BindCloseFunction(bind(&DhcpServer::SocketCloseing, this, _1));
                    paRet.first->first->BindFuncBytesReceived(bind(&DhcpServer::DatenEmpfangen, this, _1));

                    if (paRet.first->first->Create(strIpAddr.c_str(), 67) == false || paRet.first->first->EnableBroadCast() == false)
                        wcout << L"Error creating Socket: " << strIpAddr.c_str() << endl;
                }
            }

            return 0;
        }, 0);
*/
        BaseSocket::SetAddrNotifyCallback(function<void(bool, const string&, int, int)>(bind(&DhcpServer::CbIdAddrChanges, this, _1, _2, _3, _4)));
    }

    void CbIdAddrChanges(bool bDelAdd, const string& strIpAddr, int adrFamily, int nInterfaceIndex)
    {
        wcout << strIpAddr.c_str() << endl;//OutputDebugStringA(strIpAddr.c_str()); OutputDebugStringA("\r\n");

        if (m_maConfig.find(strIpAddr) != end(m_maConfig))   // IP found in the config
        {
            if (bDelAdd == true)    // and the address is new
            {
                pair<map<UdpSocket*, SOCKET_ENTRY>::iterator, bool>paRet = m_maSockets.emplace(new UdpSocket(), SOCKET_ENTRY({ adrFamily, strIpAddr, nInterfaceIndex }));
                if (paRet.second == true)
                {
                    paRet.first->first->BindErrorFunction([&](BaseSocket* pBaseSocket) { SocketError(pBaseSocket); });
                    paRet.first->first->BindCloseFunction([&](BaseSocket* pBaseSocket) { SocketCloseing(pBaseSocket); });
                    paRet.first->first->BindFuncBytesReceived([&](UdpSocket* pUdpSocket) { DatenEmpfangen(pUdpSocket); });

                    if (paRet.first->first->Create(strIpAddr.c_str(), 67) == false || paRet.first->first->EnableBroadCast() == false)
                        wcout << L"Error creating Socket: " << strIpAddr.c_str() << endl;
                }
            }
            else // IP is removed, close the socket how is listing on it
            {
                for (auto itFound : m_maSockets)
                {
                    if (itFound.second.strIpAddr == strIpAddr)
                    {
                        itFound.first->Close();  // Close Socket
                        m_maSockets.erase(itFound.first);
                        delete itFound.first;
                        break;
                    }
                }
            }
        }
    }

    void Stop()
    {
        while (m_maSockets.size())
        {
            m_maSockets.begin()->first->Close();
            delete m_maSockets.begin()->first;
            m_maSockets.erase(m_maSockets.begin());
        }
    }

    void SocketError(BaseSocket* pBaseSocket)
    {
        wcout << L"Error in Verbindung" << endl;
        pBaseSocket->Close();
    }

    void SocketCloseing(BaseSocket* pBaseSocket)
    {
        wcout << L"Socket closing" << endl;
    }

    void DatenEmpfangen(UdpSocket* pUdpSocket)
    {
        size_t nAvalible = pUdpSocket->GetBytesAvailible();

        auto spBuffer = make_unique<unsigned char[]>(nAvalible + 1);

        string strFrom;
        size_t nRead = pUdpSocket->Read(spBuffer.get(), nAvalible, strFrom);

        if (nRead > 0)
        {
            DhcpProtokol dhcpProto(spBuffer.get(), nRead);

            if (dhcpProto.m_DhcpHeader.htype == 1 && dhcpProto.m_DhcpHeader.hlen == 6)   // ethernet = 1 , MAC address 6 byt long
            {
                wstringstream ss;
                auto itSocket = m_maSockets.find(pUdpSocket);
                if (itSocket != end(m_maSockets))
                    ss << setfill(L' ') << std::left << setw(15) << itSocket->second.strIpAddr.c_str() << L" - ";

                ss << setfill(L'0') << std::right << hex << setw(2) << dhcpProto.m_DhcpHeader.chaddr[0];
                for (uint8_t i = 1; i < dhcpProto.m_DhcpHeader.hlen; ++i)
                    ss << L":" << hex << setw(2) << dhcpProto.m_DhcpHeader.chaddr[i];
                ss << L" - op: " << dhcpProto.m_DhcpHeader.op << L" - DHCP Typ: " << dhcpProto.m_cDhcpType << L" - Hostname: " << dhcpProto.m_strHostName.c_str();
                ss << L" - ClassIdent: " << dhcpProto.m_strClassIdent.c_str() << L" - Option-Request: ";
                for (size_t i = 0; i < dhcpProto.m_vOptionRequest.size(); ++i)
                    ss << dec << dhcpProto.m_vOptionRequest[i] << L",";
                ss.seekp(-1, ios_base::end);
                ss << L" - Req.-ID: " << hex << setw(8) << dhcpProto.m_DhcpHeader.xid << L" - Flag: " << hex << setw(2) << dhcpProto.m_DhcpHeader.flags;
                ss << L" - Sek.: " << dec << dhcpProto.m_DhcpHeader.secs;

                ss << L" - ciaddr: " << hex << dhcpProto.m_DhcpHeader.ciaddr;
                ss << L" - yiaddr: " << hex << dhcpProto.m_DhcpHeader.yiaddr;
                ss << L" - siaddr: " << hex << dhcpProto.m_DhcpHeader.siaddr;
                ss << L" - giaddr: " << hex << dhcpProto.m_DhcpHeader.giaddr;

                ss << L"\r\n";
                OutputDebugString(ss.str().c_str());

                if (itSocket != end(m_maSockets))
                {
                    auto itConfig = m_maConfig.find(itSocket->second.strIpAddr);

                    if (itConfig != end(m_maConfig))
                    {
                        function<uint8_t*(uint8_t*, vector<uint8_t>&)> fnSetOptionFromRequestList = [&](uint8_t* pOptions, vector<uint8_t>& vOptionRequest) -> uint8_t*
                        {
                            for (size_t i = 0; i < vOptionRequest.size(); ++i)
                            {
                                switch (vOptionRequest[i])
                                {
                                case 1: // Subnet Mask
                                    //*pOptions++ = 1; *pOptions++ = 4; *((long*)pOptions) = ::inet_addr(itConfig->second.strSubnet.c_str()); pOptions += 4;
                                    *pOptions++ = 1; *pOptions++ = 4; ::inet_pton(AF_INET, itConfig->second.strSubnet.c_str(), (long*)pOptions); pOptions += 4;
                                    break;
                                case 15:// Domain Name
                                    *pOptions++ = 15; *pOptions++ = static_cast<uint8_t>(itConfig->second.strDomainName.size());  memcpy(pOptions, &itConfig->second.strDomainName[0], 15); pOptions += itConfig->second.strDomainName.size();
                                    break;
                                case 3: // Router
                                    //*pOptions++ = 3; *pOptions++ = 4;  *((long*)pOptions) = ::inet_addr(itConfig->second.strRouter_IP.c_str()); pOptions += 4;
                                    *pOptions++ = 3; *pOptions++ = 4;  ::inet_pton(AF_INET, itConfig->second.strRouter_IP.c_str(), (long*)pOptions); pOptions += 4;
                                    break;
                                case 6: // Domain Name Server (DNS)
                                    //*pOptions++ = 6; *pOptions++ = 4;  *((long*)pOptions) = ::inet_addr(itConfig->second.strDNS_IP.c_str()); pOptions += 4;
                                    *pOptions++ = 6; *pOptions++ = 4;  ::inet_pton(AF_INET, itConfig->second.strDNS_IP.c_str(), (long*)pOptions); pOptions += 4;
                                    break;
                                }
                            }
                            return pOptions;
                        };

                        // IP pool for now
                        static uint8_t nextIp = 100;

                        // construct our hardware address variable
                        array<uint8_t, 16> arHwAddr({ to_array(dhcpProto.m_DhcpHeader.chaddr) });
                        stringstream ssHw;
                        for (uint8_t n = 0; n < dhcpProto.m_DhcpHeader.hlen; ++n)
                            ssHw << (n > 0 ? ":" : "") << setfill('0') << hex << setw(2) << dhcpProto.m_DhcpHeader.chaddr[n];

                        if (find_if(begin(itConfig->second.vstrHW_Blocked), end(itConfig->second.vstrHW_Blocked), [&](auto& strHwAddr) { return strHwAddr == ssHw.str() ? true : false; }) == end(itConfig->second.vstrHW_Blocked))
                        {
                            // look if we have the hardware address allready in our pool with asigned addresses
                            auto itIp = m_maIpLeases.find(arHwAddr);
                            if (itIp != end(m_maIpLeases) && itIp->second.nFlag == IP_DECLINE)
                                itIp = end(m_maIpLeases);

                            // Last Dot from the interface IP the request came in (used later)
                            size_t nPos = itSocket->second.strIpAddr.find_last_of(".");

                            // make a buffer for the respons
                            unique_ptr<uint8_t[]> pBuffer = make_unique<uint8_t[]>(500);
                            DhcpProtokol::DHCPHEADER& DhcpHeader = reinterpret_cast<DhcpProtokol::DHCPHEADER&>(*pBuffer.get());
                            uint8_t* pOptions = pBuffer.get() + sizeof(DhcpProtokol::DHCPHEADER);

                            DhcpHeader.op = DhcpProtokol::BOOTREPLY;
                            DhcpHeader.htype = dhcpProto.m_DhcpHeader.htype;
                            DhcpHeader.hlen = dhcpProto.m_DhcpHeader.hlen;
                            DhcpHeader.xid = dhcpProto.m_DhcpHeader.xid;
                            DhcpHeader.flags = dhcpProto.m_DhcpHeader.flags;
                            //DhcpHeader.siaddr = ::inet_addr(itSocket->second.strIpAddr.c_str());
                            ::inet_pton(AF_INET, itSocket->second.strIpAddr.c_str(), &DhcpHeader.siaddr);
                            DhcpHeader.giaddr = dhcpProto.m_DhcpHeader.giaddr;
                            copy(dhcpProto.m_DhcpHeader.chaddr, dhcpProto.m_DhcpHeader.chaddr + dhcpProto.m_DhcpHeader.hlen, DhcpHeader.chaddr);
                            memcpy(DhcpHeader.sname, "lap-88", 6);
                            copy(dhcpProto.m_DhcpHeader.option, dhcpProto.m_DhcpHeader.option + 4, DhcpHeader.option);  // Magic cookie

                            // Server Ident send allways as option
                            //*pOptions++ = 54; *pOptions++ = 4; *((long*)pOptions) = ::inet_addr(itSocket->second.strIpAddr.c_str()); pOptions += 4;
                            *pOptions++ = 54; *pOptions++ = 4; ::inet_pton(AF_INET, itSocket->second.strIpAddr.c_str(), (long*)pOptions); pOptions += 4;

                            if (dhcpProto.m_cDhcpType == DhcpProtokol::DHCPDISCOVER)
                            {
                                if (itIp == end(m_maIpLeases))
                                {
                                    auto res = m_maIpLeases.emplace(arHwAddr, IP_ENTRY({ dhcpProto.m_strClientIdent, itSocket->second.strIpAddr.substr(0, nPos + 1) + to_string(nextIp++), IP_OFFERT, chrono::system_clock::now() }));
                                    if (res.second == true)
                                        itIp = res.first;
                                }

                                if (itIp != end(m_maIpLeases))
                                {
                                    //DhcpHeader.yiaddr = ::inet_addr(itIp->second.strIP.c_str());
                                    ::inet_pton(AF_INET, itIp->second.strIP.c_str(), &DhcpHeader.yiaddr);
                                    *pOptions++ = 51; *pOptions++ = 4; *((long*)pOptions) = htonl(itConfig->second.nLeaseTime); pOptions += 4;
                                    *pOptions++ = 53; *pOptions++ = 1; *pOptions++ = DhcpProtokol::DHCPOFFER;
                                    pOptions = fnSetOptionFromRequestList(pOptions, dhcpProto.m_vOptionRequest);
                                    *pOptions++ = 255;    // End of options

                                    size_t iLen = pOptions - pBuffer.get();
                                    if (iLen < 300) iLen = 300;
                                    pUdpSocket->Write(pBuffer.get(), iLen, "255.255.255.255:68");
                                }
                            }
                            else if (dhcpProto.m_cDhcpType == DhcpProtokol::DHCPREQUEST)
                            {
                                uint8_t nMode = 0;
                                // DHCPREQUEST after DHCPOFFER
                                if (dhcpProto.m_strServerIdent == itSocket->second.strIpAddr && dhcpProto.m_DhcpHeader.ciaddr == 0 && dhcpProto.m_strRequestIp.empty() == false)
                                    nMode = 1;
                                // during INIT-REBOOT
                                if (dhcpProto.m_strServerIdent.empty() == true && dhcpProto.m_DhcpHeader.ciaddr == 0 && dhcpProto.m_strRequestIp.empty() == false)
                                    nMode = 2;
                                // during RENEWING + REBINDING
                                if (dhcpProto.m_strServerIdent.empty() == true && dhcpProto.m_DhcpHeader.ciaddr != 0 && dhcpProto.m_strRequestIp.empty() == true)
                                    nMode = 3;

                                if (nMode != 0)
                                {
                                    string strReturnAddr = "255.255.255.255:68";

                                    if (nMode == 3 && (dhcpProto.m_DhcpHeader.flags & 0x8000) == 0)
                                    {
                                        //strReturnAddr = inet_ntoa(*(reinterpret_cast<const struct in_addr*>(&dhcpProto.m_DhcpHeader.ciaddr))) + string(":68");
                                        char caAddrBuf[INET6_ADDRSTRLEN + 1] = { 0 };
                                        strReturnAddr = inet_ntop(AF_INET, reinterpret_cast<struct in_addr*>(&dhcpProto.m_DhcpHeader.ciaddr), caAddrBuf, sizeof(caAddrBuf));
                                    }

                                    if (nMode == 1 && itIp != end(m_maIpLeases) && itIp->second.strIP != dhcpProto.m_strRequestIp)
                                    {
                                        m_maIpLeases.erase(arHwAddr);
                                        itIp = end(m_maIpLeases);
                                    }

                                    if (nMode == 1 && itIp == end(m_maIpLeases))
                                    {
                                        auto res = m_maIpLeases.emplace(arHwAddr, IP_ENTRY({ dhcpProto.m_strClientIdent, itSocket->second.strIpAddr.substr(0, nPos + 1) + to_string(nextIp++), IP_OFFERT, chrono::system_clock::now() }));
                                        if (res.second == true)
                                            itIp = res.first;
                                    }

                                    if (itIp != end(m_maIpLeases))
                                    {
                                        itIp->second.nFlag = IP_LEASE;
                                        itIp->second.tLeaseTime = chrono::system_clock::now();

                                        DhcpHeader.ciaddr = dhcpProto.m_DhcpHeader.ciaddr;
                                        //DhcpHeader.yiaddr = ::inet_addr(itIp->second.strIP.c_str());
                                        ::inet_pton(AF_INET, itIp->second.strIP.c_str(), &DhcpHeader.yiaddr);
                                        *pOptions++ = 51; *pOptions++ = 4; *((long*)pOptions) = htonl(itConfig->second.nLeaseTime); pOptions += 4;
                                        *pOptions++ = 53; *pOptions++ = 1; *pOptions++ = DhcpProtokol::DHCPACK;
                                        pOptions = fnSetOptionFromRequestList(pOptions, dhcpProto.m_vOptionRequest);
                                        *pOptions++ = 255;    // End of options

                                        size_t iLen = pOptions - pBuffer.get();
                                        if (iLen < 300) iLen = 300;
                                        pUdpSocket->Write(pBuffer.get(), iLen, strReturnAddr);
                                    }
                                }
                            }
                            else if (dhcpProto.m_strServerIdent == itSocket->second.strIpAddr && dhcpProto.m_cDhcpType == DhcpProtokol::DHCPDECLINE)
                            {
                                // No answer will be send to this message
                                OutputDebugString(L"DhcpProtokol::DHCPDECLINE empfangen\r\n");

                                // The problem IP is send in the request ip option
                                if (dhcpProto.m_strRequestIp.empty() == false)
                                {
                                    for (auto& iter : m_maIpLeases)
                                    {   //search the ip in our list, and erase the entry. the bext ip counter will increase ist
                                        if (iter.second.strIP == dhcpProto.m_strRequestIp)
                                        {
                                            iter.second.nFlag = IP_DECLINE;
                                            //m_maIpLeases.erase(iter.first);
                                            break;
                                        }
                                    }
                                }
                            }
                            else if (dhcpProto.m_strServerIdent == itSocket->second.strIpAddr && dhcpProto.m_cDhcpType == DhcpProtokol::DHCPRELEASE)
                            {
                                // No answer will be send to this message
                                OutputDebugString(L"DhcpProtokol::DHCPRELEASE empfangen\r\n");
                                if (itIp != end(m_maIpLeases))
                                {
                                    itIp->second.nFlag = IP_RELEASE;
                                    itIp->second.tLeaseTime = chrono::system_clock::now();
                                }
                            }
                            else if (dhcpProto.m_cDhcpType == DhcpProtokol::DHCPINFORM)
                            {
                                if (dhcpProto.m_DhcpHeader.ciaddr != 0) // if we don't have a return address we ignore the message
                                {
                                    DhcpHeader.ciaddr = dhcpProto.m_DhcpHeader.ciaddr;
                                    *pOptions++ = 53; *pOptions++ = 1; *pOptions++ = DhcpProtokol::DHCPACK;
                                    pOptions = fnSetOptionFromRequestList(pOptions, dhcpProto.m_vOptionRequest);
                                    *pOptions++ = 255;    // End of options

                                    size_t iLen = pOptions - pBuffer.get();
                                    if (iLen < 300) iLen = 300;
                                    //string strReturnAddr = inet_ntoa(*(reinterpret_cast<const struct in_addr*>(&dhcpProto.m_DhcpHeader.ciaddr))) + string(":68");
                                    char caAddrBuf[INET6_ADDRSTRLEN + 1] = { 0 };
                                    string strReturnAddr = inet_ntop(AF_INET, reinterpret_cast<struct in_addr*>(&dhcpProto.m_DhcpHeader.ciaddr), caAddrBuf, sizeof(caAddrBuf));
                                    pUdpSocket->Write(pBuffer.get(), iLen, strReturnAddr);
                                }
                            }
                        }// find_if HW Address blocked
                    }// itConfig != end(m_maConfig)
                }
            }
            else
                OutputDebugString(L"No ethernet address request\r\n");
        }
    }

private:
    wstring                            m_strModulePath;
    map<string, CONFIG>                m_maConfig;
    map<UdpSocket*, SOCKET_ENTRY>      m_maSockets;
    map<array<uint8_t, 16>, IP_ENTRY>  m_maIpLeases;
};

int main(int argc, const char* argv[])
{
#if defined(_WIN32) || defined(_WIN64)
    // Detect Memory Leaks
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));

    _setmode(_fileno(stdout), _O_U16TEXT);
#endif

    DhcpServer mDhcpSrv;
    mDhcpSrv.Start();

#if defined(_WIN32) || defined(_WIN64)
    _getch();
#else
    getchar();
#endif

    mDhcpSrv.Stop();

    return 0;
}

