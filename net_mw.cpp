// FIRST OF ALL : don't copy  and past understand this notice :
// net_mw.cpp
// Single file Network Watcher for Windows (uses Npcap/wpcap)
// Features:
//  1 list interfaces and let user choose
//  3 capture live packets
//  3 detect new MACs (first-seen)
//  4 detect ARP IP->MAC changes (possible ARP spoofing)
//  5 count DNS queries per source IP and alert on spike
//  6 count outbound TCP SYNs per source IP and alert on burst
//  7 log events to file
// Build (Developer Command Prompt):
// cl /EHsc network_watch_win.cpp /I"C:\Path\To\Npcap\Include" /link /LIBPATH:"C:\Path\To\Npcap\Lib" wpcap.lib ws2_32.lib
// Run (as Admin):
// net_mw.cpp
// Notes:
//  - Requires Npcap installed. Must run elevated to open adapters.
//  - To capture raw 802.11 frames on Windows you also need adapter driver support and Npcap monitor mode enabled; this example treats Ethernet-layer packets (works for wired or Wi-Fi when adapter driver exposes link-layer Ethernet frames).
//  - Keep this code for defensive/legitimate monitoring on networks you control or have permission to monitor.
//  - i did what i coulD the rest According to ur knowledge

#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdint>

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <atomic>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

//  helpers 

static std::string now_str() {
    std::time_t t = std::time(nullptr);
    struct tm tm;
    localtime_s(&tm, &t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}

static std::string mac_to_str(const u_char* mac) {
    char buf[64];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return std::string(buf);
}

static std::string ip_to_str(uint32_t ip_be) {
    // ip_be is network byte order
    struct in_addr a;
    a.S_un.S_addr = ip_be;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

// safe file logger
class Logger {
    std::mutex m;
    std::ofstream ofs;
public:
    Logger() {
        std::string fname = "netwatch_" + now_str();
        // replace spaces/colons
        for (char &c : fname) if (c==' '||c==':') c = '_';
        fname += ".log";
        ofs.open(fname, std::ios::out | std::ios::app);
        if (!ofs.is_open()) {
            fprintf(stderr, "Failed to open log file: %s\n", fname.c_str());
        } else {
            ofs << "=== netwatch started: " << now_str() << " ===\n";
            ofs.flush();
        }
    }
    void log(const std::string &s) {
        std::lock_guard<std::mutex> lk(m);
        std::string line = "[" + now_str() + "] " + s;
        printf("%s\n", line.c_str());
        if (ofs.is_open()) {
            ofs << line << "\n";
            ofs.flush();
        }
    }
} logger;



// keep track of seen MACs
static std::mutex macs_mutex;
static std::unordered_set<std::string> seen_macs;

// ARP mapping: IP (network order) -> MAC string
static std::mutex arp_mutex;
static std::unordered_map<uint32_t, std::string> arp_table; // ip_be -> mac

// DNS counts: src_ip -> vector of timestamps (seconds)
static std::mutex dns_mutex;
static std::unordered_map<uint32_t, std::vector<time_t>> dns_requests;

// SYN scan counts: src_ip -> vector of timestamps for SYN packets
static std::mutex syn_mutex;
static std::unordered_map<uint32_t, std::vector<time_t>> syn_attempts;

// thresholds
const int DNS_SPIKE_COUNT = 20;      // within window => spike
const int DNS_SPIKE_WINDOW = 60;     // seconds
const int SYN_BURST_COUNT = 40;
const int SYN_BURST_WINDOW = 30;     // seconds

// helper to push timestamp and purge old entries
static void push_and_trim(std::vector<time_t> &v, int window_sec, time_t now) {
    v.push_back(now);
    // remove older than window
    size_t keep_from = 0;
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] >= now - window_sec) { keep_from = i; break; }
    }
    if (keep_from > 0) {
        std::vector<time_t> tmp(v.begin() + keep_from, v.end());
        v.swap(tmp);
    }
}

// packet parsing helpers 

// minimal Ethernet header
#pragma pack(push,1)
struct eth_hdr {
    u_char dst[6];
    u_char src[6];
    uint16_t ethertype; // big-endian
};

// minimal ARP header (Ethernet/IPv4)
struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    u_char hlen;
    u_char plen;
    uint16_t oper;
    u_char sha[6];
    uint32_t spa; // network byte order
    u_char tha[6];
    uint32_t tpa; // network byte order
};

// IPv4 header (partial)
struct ipv4_hdr {
    u_char ver_ihl;
    u_char tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    u_char ttl;
    u_char protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
};

// UDP header
struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
};

// TCP header (partial)
struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint16_t data_off_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};
#pragma pack(pop)

// checks if an EtherType corresponds to IPv4
static bool is_ethertype_ipv4(uint16_t ethertype_be) {
    return ntohs(ethertype_be) == 0x0800;
}
static bool is_ethertype_arp(uint16_t ethertype_be) {
    return ntohs(ethertype_be) == 0x0806;
}

//  alert functions 

static void alert_new_mac(const std::string &mac) {
    logger.log("[ALERT] New MAC seen: " + mac);
    // optionally, you could call a webhook or create a Windows notification here
    // keep it lightweight (don't block capture)
}

static void alert_arp_change(const std::string &ip, const std::string &oldmac, const std::string &newmac) {
    std::ostringstream ss;
    ss << "[ALERT] ARP IP->MAC change for " << ip << " : " << oldmac << " -> " << newmac;
    logger.log(ss.str());
}

static void alert_dns_spike(const std::string &ip, int count, int window) {
    std::ostringstream ss;
    ss << "[ALERT] DNS query spike from " << ip << " : " << count << " queries in " << window << "s";
    logger.log(ss.str());
}

static void alert_syn_burst(const std::string &ip, int count, int window) {
    std::ostringstream ss;
    ss << "[ALERT] SYN burst from " << ip << " : " << count << " SYNs in " << window << "s";
    logger.log(ss.str());
}

//  capture callback 

// callback called by pcap loop. We keep callback minimal and push detection into shared state.
void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    (void)user;
    if (!h || !bytes) return;
    if (h->caplen < sizeof(eth_hdr)) return;

    const eth_hdr* eh = (const eth_hdr*)bytes;
    std::string src_mac = mac_to_str(eh->src);

    // 1) new MAC detection
    {
        std::lock_guard<std::mutex> lk(macs_mutex);
        if (seen_macs.find(src_mac) == seen_macs.end()) {
            seen_macs.insert(src_mac);
            std::ostringstream ss;
            ss << "[NEW_DEVICE] " << src_mac << " first seen. Caplen=" << h->caplen;
            logger.log(ss.str());
            // non-blocking alert
            std::thread(alert_new_mac, src_mac).detach();
        }
    }

    // ARP processing
    if (is_ethertype_arp(eh->ethertype)) {
        // ensure enough bytes for arp header
        size_t off = sizeof(eth_hdr);
        if (h->caplen >= off + sizeof(arp_hdr)) {
            const arp_hdr* ah = (const arp_hdr*)(bytes + off);
            uint32_t spa = ah->spa; // already network-order
            std::string sha = mac_to_str(ah->sha);
            {
                std::lock_guard<std::mutex> lk(arp_mutex);
                auto it = arp_table.find(spa);
                if (it == arp_table.end()) {
                    // new mapping, record
                    arp_table[spa] = sha;
                    std::ostringstream ss;
                    ss << "[ARP] Learned " << ip_to_str(spa) << " -> " << sha;
                    logger.log(ss.str());
                } else {
                    if (it->second != sha) {
                        // IP mapped to different MAC -> possible ARP spoofing
                        std::string old = it->second;
                        it->second = sha; // update
                        std::thread(alert_arp_change, ip_to_str(spa), old, sha).detach();
                    }
                }
            }
        }
        return;
    }

    // IPv4 processing
    if (is_ethertype_ipv4(eh->ethertype)) {
        size_t off = sizeof(eth_hdr);
        if (h->caplen < off + sizeof(ipv4_hdr)) return;
        const ipv4_hdr* iph = (const ipv4_hdr*)(bytes + off);
        int ihl = (iph->ver_ihl & 0x0f) * 4;
        if (h->caplen < off + ihl) return;

        uint32_t saddr = iph->saddr;
        uint32_t daddr = iph->daddr;
        uint8_t proto = iph->protocol;

        // DNS detection: UDP port 53 (either sport or dport)
        if (proto == IPPROTO_UDP) {
            size_t off_udp = off + ihl;
            if (h->caplen >= off_udp + sizeof(udp_hdr)) {
                const udp_hdr* udph = (const udp_hdr*)(bytes + off_udp);
                uint16_t sport = ntohs(udph->sport);
                uint16_t dport = ntohs(udph->dport);
                if (sport == 53 || dport == 53) {
                    time_t now = std::time(nullptr);
                    {
                        std::lock_guard<std::mutex> lk(dns_mutex);
                        auto &vec = dns_requests[saddr];
                        push_and_trim(vec, DNS_SPIKE_WINDOW, now);
                        if ((int)vec.size() >= DNS_SPIKE_COUNT) {
                            // alert (once per threshold crossing)
                            alert_dns_spike(ip_to_str(saddr), (int)vec.size(), DNS_SPIKE_WINDOW);
                            // clear vector to avoid repeated alerts back-to-back,
                            // keep the latest timestamp so we still count new activity
                            vec.clear();
                            vec.push_back(now);
                        }
                    }
                }
            }
        }

        // TCP SYN detection
        if (proto == IPPROTO_TCP) {
            size_t off_tcp = off + ihl;
            if (h->caplen >= off_tcp + sizeof(tcp_hdr)) {
                const tcp_hdr* tcph = (const tcp_hdr*)(bytes + off_tcp);
                uint16_t dport = ntohs(tcph->dport);
                uint16_t sport = ntohs(tcph->sport);
                uint16_t flags = ntohs(tcph->data_off_flags) & 0x01FF; // flags low 9 bits
                bool syn = (flags & 0x0002) != 0;
                bool ack = (flags & 0x0010) != 0;
                if (syn && !ack) {
                    time_t now = std::time(nullptr);
                    {
                        std::lock_guard<std::mutex> lk(syn_mutex);
                        auto &vec = syn_attempts[saddr];
                        push_and_trim(vec, SYN_BURST_WINDOW, now);
                        if ((int)vec.size() >= SYN_BURST_COUNT) {
                            alert_syn_burst(ip_to_str(saddr), (int)vec.size(), SYN_BURST_WINDOW);
                            vec.clear();
                            vec.push_back(now);
                        }
                    }
                }
            }
        }

        // Optional: could inspect payloads for HTTP Host headers, suspicious domains, etc.
    }
}

//  main flow 

int main(int argc, char** argv) {
    printf("=== Simple Network Watcher (Windows) ===\n");
    printf("Requires Npcap and admin privileges.\n");

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return 1;
    }

    std::vector<pcap_if_t*> devs;
    int idx = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        devs.push_back(d);
        printf("[%2d] Name: %s\n    Description: %s\n",
            idx,
            d->name ? d->name : "(n/a)",
            d->description ? d->description : "(no description)");
        ++idx;
    }

    if (devs.empty()) {
        fprintf(stderr, "No adapters found. Is Npcap installed and are you admin?\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    int choice = 0;
    if (argc >= 2) {
        choice = atoi(argv[1]);
        if (choice < 0 || choice >= (int)devs.size()) {
            fprintf(stderr, "Invalid adapter index %d\n", choice);
            pcap_freealldevs(alldevs);
            return 1;
        }
    } else {
        printf("\nSelect adapter index to capture on: ");
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Input error\n");
            pcap_freealldevs(alldevs);
            return 1;
        }
        if (choice < 0 || choice >= (int)devs.size()) {
            fprintf(stderr, "Invalid choice\n");
            pcap_freealldevs(alldevs);
            return 1;
        }
    }

    char *devname = devs[choice]->name;
    printf("Opening adapter: %s\n", devname);

    // options: snaplen 65536, promiscuous 1, timeout 1000ms
    pcap_t* handle = pcap_open_live(devname, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Try to set non-blocking (optional)
    // pcap_setnonblock(handle, 1, errbuf);

    // compile simple filter to ignore 802.11 management frames etc.
    // For now we capture everything and process in callback.
    struct bpf_program fp;
    const char* filter_exp = ""; // empty means capture all
    if (filter_exp[0]) {
        if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "pcap_compile failed\n");
        } else {
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "pcap_setfilter failed\n");
            }
            pcap_freecode(&fp);
        }
    }

    // spawn worker thread that periodically prints statistics and prunes old state
    std::atomic<bool> stop_flag(false);
    std::thread stats_thread([&stop_flag]() {
        while (!stop_flag.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            // prune old ARP entries (optional) - keep it simple
            {
                std::lock_guard<std::mutex> lk(arp_mutex);
                // optional: do nothing for now
            }
            // print small summary
            size_t macs = 0;
            {
                std::lock_guard<std::mutex> lk(macs_mutex);
                macs = seen_macs.size();
            }
            size_t arp_entries = 0;
            {
                std::lock_guard<std::mutex> lk(arp_mutex);
                arp_entries = arp_table.size();
            }
            logger.log("[STATS] Known MACs: " + std::to_string(macs) + " | ARP entries: " + std::to_string(arp_entries));
        }
    });

    // start capture (this blocks until an error or break)
    logger.log(std::string("Starting capture on ") + devname + ". Press Ctrl+C to stop.");

    // we use pcap_dispatch in a loop so we can exit gracefully on Ctrl+C
    // set a signal handler for CTRL+C
    BOOL WINAPI console_handler(DWORD signal) {
        if (signal == CTRL_C_EVENT) {
            logger.log("Received Ctrl+C, stopping capture...");
            // no easy way to break pcap_dispatch from here; set non-block and rely on timeout loops below
            return TRUE;
        }
        return FALSE;
    }
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)console_handler, TRUE);

    // main loop: call pcap_dispatch with small packet count to allow periodic checks
    while (true) {
        int rv = pcap_dispatch(handle, 100, packet_handler, nullptr);
        if (rv == -1) {
            // error
            fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
            break;
        } else if (rv == 0) {
            // timeout, continue
            // check whether user signaled to stop via console? There's no direct flag. We'll let ctrl+c break.
        }
        // tiny sleep to avoid tight loop (pcap_dispatch has timeout but be gentle)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // check for Ctrl+C via console input? Keep it simple - user can close console or ctrl+c.
        // Alternatively allow user to press 'q' to quit non-blocking:
        if (_kbhit()) {
            int c = _getch();
            if (c == 'q' || c == 'Q') {
                logger.log("User requested quit (q). Stopping...");
                break;
            }
        }
    }

    // cleanup
    stop_flag.store(true);
    if (stats_thread.joinable()) stats_thread.join();

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    logger.log("Capture stopped. Exiting.");
    return 0;
}
