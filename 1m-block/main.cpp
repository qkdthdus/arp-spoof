#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_HOSTS 1000
#define MAX_HOST_LEN 256

char malicious_hosts[MAX_HOSTS][MAX_HOST_LEN];
int malicious_host_count = 0;

// Host list 불러오기
void load_host_list(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open host list file");
        exit(1);
    }

    char line[512];
    malicious_host_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0; // 개행 제거
        char* comma = strchr(line, ',');
        if (!comma) continue;

        char* domain = comma + 1;
        if (strlen(domain) > 0 && malicious_host_count < MAX_HOSTS) {
            strncpy(malicious_hosts[malicious_host_count], domain, MAX_HOST_LEN - 1);
            malicious_hosts[malicious_host_count][MAX_HOST_LEN - 1] = '\0';
            malicious_host_count++;
        }
    }

    fclose(fp);
    printf("[INFO] Loaded %d malicious hosts from %s\n", malicious_host_count, filename);
}

// Host 문자열에서 포트 제거하고 대소문자 무시 비교
int host_compare(const char* host, const char* mal_host) {
    char host_only[MAX_HOST_LEN] = {0};
    const char* colon = strchr(host, ':');
    int len = colon ? (colon - host) : strlen(host);
    if (len >= MAX_HOST_LEN) return 0;
    strncpy(host_only, host, len);
    host_only[len] = '\0';
    return strcasecmp(host_only, mal_host) == 0;
}

// Boyer-Moore 단순 구현
int bm_search(const char* text, int text_len, const char* pattern) {
    int pat_len = strlen(pattern);
    if (pat_len == 0 || text_len < pat_len) return -1;

    int skip[256];
    for (int i = 0; i < 256; i++) skip[i] = pat_len;
    for (int i = 0; i < pat_len - 1; i++) skip[(unsigned char)pattern[i]] = pat_len - 1 - i;

    int i = 0;
    while (i <= text_len - pat_len) {
        int j = pat_len - 1;
        while (j >= 0 && pattern[j] == text[i + j]) j--;

        if (j < 0) return i;
        i += skip[(unsigned char)text[i + pat_len - 1]];
    }
    return -1;
}

// 패킷 처리
int process_packet(unsigned char* data, int len) {
    struct iphdr* iph = (struct iphdr*)data;
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    int iphdr_len = iph->ihl * 4;
    if (iphdr_len < sizeof(struct iphdr)) return NF_ACCEPT;

    struct tcphdr* tcph = (struct tcphdr*)(data + iphdr_len);
    int tcphdr_len = tcph->doff * 4;
    if (tcphdr_len < sizeof(struct tcphdr)) return NF_ACCEPT;

    // HTTP 트래픽인지 확인
    if (ntohs(tcph->dest) != 80) return NF_ACCEPT;

    int payload_offset = iphdr_len + tcphdr_len;
    if (payload_offset >= len) return NF_ACCEPT;

    unsigned char* payload = data + payload_offset;
    int payload_len = len - payload_offset;

    int pos = bm_search((char*)payload, payload_len, "Host: ");
    if (pos < 0) return NF_ACCEPT;

    char* host_start = (char*)payload + pos + 6;
    char* host_end = strstr(host_start, "\r\n");
    if (!host_end || host_end - host_start >= MAX_HOST_LEN) return NF_ACCEPT;

    char host[MAX_HOST_LEN] = {0};
    strncpy(host, host_start, host_end - host_start);
    host[host_end - host_start] = '\0';

    printf("[INFO] HTTP Host: %s\n", host);

    for (int i = 0; i < malicious_host_count; i++) {
        if (host_compare(host, malicious_hosts[i])) {
            printf("[BLOCK] Matched Malicious Host: %s\n", host);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// 콜백 함수
static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
              struct nfq_data* nfa, void* data) {
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char* packet_data;
    int len = nfq_get_payload(nfa, &packet_data);
    if (len >= 0) {
        int verdict = process_packet(packet_data, len);
        return nfq_set_verdict(qh, id, verdict, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// 메인 함수
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <malicious-host-list.txt>\n", argv[0]);
        exit(1);
    }

    load_host_list(argv[1]);

    struct nfq_handle* h = nfq_open();
    if (!h) { perror("nfq_open"); exit(1); }

    if (nfq_unbind_pf(h, AF_INET) < 0) perror("nfq_unbind_pf");
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); exit(1); }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) { perror("nfq_create_queue"); exit(1); }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); exit(1);
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
