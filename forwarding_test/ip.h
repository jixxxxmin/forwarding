#include <stdint.h>
#include <winsock2.h> // Windows ȯ�濡�� htons, ntohs ���� ���� �ʿ�

// IP ��� ����ü
struct ip_header {
    uint8_t  ip_header_len : 4;    // IP ��� ����
    uint8_t  ip_version : 4;       // IP ����
    uint8_t  ip_tos;             // Type of service
    uint16_t ip_total_length;    // ��Ŷ�� �� ����
    uint16_t ip_id;              // ID �ʵ�
    uint16_t ip_off;             // Fragment offset �ʵ�
    uint8_t  ip_ttl;             // TTL
    uint8_t  ip_protocol;        // �������� (��: TCP, UDP, ICMP)
    uint16_t ip_checksum;        // üũ��
    uint32_t ip_srcaddr;         // ����� IP �ּ�
    uint32_t ip_destaddr;        // ������ IP �ּ�
};

// ICMP ��� ����ü
struct icmp_header {
    uint8_t  icmp_type;          // ICMP �޽��� Ÿ��
    uint8_t  icmp_code;          // �ڵ�
    uint16_t icmp_checksum;      // üũ��
    uint16_t icmp_id;            // ID �ʵ�
    uint16_t icmp_seq;           // ������ ��ȣ
};
