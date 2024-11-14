#include <stdint.h>
#include <winsock2.h> // Windows 환경에서 htons, ntohs 등을 위해 필요

// IP 헤더 구조체
struct ip_header {
    uint8_t  ip_header_len : 4;    // IP 헤더 길이
    uint8_t  ip_version : 4;       // IP 버전
    uint8_t  ip_tos;             // Type of service
    uint16_t ip_total_length;    // 패킷의 총 길이
    uint16_t ip_id;              // ID 필드
    uint16_t ip_off;             // Fragment offset 필드
    uint8_t  ip_ttl;             // TTL
    uint8_t  ip_protocol;        // 프로토콜 (예: TCP, UDP, ICMP)
    uint16_t ip_checksum;        // 체크섬
    uint32_t ip_srcaddr;         // 출발지 IP 주소
    uint32_t ip_destaddr;        // 목적지 IP 주소
};

// ICMP 헤더 구조체
struct icmp_header {
    uint8_t  icmp_type;          // ICMP 메시지 타입
    uint8_t  icmp_code;          // 코드
    uint16_t icmp_checksum;      // 체크섬
    uint16_t icmp_id;            // ID 필드
    uint16_t icmp_seq;           // 시퀀스 번호
};
