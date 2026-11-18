/* common.h - 필요한 상수 및 구조체 선언 */

/* 전체 메모리 구조 예시 */

/*
NSLOT = 4 기준

0 ~  15 : hb        (하트비트 버퍼)
16 ~  47 : sess[0]  (alice: user 8B + token 24B)
48 ~  79 : sess[1]  (bob)
80 ~ 111 : sess[2]  (첫 번째 접속자에게 배정)
112 ~ 143 : sess[3]
*/

/*
요청: [레코드 길이 2B][선언 길이 L 2B][payload P] (빅 엔디언, 레코드 길이 = 2 + |P|)
응답: [상태 1B][길이 2B][데이터]
*/

#ifndef HP_COMMON_H
#define HP_COMMON_H

#include <stdint.h>

// 슬롯 개수
#ifndef NSLOT
#define NSLOT 4
#endif

// 버전
#ifndef VARIANT
#define VARIANT "unknown"
#endif

/* 하트비트 버퍼 */
// payload의 최대 길이도 겸한다
#define HB_SIZE 16

/* 유저 이름 */
#define USER_LEN 8

/* 비밀 토큰 길이 */
#define TOKEN_LEN 24

/* 접속자에게 배정을 시작하는 슬롯 번호 */
// 슬롯 0, 1은 공격 피해자의 슬롯 번호로 이미 등록되어 있음
// 따라서 2부터 시작
#define FIRST_GUEST_SLOT 2

// decoy의 수명(초)
#define DECOY_TTL 30

/* 응답 코드 */
#define ST_OK  0x00     // 정상 응답
#define ST_ERR 0x01     // 오류 응답

/* 세션 구조체 */
// 사용자 이름 + 비밀 토큰
// 전부 char 배열이므로 필드 사이의 패딩은 없음
struct session {
    char user[USER_LEN];
    char token[TOKEN_LEN];
};

/* 전체 메모리 영역 구조체 */
// 제안을 참고해 버퍼, 세션 슬롯을 단일 구조체로 배치 
struct arena {
    char hb[HB_SIZE];
    struct session sess[NSLOT];
};

/* 컴파일 타임 조건 검사 */
// 세션에 패딩이 존재한다면 컴파일 에러
_Static_assert(sizeof(struct session) == 32, "session must be 32 bytes");
// 전체 메모리에 패딩이 존재한다면 컴파일 에러
_Static_assert(sizeof(struct arena) == HB_SIZE + 32 * NSLOT, "arena must have no padding");

// 전역 변수 공유
extern struct arena A;

#endif
