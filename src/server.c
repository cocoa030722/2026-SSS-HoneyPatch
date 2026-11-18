/* server.c - Heartbleed 형태의 over-read 취약점을 가진 TCP 서버 

빌드 옵션 
    (none)              : 취약 서버
    -DPATCH             : 일반 패치 (L > |P| 이면 오류 응답)
    -DHONEY             : 허니패치  (L > |P| 이면 decoy로 포크)
    -DHONEY -DNO_REDACT : 허니패치, 비밀 삭제 끔 (실험용)

서버 실행 : ./server <port> [victims.txt]

환경 변수 HP_LOG  : 로그 파일 경로 (기본 hp.log)
환경 변수 HP_FILL : 설정하면 빈 슬롯을 가상 사용자로 채움 (실험용)

로컬 실습 전용: 127.0.0.1에만 바인딩한다.
*/

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "hp.h"

/* 전체 메모리의 실제 정의 */
// 전역 변수 공유로 인해 hp.c에서도 접근 가능
struct arena A;

/* handle_conn()의 결과 */
#define CONN_CLOSED 0
#define CONN_MOVED  1   // 연결이 decoy로 넘어감

/* ---------- 송수신 보조 함수 ---------- */

/* 정확히 n바이트 받기 */
// fd에서 n바이트를 받아 buf에 저장
static int recv_all(int fd, void *buf, size_t n)
{
    size_t got = 0;     // 지금까지 받은 바이트 수

    // n바이트를 다 받을 때까지 계속 반복한다
    while (got < n) {
        ssize_t r = recv(fd, (char *)buf + got, n - got, 0);
        if (r == 0)     // 상대가 연결을 close
            return 0;
        if (r < 0) {
            if (errno == EINTR)
                continue;   // 재시도
            return 0;   // 오류
        }
        got += (size_t)r;
    } 
    return 1;   // 다 받기 성공
}

/* 정확히 n바이트 보내기 */
// 위의 함수와 같은 구조
static int send_all(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, (const char *)buf + sent, n - sent, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        sent += (size_t)r;
    }
    return 1;
}

/* 오류 응답 보내기 */
static int send_error(int fd)
{
    uint8_t out[3] = { ST_ERR, 0, 0 };
    return send_all(fd, out, sizeof(out)) ? 0 : -1;
}

/* ---------- 세션 관리 ---------- */
static void load_victims(const char *path)
{
    // victims.txt의 내용으로
    FILE *fp = path ? fopen(path, "r") : NULL;
    if (!fp) {
        hp_log("[SRV] victims file not found, slots 0-1 empty");
        return;
    }
    // 슬롯 0, 1을 채운다
    char user[64], token[64];
    int i = 0;
    while (i < FIRST_GUEST_SLOT && fscanf(fp, "%63s %63s", user, token) == 2) {
        if (strlen(token) != TOKEN_LEN)
            continue;
        size_t n = strlen(user);
        memcpy(A.sess[i].user, user, n < USER_LEN ? n : USER_LEN);
        memcpy(A.sess[i].token, token, TOKEN_LEN);
        i++;
    }
    fclose(fp);
}

/* 빈 슬롯을 가상 사용자로 채운다(실험용 함수) */
// 환경 변수 HP_FILL이 있을 때만 main에서 호출
static void fill_slots(void)
{
    // 접속용으로 마지막 2개 슬롯은 비운다 (NSLOT - 2)
    for (int i = FIRST_GUEST_SLOT; i < NSLOT - 2; i++) {
        if (A.sess[i].user[0] != '\0')
            continue;
        snprintf(A.sess[i].user, USER_LEN, "u%05d", i);
        random_hex(A.sess[i].token, TOKEN_LEN);
    }
}

/* 접속자에게 슬롯 배정 */
static int assign_slot(void)
{
    // 슬롯 2(FIRST_GUEST_SLOT)부터 첫 번째 빈자리를 준다
    for (int i = FIRST_GUEST_SLOT; i < NSLOT; i++) {
        if (A.sess[i].user[0] == '\0') {
            // 유저 이름은 g + 슬롯 번호
            snprintf(A.sess[i].user, USER_LEN, "g%d", i);
            // 비밀 토큰은 랜덤
            random_hex(A.sess[i].token, TOKEN_LEN);
            return i;
        }
    }
    return -1;
}

/* 슬롯 비우기 */
static void free_slot(int i)
{
    if (i >= 0)
        // 32바이트를 전부 0으로 채운다
        // 슬롯이 비어있는지를 판단할때 user[0] == 0 인지로 판단한다
        memset(&A.sess[i], 0, sizeof(A.sess[i]));
}

/* ---------- Heartbleed 취약점 / (허니패치 지점) ---------- */
static int heartbeat(int conn, int slot, int L, const uint8_t *payload, int P)
{
    (void)slot;     // 컴파일러 경고를 없애기 위해 void로 형변환

    if (hp_in_decoy())      // 이 프로세스가 decoy라면 로그 기록
        hp_log("[DECOY] request L=%d P=%d", L, P);

/* 일반 패치 : 거부해서 패치 사실이 드러난다 */
#if defined(PATCH)
    if (L > P)      // 조건 동일
        return send_error(conn);

/* 허니패치: 탐지 조건은 일반 패치와 동일하고 동작만 다르다 */
#elif defined(HONEY)
    if (L > P) {    // 조건 동일
        // 라이브러리의 hp_fork() 호출 (동작은 hp.c 설명 참고)
        int r = hp_fork(conn, slot, L, P);

        if (r == HP_TARGET)         // 부모 프로세스인 경우
            return CONN_MOVED;

        // 그 외
        // 즉, HP_DECOY or HP_FAIL   
        hp_skip(return send_error(conn));   /* decoy에서는 건너뜀, fork 실패 시 실행 */
    }
#endif

    /* 전체 메모리 바깥 읽기 방지 */
    // 의도한 취약점이 아니므로 막음
    if (L > (int)sizeof(A))
        L = (int)sizeof(A);

    /* heartbeat 버퍼에 payload 저장 */
    // 하기전에 버퍼 초기화
    memset(A.hb, 0, HB_SIZE);
    // 그 후 저장
    memcpy(A.hb, payload, (size_t)P);

    //////////////////////////////////////////////////////////////////
    /* 취약 지점: hb 시작부터 L바이트를 그대로 응답 (L > |P| 검증 없음) */
    //////////////////////////////////////////////////////////////////
    
    /* 응답을 담을 버퍼 */
    static uint8_t out[3 + sizeof(struct arena)];

    // 참고) 응답 형식 [상태 1B][길이 2B][데이터]

    out[0] = ST_OK;             // 상태 코드
    /* 길이 L(빅 엔디언) */
    out[1] = (uint8_t)(L >> 8);
    out[2] = (uint8_t)(L & 0xff);

    memcpy(out + 3, (const char *)&A, (size_t)L); // <- (size_t)L바이트를 그냥 복사해버린다
    return send_all(conn, out, 3 + (size_t)L) ? 0 : -1;
}


// 참고) 요청 형식 [레코드 길이 2B][선언 길이 L 2B][payload P]

static int handle_conn(int conn, int slot)
{
    uint8_t hdr[2];             // 레코드 길이 2바이트를 받을 곳
    uint8_t body[2 + HB_SIZE];  // 선언 길이 L 2바이트 + payload 최대 16바이트 = 18

    for (;;) {
        /* 레코드 길이(2바이트)를 받음*/
        if (!recv_all(conn, hdr, 2))
            return CONN_CLOSED;
        int rec_len = (hdr[0] << 8) | hdr[1];

        /* payload가 hb보다 크면 거부 */
        // 의도한 취약점이 아니므로 막음
        if (rec_len < 2 || rec_len > 2 + HB_SIZE) {
            send_error(conn);
            return CONN_CLOSED;
        }

        /* 레코드 길이(rec_len)만큼 본문을 받음 */
        if (!recv_all(conn, body, (size_t)rec_len))
            return CONN_CLOSED;
        int L = (body[0] << 8) | body[1];
        int P = rec_len - 2;

        /* heartbeat */
        int r = heartbeat(conn, slot, L, body + 2, P);
        if (r == CONN_MOVED)
            return CONN_MOVED;
        if (r < 0)
            return CONN_CLOSED;
    }
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 9000;
    const char *victims = argc > 2 ? argv[2] : NULL;
    const char *logpath = getenv("HP_LOG") ? getenv("HP_LOG") : "hp.log";

    /* SIGPIPE, SIGCHLD 무시*/
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);    

    /* 로그 파일 열기 */
    // 쓰기전용, 파일이 없으면 만듦, 파일 끝에 붙임, 권한은 0644
    int log_fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);

    /* 전체 메모리 0으로 밀어서 초기화 */
    memset(&A, 0, sizeof(A));

    /* 로그만 먼저 준비 */
    hp_init(-1, log_fd);

    /* 가상의 비밀 유출 피해자 등록 */
    load_victims(victims);

    /* 실험용 */
    if (getenv("HP_FILL"))
        fill_slots();

    /* TCP 소켓 생성 */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);

    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(lfd, 16) < 0) {
        perror("bind/listen");
        return 1;
    }

    /* 대기 소켓 추가 */
    hp_init(lfd, log_fd);
    hp_log("[SRV] start variant=%s nslot=%d arena=%d port=%d",
           VARIANT, NSLOT, (int)sizeof(A), port);

    /* accept()로 접속 처리 */
    for (;;) {
        // 접속 시
        int conn = accept(lfd, NULL, NULL);
        if (conn < 0)
            continue;

        // 슬롯 배정
        int slot = assign_slot();
        // 슬롯이 다 찼으면 오류 전송 후 close
        if (slot < 0) {
            send_error(conn);
            close(conn);
            continue;
        }
        
        // 연결 처리
        int r = handle_conn(conn, slot);
        
        // decoy는 연결이 종료된 후 여기서 _exit()로 스스로 종료한다
        // 공격자가 연결을 끊지 않는 경우는 hp_fork()에서 예약한 alarm(DECOY_TTL)이 강제 종료한다
        if (hp_in_decoy()) {          
            hp_log("[DECOY] end pid=%d", (int)getpid());
            _exit(0);
        }

        // target은 연결을 close한 후
        if (r != CONN_MOVED)
            close(conn);

        // 접속자의 슬롯을 비우고 무한루프 계속 진행
        free_slot(slot);
    }
}
