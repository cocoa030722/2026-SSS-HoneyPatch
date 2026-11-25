/* hp.c - 허니패치 라이브러리 구현 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "hp.h"

/* 서버의 대기 소켓 fd */
static int g_listen_fd = -1;

/* 로그 파일의 fd */
static int g_log_fd    = -1;

/* decoy FLAG */
// 이 프로세스가 decoy라면 1
static int g_in_decoy  = 0;

static char fake_tokens[NSLOT][TOKEN_LEN + 1];
static int fake_initialized = 0;

void hp_init(int listen_fd, int log_fd)
{
    g_listen_fd = listen_fd;
    g_log_fd    = log_fd;
}

/* 현재 프로세스가 decoy인지 확인하는 함수 */
int hp_in_decoy(void)
{
    return g_in_decoy;      // decoy FLAG를 그대로 돌려준다
}

/* 로그 한 줄을 기록하는 함수 */
void hp_log(const char *fmt, ...)
{
    if (g_log_fd < 0)
        return;

    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n > (int)sizeof(buf) - 2)
        n = sizeof(buf) - 2;
    buf[n++] = '\n';
    (void)!write(g_log_fd, buf, n);
}

/* 토큰과 같은 형식의 가짜 비밀을 만드는 함수 */
void random_hex(char *dst, int len)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char rnd[64];
    // 리눅스의 특수 파일을 읽어 랜덤 바이트를 추출한다
    int fd = open("/dev/urandom", O_RDONLY);

    // 파일 열기에 실패했거나, len 바이트를 읽는 과정에서 문제가 발생했을 경우
    // 고정 패턴으로 비밀을 생성한다
    if (fd < 0 || read(fd, rnd, (size_t)len) != len) {
        for (int i = 0; i < len; i++)
            rnd[i] = (unsigned char)(i * 31 + 7);
    }
    if (fd >= 0)
        close(fd);
    for (int i = 0; i < len; i++)
        dst[i] = hex[rnd[i] & 0x0f];
}

/* 공격자 슬롯(keep_slot)을 제외한 모든 세션의 토큰을 같은 길이와 형식의 가짜 값으로 덮어쓴다 */
void hp_redact(int keep_slot)
{
    int count = 0;

    for (int i = 0; i < NSLOT; i++) {
        if (i == keep_slot || A.sess[i].user[0] == '\0')
            continue;

        memcpy(A.sess[i].token, fake_tokens[i], TOKEN_LEN);
        count++;
    }

    hp_log("[DECOY] redacted %d session(s)", count);
}

/* 
공격이 탐지되면 세션을 decoy로 복제한다
    
fork()시 자식 프로세스(decoy)는 부모 프로세스(target)의 File Descriptor Table을 그대로 복제해 상속받는다
fd는 커널 안의 소켓을 가리키는 번호일 뿐이라 소켓 자체는 복사되지 않고 target과 decoy가 같은 소켓을 가리키게 된다

target은 공격자 소켓(conn)을 닫는다(close)
target이 conn을 close해도 decoy의 fd가 남아 있으므로 연결은 끊기지 않는다

decoy는 대기 소켓을 close한다 
설계 상 대기 소켓은 target만 가지며 닫지 않으면 새 정상 사용자의 접속이 decoy에게 배정될 수도 있기 때문이다
그 후 비밀을 삭제하고 공격자의 연결을 이어서 처리한다
*/
int hp_fork(int conn_fd, int attacker_slot, int L, int P)
{
    // 이미 decoy라면 다시 fork하지 않는다
    if (g_in_decoy)
        return HP_DECOY;

    // fork() 실시 지점
    pid_t pid = fork();

    // fork() 실패 시
    if (pid < 0) {
        hp_log("[HP] fork failed, fallback to patch");
        return HP_FAIL;
    }

    // target
    if (pid > 0) {
        // 공격자 연결 close
        close(conn_fd);
        hp_log("[HP] fork decoy pid=%d slot=%d L=%d P=%d", (int)pid, attacker_slot, L, P);
        return HP_TARGET;
    }

    // decoy라면 decoy FLAG를 1로 설정한다
    g_in_decoy = 1;
    // 부모의 대기 소켓 close
    if (g_listen_fd >= 0)
        close(g_listen_fd);

#ifndef NO_REDACT
    // 비밀 삭제 (redaction)
    hp_redact(attacker_slot);
#else
    // -DNO_REDACT 옵션으로 빌드하면 관련 로그만 추가한다
    hp_log("[DECOY] redaction disabled");
#endif
    // decoy의 수명을 제한한다
    alarm(DECOY_TTL);
    hp_log("[DECOY] start pid=%d slot=%d", (int)getpid(), attacker_slot);
    return HP_DECOY;
}

void hp_init_fake_tokens(void)
{
    if (fake_initialized)
        return;

    for (int i = 0; i < NSLOT; i++)
        random_hex(fake_tokens[i], TOKEN_LEN);

    fake_initialized = 1;
}