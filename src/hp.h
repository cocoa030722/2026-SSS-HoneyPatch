/* hp.h - 허니패치 라이브러리 */

/*
논문의 API를 프로세스 수준으로 구현
    hp_fork() : 공격 탐지 시 세션을 decoy로 복제한다 (CRIU 대신 fork 사용)
    hp_skip() : decoy에서는 패치의 거부 동작을 건너뛴다
*/

#ifndef HP_H
#define HP_H

/* hp_fork()의 리턴 값들 */
enum hp_result {
    HP_TARGET = 0,      // fork 후 공격자 연결을 close한 target
    HP_DECOY  = 1,      // fork로 생성된 decoy (이미 decoy면 fork 없이 이 값)
    HP_FAIL   = 2       // 포크가 실패
};

void hp_init(int listen_fd, int log_fd);
int  hp_fork(int conn_fd, int attacker_slot, int L, int P);
int  hp_in_decoy(void);
void hp_redact(int keep_slot);
void hp_log(const char *fmt, ...);
void random_hex(char *dst, int len);
void hp_init_fake_tokens(void);

/* hp_skip, 매크로로 정의 */
// 인자로 문장(stmt)을 넣으면 decoy가 아닐 때만 그 문장을 실행한다
#define hp_skip(stmt) do { if (!hp_in_decoy()) { stmt; } } while (0)

#endif
