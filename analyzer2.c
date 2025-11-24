#include "entropy.h"
#include "analyzer.h"
#include <string.h> // strcmp, memcmp
#include <stddef.h> // size_t, NULL
#include <stdio.h> 

// --- 1. 가중치 설정 (Weight Configuration) ---/

// --- 1. 내용 기반 (Content-based) ---
// [상향] 기본 쓰기 점수를 5배 높임.
// 효과: '메롱' 덮어쓰기 같은 미세한 파괴 행위도 30번(150/5) 만에 차단됨.
#define WEIGHT_WRITE 5           //쓰기 행위 시 
#define WEIGHT_HIGH_ENTROPY 20   // 20점 부여함
#define ENTROPY_THRESHOLD 4.3 //엔트로피가 4.3 보다 높으면 (교수님 자료에 암호화전 읽기/쓰기 상황의 엔트로피가 4.3 이하였던 것에 근거함))

// --- 2. 행위 기반 (Behavior-based) ---
// [상향] 삭제/변경 점수를 2배 높임.
// 효과: 파일을 8개만 삭제(unlink)하거나 암호화 후 이름 변경(rename)해도 즉시 차단됨.
#define WEIGHT_MALICIOUS 20      

// [유지]평소에 자주하는 정찰 행위인 파일을 읽거나(read), 정보를 보는 것(getattr)은 너무 높이면 'ls' 명령어도 막히므로 2점 유지
#define WEIGHT_MALICIOUS_LOW 2   

// --- 3. 맥락 기반 (Context-based) ---
// [유지] 한 방 차단 (임계치와 동일하게 설정)
#define WEIGHT_LARGE_WRITE 150   //150점 바로 부여
#define LARGE_WRITE_THRESHOLD (10 * 1024 * 1024) //10MB 넘게 쓰면

// --- 4. 변화량 기반 (Delta Entropy) ---
// [유지] 한 방 차단 (임계치와 동일하게 설정)
#define WEIGHT_DELTA_ENTROPY 150 //(3) 150점 바로 부여
#define ENTROPY_DELTA_THRESHOLD 3.8 //(1) 파일의 엔트로피가 3.8  이상 급변하거나 (교수님 자료에서는암호화시 2.8정도 변화하나, 테스트 결과 간단한 수정 등에도 너무 쉽게 차단해버림)
#define HIGH_ENTROPY_FLOOR 7.0 //(2) 최종 엔트로피가 7.0 이상이라면 ( 이 과정을 통해 빈 파일에 간단한 쓰기만 해도 악성으로 판단하는 걸 막을 수 있음)



 //다양한 파일 포맷의 헤더(Magic Number)를 검사하여 오탐 방지 (엔트로피가 높은 파일들을 모두 랜섬웨어로 판단하는 것을 막기 위함)
int is_valid_file_header(const char *buf, size_t size) {
    if (size < 4) return 0; // 데이터가 너무 짧으면 검사 불가

    // 1. 이미지 파일 (Image)
    // JPG (FF D8 FF)
    if (size >= 3 && memcmp(buf, "\xFF\xD8\xFF", 3) == 0) return 1;
    // PNG (89 50 4E 47)
    if (size >= 4 && memcmp(buf, "\x89\x50\x4E\x47", 4) == 0) return 1;
    // GIF (GIF8)
    if (size >= 4 && memcmp(buf, "GIF8", 4) == 0) return 1;
    // BMP (BM)
    if (size >= 2 && memcmp(buf, "BM", 2) == 0) return 1;
    // TIF/TIFF (II* or MM*)
    if (size >= 4 && (memcmp(buf, "II*\x00", 4) == 0 || memcmp(buf, "MM\x00*", 4) == 0)) return 1;

    // 2. 문서 및 압축 파일 (Docs & Archives)
    // ZIP, Office(docx, xlsx, pptx), APK,.jar 파일들이 전부 보호(이 파일들은 ZIP 포맷이라서 전부 PK로 시작)
    if (size >= 2 && memcmp(buf, "PK", 2) == 0) return 1;
    // PDF (%PDF)
    if (size >= 4 && memcmp(buf, "%PDF", 4) == 0) return 1;
    // HWP (한글 구버전 OLE 헤더: D0 CF 11 E0)
    if (size >= 8 && memcmp(buf, "\xD0\xCF\x11\xE0", 4) == 0) return 1;

    // 3. 미디어 파일 (Media)
    // MP4, MOV (ftyp 시그니처가 4번째 바이트부터 등장)
    if (size >= 12 && memcmp(buf + 4, "ftyp", 4) == 0) return 1;
    // AVI, WAV (RIFF)
    if (size >= 4 && memcmp(buf, "RIFF", 4) == 0) return 1;
    // MP3 (ID3 태그 또는 FF FB 헤더)
    if (size >= 3 && memcmp(buf, "ID3", 3) == 0) return 1;
    if (size >= 2 && (unsigned char)buf[0] == 0xFF && ((unsigned char)buf[1] & 0xE0) == 0xE0) return 1;

    // 4. 실행 파일 (Executable)
    // ELF (리눅스 실행 파일: 7F 45 4C 46)
    if (size >= 4 && memcmp(buf, "\x7F\x45\x4C\x46", 4) == 0) return 1;

    return 0; // 알려진 헤더가 아님 (암호화된 데이터일 가능성 높음)
}

int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null, size_t size) {
    int score_to_add = 0;

    // --- [1] WRITE (쓰기) 연산 분석 ---
    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE; // 기본 5점 부여

        if (new_buf != NULL && size > 0) {
            
            double new_entropy = calculate_entropy(new_buf, size);
            double old_entropy = 0.0;

            if (old_buf_or_null != NULL) {
                old_entropy = calculate_entropy(old_buf_or_null, size);
            }

            double delta = new_entropy - old_entropy;
            
            // [핵심 방어 로직]
            // 1. 엔트로피가 급증했거나(새 파일), 결과물이 매우 높은가(7.0 이상)?
            if (delta > ENTROPY_DELTA_THRESHOLD || new_entropy > HIGH_ENTROPY_FLOOR) {
                
                // 2. (오탐 방지) 정상적인 파일 헤더가 있는가?
                if (is_valid_file_header(new_buf, size)) {
                    // [PASS] 엔트로피는 높지만 정상 파일(이미지/압축)임.
                } 
                else {
                    // [BLOCK] 엔트로피가 높은데 헤더가 없다 -> 암호화 데이터!
                    score_to_add += WEIGHT_DELTA_ENTROPY; // 150점 (즉시 차단)
                }
            }
        }
        
        // [대용량 쓰기 방어] (엔트로피와 무관하게 검사)
        if (size > LARGE_WRITE_THRESHOLD) {
            score_to_add += WEIGHT_LARGE_WRITE; // 150점 (즉시 차단)
        }

    } 
    // --- [2] 고위험 행위 (삭제/변경) ---
    else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {
        score_to_add += WEIGHT_MALICIOUS; // 20점
    } 
    // --- [3] 저위험 정찰 행위 (읽기/탐색) ---
    else if (strcmp(operation, "READ") == 0 ||
             strcmp(operation, "OPEN") == 0 ||
             strcmp(operation, "GETATTR") == 0 ||
             strcmp(operation, "READDIR") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW; // 2점
    
    // --- [4] 기타 조작 행위 ---
    } else if (strcmp(operation, "CREATE") == 0 ||
               strcmp(operation, "MKDIR") == 0 ||
               strcmp(operation, "RMDIR") == 0 ||
               strcmp(operation, "UTIMENS") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW; // 2점
    }

    return score_to_add;
}
