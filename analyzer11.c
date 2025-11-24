#include "entropy.h"
#include "analyzer.h"
#include <string.h> // strcmp 함수
#include <stddef.h> // size_t, NULL
#include <stdio.h> 

//content-based (내용기반) = 모든 쓰기 요청마다 가중치와  엔트로피를 계산
//(가중치 고려해야 할 점 red 팀한테 코드 받아보고 평균적인 임계치랑 가중치 점수 수정해야함)
#define WEIGHT_WRITE 1 //myfs_write 호출시 기본 점수 1
#define WEIGHT_HIGH_ENTROPY 20 // 엔트로피 4.2 이상이면 20점 추가
#define ENTROPY_THRESHOLD 4.2 // 대략적으로 정한 엔트로피 임계치냄

// behavior-based(행위기반) = 삭제나 이름변경 시 가중치 계산 -> 이 때 데이터의 변화는 없으므로 엔트로피는 계산하지 않는다
#define WEIGHT_MALICIOUS 3 // 삭제나 이름 변경 시 3점 가중치 부여(고위험)
#define WEIGHT_MALICIOUS_LOW 1 // (12일 과제) 나머지 행위들에 대해 1점 가중치 부여(저위험)	
			       //
//(새롭게 추가)저엔트로피 우회를 막기 위해 필수적
#define WEIGHT_LARGE_WRITE 80
#define LARGE_WRITE_THRESHOLD (10* 1024 * 1024) //같은 문자를 오버라이트 하면 저엔트로피로 우회가 가능하므로 10MB 이상 덮어쓰면 80점 부여해서 무조건 악성이라 판단하기

//(12일 과제) 엔트로피 변화량에 대한 가중치 부여
#define WEIGHT_DELTA_ENTROPY 80 // 엔트로피가 3.0 이상 변화하면 80점으로 무조건 악성 판단
#define ENTROPY_DELTA_THRESHOLD 3.0 // 엔트로피가 3.0 이상 변화함을 나타냄
#define HIGH_ENTROPY_FLOOR 6.0 // 일반 텍스트는 4.5 를 넘기 어려우므로 아무것도 안 적혀있는 파일에 대해 쓰기를 해도 악성이라고 판단하지 않음
			       //
//(12일과제 - 변경 사항 * new_buf 는 파일에 새로 쓰려는 데이터, old_buf 는 기존에 있던 원본 데이터를 의미)
int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null, size_t size) {
        int score_to_add = 0;

        if (strcmp(operation, "WRITE") == 0) {
                score_to_add += WEIGHT_WRITE; //write 시 앞서 설정해놓은 가중치 1점 추가

		if(new_buf != NULL && size > 0){
			double new_entropy = calculate_entropy(new_buf, size);
			double old_entropy = 0.0; // 처음 파일이 생성될 때는 기본 엔트로피 0
			
			if (old_buf_or_null != NULL && size > 0) {
                        old_entropy = calculate_entropy(old_buf_or_null,size);
			}	// 기존 데이터가 있다면 기존 엔트로피 계산

			double delta = new_entropy - old_entropy;

                        if (delta > ENTROPY_DELTA_THRESHOLD && new_entropy > HIGH_ENTROPY_FLOOR) { // 엔트로피 변화량이 3.0 이상이고 새 엔트로피가 6.0 을 넘는 경우
                                score_to_add += WEIGHT_DELTA_ENTROPY; //80점 부가해서 무조건 악성으로 판단

                        }
                 }
// 동일 문자 입력으로 저엔트로피우회가 가능하므로 쓰기 크기가 큰 상황 자체도 80점 부가해서 악성코드라 판단-> 단 한 번의 쓰기가 10MB를  넘어가는지
                if (size > LARGE_WRITE_THRESHOLD) {
                        score_to_add += WEIGHT_LARGE_WRITE; //저엔트로피 우회시 80점 부가해서 무조건 악성으로 판단
                }

        }
        // unlink 나 rename 시 가중치 3점 부여
        else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {

                score_to_add += WEIGHT_MALICIOUS; //3점 추가
        }
	//(12일 과제) 나머지 모든 행위에 대한 가중치 1점 부여 -> 이 행위들에 대해 가중치를 높여버리면 너무 쉽게 점수가 누적돼서 함부로 건드리기 애매함..
	else if (strcmp(operation, "READ") == 0 || strcmp(operation, "OPEN")==0 || strcmp(operation, "GETATTR") == 0 ||strcmp(operation, "READDIR") == 0){
		score_to_add += WEIGHT_MALICIOUS_LOW;
	}

	else if (strcmp(operation, "CREATE") == 0 || strcmp(operation, "MKDIR") ==0 || strcmp(operation, "RMDIR") == 0 ||strcmp(operation, "UTIMENS") == 0){
                score_to_add += WEIGHT_MALICIOUS_LOW;
	}

        return score_to_add; // 모든 행위들에 대한 누적된 점수 반환
}
