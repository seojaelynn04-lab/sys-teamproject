#include <math.h>
#include <string.h>
#include <stddef.h>
#include "entropy.h"
#include "analyzer.h " 
#include <time.h>
#include <stdio.h>
#include <unistd.h>

double calculate_entropy(const char *buffer, size_t size);

//행동(operation) 에 따라 가중치 부여
//가중치 고려해야 할 점-> red 팀한테 코드 받아보고 평균적인 임계치랑 가중치 점수 수정해야
#define WEIGTH_WRITE 1 //myfs_write 호출시 기본 점수 1
#define WEIGTH_MALICIOUS 3 // myfs_unlink 나 _rename 호출시 점수 3 (더 많은 가중치 부여)
#define WEIGHT_HIGH_ENTROPY 20 // 엔트로피 4.2 이상이면 20점 추가
#define ENTROPY_THRESHOLD 4.2 // 대략적으로 정한 엔트로피 임계치

//(새롭게 추가)저엔트로피 우회를 막기 위해 필수적
#define WEIGTH_LARGE_WRITE 80
#define LARGE_WRITE_THRESHOLD (10* 1024 * 1024) //같은 문자를 오버라이트 하면 저엔트로피로 우회가 가능하므로 10MB 이상 덮어쓰면 80점 부여해서 무조건 악성이라 판단하기 


//반복 행위에 대한  (빈도에 따라) 임계치
#define TIME_SECONDS 3 // 3초 단위 검사
#define WRITE_THRESHOLE_PER_1 100 //3초에 write 100회까지
#define UNLINK_THRESHOLE_PER_1 10 //3초에 unlink 10회까지
#define RENAME_THRESHOLE_PER_1 10 //3초에 rename 10회까지

//3초 내에 각 operation 이임계치 이상 반복될 때  추가 벌점
#define PENALTY_HIGh_WRITE 50 // 쓰기 100회 넘었을 때 50벌점 부여
#define PENALTY_HIGh_UNLINK 100 // 언링크 10회 넘었을 때 80벌점 부여
#define PENALTY_HIGh_RENAME 100 // 리네임 3초동안 10회 넘으면 80벌점 부여

#define FINAL_MALICE_THRESHOLD 200 // 총 누적 점수가 200이 넘으면 최종 악성 판단


static int write_count = 0;
static int unlink_count = 0;
static int rename_count = 0;
static int total_malice_score = 0;
static time_t start_time = 0;

static int get_score(const char* operation, const char* buf, size_t size) { //operation은 기본함수 구현하는 사람한테 받아와야함
	int score_to_add = 0;

	if (strcmp(operation, "WRITE") == 0) {
		score_to_add += WEIGHT_WRITE; //write 시 앞서 설정해놓은 가중치 1점 추가

		if (buf != NULL && size > 0) {
			double entropy = calculate_entropy(buf,size); //entropy.c 불러와서 entropy 에 저장하는 것을 의미
//만약 entropy가 4.2 넘으면 추가 벌점 부여 //entropy 는 문자가 반복되는 횟수를 의미하므로 write에서만 계산이 가능해 삭제나 이름변경은 buf == NULL 이기 때문
			if (entropy > ENTROPY_THRESHOLD) { //entropy 가 4.2 를 넘으면 추가 점수
				score_to_add += WEIGTH_HIGH_ENTROPY; //5점 추가 벌점
								     
			}
		}
//(추가한 내용) 동일 문자 입력으로 저엔트로피우회가 가능하므로  그냥 쓰기행위를 많이 하는 것 자체도 80점 부가해서 악성코드라 판
		if (size > LARGE_WRITE_THRESHOLD) {
			score_to_add += WEIGHT_LARGE_WRITE;
		}

	}
        // unlink 나 rename 시 가중치 3점 부여단
	else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {

		score_to_add += WEIGHT_MALICIOUS; //3점 추가
	}

	return score_to_add; //일단은 쓰기, rename, unlink 만 점수부여 
}


//총 점수 계산 및 악성인지 판단하기 과정
static int check_frequency_and_alert(){
	time_t current_time = time(NULL);
	int is_malicious = 0;

	if(start_time == 0) {
		start_time = current_time;
		return 0 ; 
	}
	// 3초가 안 지났으면 검사 X
	if (current_time - start_time < TIME_SECONDS){
		return 0;
	}
        // 임계치 넘으면 50점 벌점 추가
	if (write_count > WRITE_THRESHOLD_PER_1) {
		total_malice_score += PENALTY_HIGH_WRITE;
	}
        //임계치 넘으면 100점 벌점 추가
	if (unlink_count > UNLINK_THRESHOLD_PER_1){
		total_malice_score += PENALTY_HIGH_UNLILNK;
	}
        //임계치 넘으면 100점 벌점 추가
	if (rename_count > RENAME_THRESHOLD_PER_1){
                total_malice_score += PENALTY_HIGH_RENAME;
	}
       // 전체 총합 점수가 임계치 넘으면 악성으로 판
	if (total_malice_score > FINAL_MALICE_THRESHOLD) {
		printf("헉!!!!!!");
		printf("malice detected (PID:%d)\n", current_pid); //fuse 로부터 전달받아 저장해둔  공격자 pid
		printf("malice score : %d (threshold: %d)\n", total_malice_score, FINAL_MALICE_THRESHOLD);
		printf("각 행동 횟수 :(w : %d. U : %d, R:%d)\n", write_count, unlink_count, rename_count);

		is_malicious = 1; // 악성으로 판정
		}
	// 다시 다음 1초를 위해 초기화해줌
	total_malice_score = 0;
	write_count = 0;
	unlink_count = 0;
	rename_count = 0;
	start_time = current_time;

	return is_malicious;
}

int monitor_operation(const char* operation, const char* buf, size_t size){

	int content_score = get_score(operation, buf, size); //계산기로 단일 점수 계산
	total_malice_score += content_score; // 장부에 점수와 횟수 누적

	if (strcmp(operation, "WRITE") == 0) {
		write_count++;
	} else if (strcmp(operation, "UNLINK") == 0) {
		unlink_count++;
	} else if (strcmp(operation, "RENAME") == 0) {
		rename_count++;
	}

	return check_frequency_and_alert(); //monitor 가 1초마다 검사하고 결과 반환 (악성이면 1)
}
