#define FUSE_USE_VERSION 35
#define MAX_TRACKED_PIDS 100
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>     // realpath 함수 사용을 위해 추가
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include "analyzer.h" // (재린 추가함) 스코어 계산하는 함수
#define KILL_THRESHOLD 80    // Malice Score 강제 종료 임계값 ((임시))

static int base_fd = -1;

// 블랙리스트 생성(해당 이름의 파일을 차단)
static const char *blacklist[] = {
    "/ransomware.exe",
    NULL // 목록 끝을 표시
};

// 쓰기 전용 화이트리스트 생성(일종의 낚시 파일을 제외한 리스트)
static const char *writable_whitelist[] = {
    "/text.txt",  //일반적인 파일 지정
    NULL 
};

// 해당 파일이 블랙리스트에 포함되는지 확인
static int is_blacklisted(const char *path) {
    for (int i = 0; blacklist[i] != NULL; i++) {
        if (strcmp(path, blacklist[i]) == 0) {
            return 1; // 차단
        }
    }
    return 0; // 허용
}

// 해당 파일이 화이트리스트에 존재하는 파일인지 점검
static int is_writable_whitelisted(const char *path) {
    for (int i = 0; writable_whitelist[i] != NULL; i++) {
        if (strcmp(path, writable_whitelist[i]) == 0) {
            return 1; // 쓰기 허용
        }
    }
    return 0; // 쓰기 차단
}

// PID별 Malice Score, 행동 정보 저장할 구조체
typedef struct {
    pid_t pid;             
    int malice_score;      
    time_t last_write_time; // 마지막 쓰기 연산 시간 
    char proc_name[32];  //  프로세스 이름 저장
} ProcessScore;

// 전역 Score 테이블
ProcessScore g_score_table[MAX_TRACKED_PIDS];
int g_process_count = 0; // 현재 추적 중인 프로세스 개수

// ProcessScore 엔트리를 찾거나 새로 생성해 포인터 반환
ProcessScore* find_or_create_score_entry(pid_t pid) {
    // 기존 엔트리 검색
    for (int i = 0; i < g_process_count; i++) {
        if (g_score_table[i].pid == pid) {
            // PID가 이미 존재하면 해당 엔트리 반환
            return &g_score_table[i];
	}
    }
    
    // 새 엔트리 생성
    if (g_process_count < MAX_TRACKED_PIDS) {
        ProcessScore *new_entry = &g_score_table[g_process_count];
        // 새로운 엔트리 초기화
        new_entry->pid = pid;
        new_entry->malice_score = 0;
        new_entry->last_write_time = time(NULL);
        g_process_count++; // 추적 중인 프로세스 수 증가
        
        return new_entry;
    }
    
    // 배열이 가득 찼을 때 
    fprintf(stderr, "오류: 최대 PID 추적 개수 초과!\n");
    return NULL;
}

// 특정 PID의 Malice Score 업데이트, 마지막 쓰기 시간 갱신
void update_malice_score(pid_t pid, int added_score) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    
    if (entry) {
        entry->malice_score += added_score;
        entry->last_write_time = time(NULL); 
    }
}

// 특정 PID의 Malice Score 반환
int get_malice_score(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        return entry->malice_score;
    }
    return 0; // 엔트리 못 찾으면 0점 반환
}

// 프로세스 종료 시 Score 0으로 초기화
void reset_malice_score(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        entry->malice_score = 0;
    }
}

static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// getattr 함수 구현
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    //(12일과제)
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("GETATTR",NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }

    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;
    
    // 블랙리스트 기반 차단
    if ((stbuf->st_mode & S_IFREG) && (stbuf->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        // 블랙리스트에 존재 여부 검사
        if (is_blacklisted(path)) {
            // 존재하면 실행에 대한 권한 강제 제거
            stbuf->st_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);
        }
    }

    return 0;
}

// readdir 함수 구현
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
    			enum fuse_readdir_flags flags) {

    //(12일 과제)
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("READDIR",NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }

    DIR *dp;
    struct dirent *de;
    int fd;

    (void) offset;
    (void) fi;
    (void) flags;

    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1)
        return -errno;

    dp = fdopendir(fd);
    if (dp == NULL) {
        close(fd);
        return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

// open 함수 구현
static int myfs_open(const char *path, struct fuse_file_info *fi) {

    //(12일과제)
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("OPEN",NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }

    // 쓰기 검사 구현
    if ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
        // 화이트리스트에 있는지 확인
        if (!is_writable_whitelisted(path)) {
            return -EACCES; //없다면 접근 거부
        }
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// create 함수 구현
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {

    //(12일과제)
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("CREATE", NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }

    // 쓰기 검사 구현
  //  if ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
        // 화이트리스트에 있는지 확인
        if (!is_writable_whitelisted(path)) {
            return -EACCES; //없다면 접근 거부
        }
   //  }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags| O_CREAT, mode); //O_CREAT, mode 부분이 이해 안됨
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}


    // 쓰기(생성) 차단
    if (!is_writable_whitelisted(path)) {
        return -EACCES; 
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags | O_CREAT, mode_t);
    if (res == -1) {
        return -errno;

    fi->fh = res;
    return 0;
}

// read 함수 구현
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    int res;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

// write 함수 구현
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    // 화이트리스트 체크
    if (!is_writable_whitelisted(path)) {
        return -EACCES; // 화이트리스트에 없으면 접근 거부
    }
    
    // PID 획득
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
   
   //(12일과제)
   char *old_buf = NULL; //기존데이터를 담을 버퍼
   int added_score = 0;

  if (size > 0) {
	 old_buf = malloc(size); // 기존 데이터를 읽을 메모리 할당
	 if (old_buf == NULL) {
		fprintf(stderr, "메모리 할당 실패\n");
	       return -ENOMEM;
	 }
         
	 // 디스크에서 현재 쓰려는 위치(offset) 의 기존데이터를 읽어옴
	 ssize_t read_bytes = pread(fi->fh, old_buf, size, offset);

	 if(read_bytes >= 0){
		 added_score = get_score("WRITE", buf, old_buf, size);
	 }
	 else{
		 added_score = get_score("WRITE", buf, NULL, size);
	 }

	 free(old_buf); // 메모리 해제 필수
	
  }
  else {  //size 가 0인 경우
	  added_score = get_score("WRITE", buf, NULL, size);
  }

    update_malice_score(current_pid, added_score);
    
    
    // 임계값 확인 후 강제 종료 조치
    if (get_malice_score(current_pid) >= KILL_THRESHOLD) {
        fprintf(stderr, "Kill ! 'write' 임계값 초과! PID %d 강제 종료\n", current_pid);
        
        // 강제 종료 실행
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }

        // 쓰기 연산 차단 및 에러 반환
        return -EIO; 
    }

    // 정상 연산 
    int res;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }
    return res;
}

// release 함수 구현
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    reset_malice_score(current_pid); //파일 닫으면 해당 p의 score초기화
    return 0;
}

// unlink 함수 구현 (파일 삭제)
static int myfs_unlink(const char *path) {
    // 화이트리스트 체크
    if (!is_writable_whitelisted(path)) {
        return -EACCES; // 화이트리스트에 없으면 삭제 거부
    }
    
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;
    
    int added_score = get_score("UNLINK", NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기
   
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
	    fprintf(stderr, "Kill ! 'unlink' 임계값 초과! PID %d 강제종료\n", current_pid);
	    if(kill(current_pid,SIGKILL) == -1){
		    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
	    }
	    return -EIO;
    }
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
        return -errno;

    return 0;
}

// mkdir 함수 구현 (디렉터리 생성)
static int myfs_mkdir(const char *path, mode_t mode) {

    //(12일과제)
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("MKDIR", NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }

    // 쓰기 검사 구현
    if ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
        // 화이트리스트에 있는지 확인
        if (!is_writable_whitelisted(path)) {
            return -EACCES; //없다면 접근 거부
        }
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}


    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

// rmdir 함수 구현 (디렉터리 삭제)
static int myfs_rmdir(const char *path) {

    //(12일과제)
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("RMDIR", NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }

    // 쓰기 검사 구현
    if ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
        // 화이트리스트에 있는지 확인
        if (!is_writable_whitelisted(path)) {
            return -EACCES; //없다면 접근 거부
        }
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}


    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
        return -errno;

    return 0;
}

// rename 함수 구현 (파일/디렉터리 이름 변경)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    // to 경로에 대한 화이트리스트 체크 (화이트리스트 파일로만 이름 변경 허용)
    if (!is_writable_whitelisted(to)) {
        return -EACCES; // 목적지 경로가 화이트리스트에 없으면 거부
    }
    
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("RENAME", NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 'rename' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    if (flags)
        return -EINVAL;

    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1)
        return -errno;

    return 0;
}

// utimens 함수 구현
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {

    //(12일과제)
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    int added_score = get_score("UTIMENS", NULL, NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            }
            return -EIO;
    }

    // 쓰기 검사 구현
    if ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
        // 화이트리스트에 있는지 확인
        if (!is_writable_whitelisted(path)) {
            return -EACCES; //없다면 접근 거부
        }
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}


    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (fi != NULL && fi->fh != 0) {
        // 파일 핸들이 있는 경우
        res = futimens(fi->fh, tv);
    } else {
        // 파일 핸들이 없는 경우
        res = utimensat(base_fd, relpath, tv, 0);
    }
    if (res == -1)
        return -errno;

    return 0;
}

// 파일시스템 연산자 구조체
static const struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .create     = myfs_create,
    .read       = myfs_read,
    .write      = myfs_write,
    .release    = myfs_release,
    .unlink     = myfs_unlink,
    .mkdir      = myfs_mkdir,
    .rmdir      = myfs_rmdir,
    .rename     = myfs_rename,
    .utimens    = myfs_utimens,  
};


int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    // 마운트 포인트 경로 저장
    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (mountpoint == NULL) {
        perror("realpath");
        return -1;
    }

    // 지정된 경로 획득 (백엔드 경로)
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
    	fprintf(stderr, "Error: HOME environment variable not set.\n");
        return -1;
    }
    
    char backend_path[PATH_MAX];
    // '/home/계정명/workspace/target' 경로 구성
    snprintf(backend_path, PATH_MAX, "%s/workspace/target", home_dir);

    // 백엔드 디렉터리 열기 (base_fd 획득)
    fprintf(stderr, "INFO: Protecting backend path: %s\n", backend_path);
    
    base_fd = open(backend_path, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
	perror("Error opening backend directory");
	return -1;
    }

    // FUSE 파일시스템 실행
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    close(base_fd);
    return ret;
}
