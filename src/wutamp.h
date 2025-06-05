
#include <stdint.h>

#define GREEN_TEXT(text)  (is_tty ? "\033[32m" text "\033[0m" : text)
#define RED_TEXT(text)    (is_tty ? "\033[31m" text "\033[0m" : text)
#define CYAN_TEXT(text)   (is_tty ? "\033[36m" text "\033[0m" : text)
#define PURPLE_TEXT(text) (is_tty ? "\033[35m" text "\033[0m" : text)

#define SCORE_DECREASE(score, factor) \
    do { if ((factor) <= (score)) { (score) -= (factor); } } while (0)
#define SCORE_INCREASE(score, factor) \
    do { if ((factor) > 0) { (score) += (factor); } } while (0)

#define FUTMPX_USERLEN 32
#define FUTMPX_LINELEN 32
#define FUTMPX_HOSTLEN 257

#define EMPTY         0
#define RUN_LVL       1
#define BOOT_TIME     2
#define OLD_TIME      3
#define NEW_TIME      4
#define INIT_PROCESS  5
#define LOGIN_PROCESS 6
#define USER_PROCESS  7
#define DEAD_PROCESS  8
#define ACCOUNTING    9


struct futmpx 
{
    char ut_user[FUTMPX_USERLEN];      /* user login name */
    char ut_id[4];                     /* inittab id */
    char ut_line[FUTMPX_LINELEN];      /* device name (console, lnxx) */
    int32_t ut_pid;                    /* process id */
    int16_t ut_type;                   /* type of entry */
    struct 
    {
        int16_t e_termination;         /* process termination status */
        int16_t e_exit;                /* process exit status */
    } ut_exit;                         /* exit status of a process */
    struct timeval32 
    {                
        int32_t tv_sec;                /* seconds since epoch */        
        int32_t tv_usec;               /* microseconds */            
    } ut_tv;                           /* time entry was made */
    int32_t ut_session;                /* session ID, user for windowing */
    int32_t pad[5];                    /* reserved for future use */
    int16_t ut_syslen;                 /* significant length of ut_host */
    char ut_host[FUTMPX_HOSTLEN];      /* remote host name */
};


bool solaris_valid_username(unsigned char *username, int *s_len);
char * file_mmap(const char *filename, size_t *out_size);
void file_unmap(char *buffer, size_t size);
int  solaris_score_futmpx(struct futmpx *fentry, int user_length);
void solaris_print_futmpx(struct futmpx *fentry, int score, int min_score);
bool valid_hostname(const char *hostname);
bool valid_ip(const char *ip_str);
bool timestamp_valid(time_t timestamp_sec);
int scan_wtmp(char *filename, int min_score);
void print_usage(const char *program_name);