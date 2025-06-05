#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>  
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <stddef.h>
#include <getopt.h>
#include "wutamp.h"

const char  *path;
int         max_score = 10;
bool        is_tty    = false;
bool        is_pause  = false;


int main(int argc, char *argv[]) 
{
    int opt;
    int option_index = 0;
    
    static struct option long_options[] = 
    {
        {"path",  required_argument, 0, 'p'},
        {"score", optional_argument, 0, 's'},
        {"pause", no_argument, 0, 'x'},
        {"help",  no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:s:h:x", long_options, &option_index)) != -1) 
    {
        switch (opt) 
        {
        case 'p':
            path = optarg;
            break;
        case 's':
            max_score = atoi(optarg);
            break;
        case 'x':
            is_pause = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return -1;
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (isatty(fileno(stdout)))
        is_tty = true;

    if (!path)
    {
        print_usage(argv[0]);
        return -1;
    }

    scan_wtmp((char *)path, max_score);
    return 0;
}

void print_usage(const char *program_name) 
{
    printf("Usage: %s --path <path> [--score <max_score>]\n", program_name);
    printf("\nOptions:\n");
    printf("  -p --path=<path>        Path to wtmp or utmp file (required).\n");
    printf("  -s --score=<max_score>  Specify maximum corruption score before entry is omitted from output.\n");
    printf("  -x --pause              Pause output on corrupted entry. Press [enter] to resume output.\n");
}

int scan_wtmp(char *filename, int max_score)
{
    size_t         file_size = 0;
    struct futmpx  *entry;
    int            score;
    int            username_length;

    char *buffer = file_mmap(filename, &file_size);
    if (buffer == NULL)
        return -1;
  
    for ( char *p = buffer; p < buffer + file_size; p++ )
    {
        entry = (struct futmpx *)p;

        if (solaris_valid_username((u_char *)p, &username_length) == true)
        {
            score = solaris_score_futmpx(entry, username_length);
            solaris_print_futmpx(entry, score, max_score);
            if (is_pause && score >= 3 && score <= max_score)
                getchar();
            p += sizeof(struct futmpx) - 1;
        }
    }
    
    file_unmap(buffer, file_size);
    return 0;
}

void solaris_print_futmpx(struct futmpx *fentry, int score, int max_score) 
{
    char           time_str[64];
    time_t         raw_time;
    struct tm      *timeinfo;
    char           *fmt;
    struct futmpx  entry;

    entry                       = *fentry;
    entry.ut_type               = ntohs(entry.ut_type);
    entry.ut_tv.tv_sec          = ntohl(entry.ut_tv.tv_sec);
    entry.ut_tv.tv_usec         = ntohl(entry.ut_tv.tv_usec);
    entry.ut_session            = ntohl(entry.ut_session);
    entry.ut_session            = ntohl(entry.ut_session);
    entry.ut_pid                = ntohl(entry.ut_pid);
    entry.ut_syslen             = ntohs(entry.ut_syslen);
    entry.ut_exit.e_termination = ntohs(entry.ut_exit.e_termination);
    entry.ut_exit.e_exit        = ntohs(entry.ut_exit.e_exit);

    raw_time = entry.ut_tv.tv_sec;
    timeinfo = localtime(&raw_time);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

    if (score >= 8)
        fmt = RED_TEXT("%32s\t%8s\t%12s\t%48s\t%10u\t%d\t%d\t%d\t%d\n");
    else if (score >= 5)
        fmt = PURPLE_TEXT("%32s\t%8s\t%12s\t%48s\t%10u\t%d\t%d\t%d\t%d\n");
    else if (score >= 3)
        fmt = CYAN_TEXT("%32s\t%8s\t%12s\t%48s\t%10u\t%d\t%d\t%d\t%d\n");
    else
        fmt = "%32s\t%8s\t%12s\t%48s\t%10u\t%d\t%d\t%d\t%d\n";

    if (score <= max_score)
        printf( 
                fmt,
                time_str,
                entry.ut_user,
                entry.ut_line,
                entry.ut_host,
                entry.ut_pid,
                entry.ut_type,
                entry.ut_exit.e_exit,
                entry.ut_exit.e_termination,
                entry.ut_session
            );
}

int  solaris_score_futmpx(struct futmpx *fentry, int user_length) 
{
    int16_t       e_term;
    int16_t       e_exit;
    char          blank[FUTMPX_HOSTLEN] = {0};
    struct futmpx entry;
    int           score = 0;

    entry = *fentry;
    entry.ut_type       = ntohs(entry.ut_type);
    entry.ut_tv.tv_sec  = ntohl(entry.ut_tv.tv_sec);
    entry.ut_tv.tv_usec = ntohl(entry.ut_tv.tv_usec);
    entry.ut_session    = ntohl(entry.ut_session);
    entry.ut_pid        = ntohl(entry.ut_pid);
    entry.ut_syslen     = ntohs(entry.ut_syslen);
    e_term              = ntohs(entry.ut_exit.e_termination);
    e_exit              = ntohs(entry.ut_exit.e_exit);

    // Exceptions
    if  ( entry.ut_type == EMPTY && 
          entry.ut_pid     == 0  &&
          e_term           == 0  && 
          e_term           == 0  && 
          entry.ut_session == 0  &&
          ( strcmp(entry.ut_user, "console")  == 0 ||
            strcmp(entry.ut_user, "shutdown") == 0 ||
            strcmp(entry.ut_user, "co10")     == 0 
          )
        )
    {
        return score;
    }

    // Time
    if (!timestamp_valid(entry.ut_tv.tv_sec))
        SCORE_INCREASE(score, 2);

    // DeviceName
    if (entry.ut_line[0] == 0x0)
        SCORE_INCREASE(score, 1);
    else if ( strstr(entry.ut_line, "sshd")     == NULL && 
              strstr(entry.ut_line, "pts/")     == NULL &&
              strcmp(entry.ut_line, "console")  != 0    && 
              strstr(entry.ut_line, "ftp")      == NULL )
        SCORE_INCREASE(score, 3);

    // Username
    if ( entry.ut_type != BOOT_TIME && user_length <= 1 )
        SCORE_INCREASE(score, 10);
    else if (user_length <= 2)
        SCORE_INCREASE(score, 7);

    // Host
    if (entry.ut_syslen == 0 && 
        memcmp(entry.ut_host, blank, FUTMPX_HOSTLEN) != 0)
        SCORE_INCREASE(score, 3);
    else if ( !valid_hostname(entry.ut_host) && 
              !valid_ip(entry.ut_host) && 
              strlen(entry.ut_host) != (unsigned long)entry.ut_syslen )
        SCORE_INCREASE(score, 3);

    // Type
    if  ( entry.ut_type == EMPTY ) 
        SCORE_INCREASE(score, 1);
    else if ( !(entry.ut_type > EMPTY && 
                entry.ut_type <= ACCOUNTING) )
        SCORE_INCREASE(score, 2);
  
    // PID
    if (entry.ut_pid > 30000)
        SCORE_INCREASE(score, 1);
    else if (entry.ut_pid < 100)
        SCORE_INCREASE(score, 1);

    // e_exit & e_term
    if (!(e_term == 0 && (e_exit == 0 || e_exit == 256)))
        SCORE_INCREASE(score, 1);
    else if ((uint16_t)e_term  > 256 && (uint16_t)e_exit > 256)
        SCORE_INCREASE(score, 1);

    // Session 
    if (entry.ut_session != 0)
        SCORE_INCREASE(score, 1);

    return score;
}

bool solaris_valid_username(u_char *p, int *s_len)
{
    int max_login_name;
    int length = 0;    
    u_char *username;
    int16_t type;
    int offset;

    username = p;

    //if ( ((uint32_t)p) % 4 != 0 )
    //    return false;
   
    if (username == NULL)
        return false;

    type = *(int16_t *)(p + offsetof(struct futmpx, ut_type));
    type = ntohs(type);
   
    // Assuming type could have been corrupted with null value
    if (type >= EMPTY && type <= ACCOUNTING)
    {

        if (username[0] == 0x0)
            return false;

        max_login_name = 8;
        if (!islower(username[0]))
            return false;

        length = strlen((char *)username);
        if (length > max_login_name)
            return false;

        *s_len = length;

        for (int i = 1; username[i] != 0x0 && i < max_login_name - 1; i++) 
        {
            if ( !islower(username[i]) && 
                !isdigit(username[i]) &&
                username[i] != '.'   && 
                username[i] != '_' )
                return false;
        }

        int index = length;
        for (int i = index; i < FUTMPX_USERLEN - 1; i++)
        {
            if (username[i] != 0x0)
                return false;
        }

        offset = offsetof(struct futmpx, pad);
        char *ptr = (char *)username + offset;
        if (memcmp(ptr, "\x00\x00\x00\x00\x00", 5) != 0)
            return false;

        return true; 
    }
    
    return false;
}

bool valid_hostname(const char *hostname) 
{
    char c;
    bool content = false;
    
    if ( hostname == NULL || hostname[0] == 0x0 ||
          strlen(hostname) > 253 ) 
        return false;
  
    if ( hostname[0] == '-' || 
         hostname[strlen(hostname) - 1] == '-' ) 
        return false;
  
    for (int i = 0; hostname[i] != '\0'; i++) 
    {
        c = hostname[i];
        if (isalnum(c)) 
        {
            content = true;
            continue;
        }
        if (c == '-')
        {
            if (!content) 
                return false;
            continue;
        }
        if (c == '.') 
        {
            if (!content) 
                return false;
        content = false;
        continue;
      }

      return false;
    }

    return content;
}

bool valid_ip(const char *ip_str) 
{
    int  dots = 0;
    int  numbers;
    char *token;
    char ip[strlen(ip_str) + 1];

    strcpy(ip, ip_str);

    token = strtok(ip, ".");
    while ( token != NULL ) 
    {
        numbers = atoi(token);
        if (!isdigit(token[0]) || numbers < 0 || numbers > 255) 
            return false;
        token = strtok(NULL, ".");
        dots++;
    }
    if (dots != 4)
        return false;
    return true;
}

char * file_mmap(const char *filename, size_t *out_size) 
{
    int fd;
    struct stat st;
    size_t file_size;
    char *buffer = NULL;

    fd = open(filename, O_RDONLY);
    if (fd < 0) 
    {
        fprintf(stderr, "[-] Error: opening file %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    if (fstat(fd, &st) < 0) 
    {
        fprintf(stderr, "[-] Error: getting file stats for %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    file_size = st.st_size;
    *out_size = file_size;

    if (file_size == 0) 
    {
        fprintf(stderr, "[-] Error: File %s is empty\n", filename);
        return NULL;
    }

    buffer = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buffer == MAP_FAILED) 
    {
        fprintf(stderr, "[-] Error: mapping file %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    close(fd);
    return buffer;
}

void file_unmap(char *buffer, size_t size) 
{
    if (munmap(buffer, size) < 0)
        fprintf(stderr, "[-] Error: unmapping memory: %s\n", strerror(errno));
}

bool timestamp_valid(time_t timestamp) 
{
    time_t     current_time;
    struct tm  *time_info;
    struct tm  max_time_info;
    struct tm  today_info;
    time_t     max_time;
    time_t     today;

    current_time = time(NULL);
    if (current_time == (time_t)-1) 
    {
        fprintf(stderr, "[-] Error: Failed to get current time: %s\n", strerror(errno));
        return false;
    }

    time_info = localtime(&current_time);
    if (time_info == NULL) {
        fprintf(stderr, "[-] Error: Failed to convert current time: %s\n", strerror(errno));
        return false;
    }

    max_time_info = *time_info;
    max_time_info.tm_year -= 10;
    max_time_info.tm_hour  =  0;
    max_time_info.tm_min   =  0;
    max_time_info.tm_sec   =  0;
    max_time_info.tm_isdst = -1; 

    max_time = mktime(&max_time_info);
    if (max_time == (time_t)-1) 
    {
        fprintf(stderr, "[-] Error: Failed to calculate timestamp for 10 years ago: %s\n", strerror(errno));
        return false;
    }
   
    today_info = *time_info; 
    today_info.tm_hour  = 23;
    today_info.tm_min   = 59;
    today_info.tm_sec   = 59; 
    today_info.tm_isdst = -1; 
    today = mktime(&today_info);
     if (today == (time_t)-1) 
     {
        fprintf(stderr, "[-] Error: Failed to calculate timestamp for end of today: %s\n", strerror(errno));
        return false;
    }

    bool is_ancient = (timestamp >= max_time);
    bool is_time_traveller = (timestamp <= today);
    return is_ancient && is_time_traveller;
}
