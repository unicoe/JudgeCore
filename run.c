#include <sys/resource.h>
#include <mysql/mysql.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define FLAG_WAIT 0
#define FLAG_CP 1
#define FLAG_CE 2
#define FLAG_AC 3
#define FLAG_PE 4
#define FLAG_WA 5
#define FLAG_RE 6
#define FLAG_TLE 7
#define FLAG_OLE 8
#define FLAG_MLE 9

#define langC 1
#define langCPP 2
#define STD_MB 1048576 //1024KB
#define STD_F_LIM (STD_MB << 5)
#define BUF_SIZE 512
int problem_id;
char pathBuf[100];
char query[200];
struct rusage usage;
MYSQL db;


int get_proc_status(int pid, const char * mark)
{
    FILE * pf;
    char fn[BUF_SIZE], buf[BUF_SIZE];
    int ret = 0;
    sprintf(fn, "/proc/%d/status", pid);
    pf = fopen(fn, "re");
    int m = strlen(mark);
    while(pf && fgets(buf, BUF_SIZE - 1, pf))
    {
        buf[strlen(buf) - 1] = 0;
        if(strncmp(buf, mark, m) == 0)
            sscanf(buf + m + 1, "%d", &ret);
    }
    if(pf)
        fclose(pf);
    return ret;
}

int compile(int lang)
{
    pid_t pid = fork();
    if(pid == 0)
    {
        freopen("ce.txt", "w", stderr);
        const char * CP_C[] = { "gcc", "Main.c", "-o", "Main", "-std=c99", "-Wall", NULL};
        const char * CP_P[] = { "g++", "Main.cc" "-o", "Main", NULL};
        if(lang == langC)
            execvp(CP_C[0], (char * const *) CP_C);
        else if(lang == langCPP)
            execvp(CP_P[0], (char * const *) CP_P);
    }
    else
    {
        int status = 0;
        waitpid(pid, &status, 0);
        return status;
    }
}

int max(int a, int b)
{
    return a > b ? a : b;
}

int run_solution(int time_limit, int memory_limit, int problem_id, int *memoryUsed)
{
    pid_t pid = fork();
    if(pid == 0)
    {
        struct rlimit rlim;
        //Time
        rlim.rlim_cur = time_limit;
        rlim.rlim_max = time_limit + 1;
        setrlimit(RLIMIT_CPU, &rlim);
        alarm(0);
        alarm(time_limit * 10);

        //Stack Size
        rlim.rlim_cur = STD_MB << 6; //6MB
        rlim.rlim_max = STD_MB << 6; //6MB
        setrlimit(RLIMIT_STACK, &rlim);

        //Memory Size KB
        rlim.rlim_cur = STD_MB * memory_limit / 2 * 3;
        rlim.rlim_max = STD_MB * memory_limit * 2;
        setrlimit(RLIMIT_AS, &rlim);

        //File Size
        rlim.rlim_cur = STD_F_LIM;
        rlim.rlim_max = STD_F_LIM + STD_MB;
        setrlimit(RLIMIT_FSIZE, &rlim);

        sprintf(pathBuf, "/root/iof/%d/in.txt", problem_id);
        freopen(pathBuf, "r", stdin);
        freopen("user.txt", "w", stdout);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execlp("./Main", "./Main", (char *)NULL);
    }
    else
    {
        int status = 0;
//        *memoryUsed = get_proc_status(pid, "VmRSS:");
        waitpid(pid, &status, 0);
  //      *memoryUsed = get_proc_status(pid, "VmPeak:");
        getrusage(RUSAGE_CHILDREN, &usage);
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        if(WIFEXITED(status))
            return 0;
        else if(WIFSIGNALED(status))
            return WTERMSIG(status);
    }
}

void getInfor(int solution_id, int *lang, int *time_limit, int *memory_limit, int *problem_id)
{
    sprintf(query, "SELECT language, problem_id FROM status WHERE solution_id = %d", solution_id);
    mysql_query(&db, query);
    MYSQL_RES *res = mysql_store_result(&db);
    MYSQL_ROW row = mysql_fetch_row(res);
    *lang = atoi(row[0]);
    *problem_id = atoi(row[1]);
    mysql_free_result(res);

    sprintf(query, "SELECT code FROM solution WHERE runid = %d LIMIT 1", solution_id);
    mysql_query(&db, query);
    res = mysql_store_result(&db);
    row = mysql_fetch_row(res);

    if(*lang == langC)
        sprintf(pathBuf, "Main.c");
    else if(*lang == langCPP)
        sprintf(pathBuf, "Main.cc");

    FILE *fp = fopen(pathBuf, "w");
    fprintf(fp, "%s", row[0]);
    fclose(fp);
    mysql_free_result(res);

    sprintf(query, "SELECT time_limit, memory_limit FROM problem WHERE problem_id = %d", *problem_id);
    mysql_query(&db, query);
    res = mysql_store_result(&db);
    row = mysql_fetch_row(res);
    *time_limit = atoi(row[0]);
    *memory_limit = atoi(row[1]);
    mysql_free_result(res);
}

void update_solution(int solution_id, int flag, int memoryUsed)
{
    long usedTime = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec;
	printf("%u\n", usage.ru_maxrss);

    usedTime += (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000000;
    usedTime = usedTime * 1000 + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) % 1000000 / 1000;
    sprintf(query, "UPDATE status SET status=%d, time=%ld, memory=%d WHERE solution_id=%d", flag, usedTime, memoryUsed, solution_id);
    mysql_query(&db, query);
}

int compare(int problem_id)
{
    return FLAG_AC;
}

int main(int argc, char *argv[])
{
    chdir("/root/run");
    int solution_id = atoi(argv[1]);
    int time_limit, memory_limit;
    int memoryUsed;
    int problem_id;
    int lang;

    mysql_init(&db);
    if(!mysql_real_connect(&db, "115.28.80.81", "oj", "nuc_icpc", "oj", 0, NULL, 0))
        return 0;
    getInfor(solution_id, &lang, &time_limit, &memory_limit, &problem_id);
    if(!compile(lang))
    {
        int status = run_solution(time_limit, memory_limit, problem_id, &memoryUsed);
        //printf("%s\n", status);
        if(status == 0)
            update_solution(solution_id, compare(problem_id), memoryUsed);
        else if(status == SIGXCPU || status == SIGALRM)
            update_solution(solution_id, FLAG_TLE, memoryUsed);
        else if(status == SIGXFSZ)
            update_solution(solution_id, FLAG_OLE, memoryUsed);
        else
        {
            if(memoryUsed >= memory_limit * STD_MB)
                update_solution(solution_id, FLAG_MLE, memoryUsed);
            else
                update_solution(solution_id, FLAG_RE, memoryUsed);
        }
    }
    else
    {
        update_solution(solution_id, FLAG_CE, 0);
    }
    mysql_close(&db);
    return 0;
}
