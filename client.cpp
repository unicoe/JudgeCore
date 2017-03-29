//
#define IGNORE_ESOL
// File:   main.cc
// Author: sempr
// refacted by zhblue
/*
* Copyright 2008 sempr <iamsempr@gmail.com>
*
* Refacted and modified by zhblue<newsclan@gmail.com>
* Bug report email newsclan@gmail.com
*
*
* This file is part of HUSTOJ.
*
* HUSTOJ is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* HUSTOJ is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with HUSTOJ. if not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/signal.h>
//#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <assert.h>
#include "okcalls.h"

#define STD_MB 1048576
#define STD_T_LIM 2
#define STD_F_LIM (STD_MB<<5)
#define STD_M_LIM (STD_MB<<7)
#define BUFFER_SIZE 5120

#define OJ_WT0 0
#define OJ_WT1 1
#define OJ_CI 2
#define OJ_RI 3
#define OJ_AC 4
#define OJ_PE 5
#define OJ_WA 6
#define OJ_RE 7
#define OJ_TL 8
#define OJ_ML 9
#define OJ_OL 10
#define OJ_CE 11
#define OJ_CO 12
#define OJ_TR 13
/*copy from ZOJ
http://code.google.com/p/zoj/source/browse/trunk/judge_client/client/tracer.cc?spec=svn367&r=367#39
*/
#ifdef __i386
#define REG_SYSCALL orig_eax
#define REG_RET eax
#define REG_ARG0 ebx
#define REG_ARG1 ecx
#else
#define REG_SYSCALL orig_rax
#define REG_RET rax
#define REG_ARG0 rdi
#define REG_ARG1 rsi

#endif

static int DEBUG = 0;
static char host_name[BUFFER_SIZE];
static char user_name[BUFFER_SIZE];
static char password[BUFFER_SIZE];
static char db_name[BUFFER_SIZE];
static char oj_home[BUFFER_SIZE];
static char data_list[BUFFER_SIZE][BUFFER_SIZE];
static int data_list_len = 0;

static int port_number;
static int max_running;
static int sleep_time;
static int java_time_bonus = 5;
static int java_memory_bonus = 512;
static char java_xms[BUFFER_SIZE];
static char java_xmx[BUFFER_SIZE];
static int sim_enable = 0;
static int oi_mode = 0;
static int full_diff = 0;
static int use_max_time = 0;
static int shm_run = 0;

static char record_call = 0;
static int use_ptrace = 1;

//static int sleep_tmp;
#define ZOJ_COM
MYSQL *conn;

static char lang_ext[4][8] = { "all", "c", "cc", "java" };
//static char buf[BUFFER_SIZE];
int data_list_has(char * file)
{
	for (int i = 0; i < data_list_len; i++)
	{
		if (strcmp(data_list[i], file) == 0)
			return 1;
	}
	return 0;
}

long get_file_size(const char * filename)
{
	struct stat f_stat;

	if (stat(filename, &f_stat) == -1)
	{
		return 0;
	}

	return (long)f_stat.st_size;
}

void write_log(const char *fmt, ...)
{
	va_list ap;
	char buffer[4096];
	//      time_t          t = time(NULL);
	//int l;
	sprintf(buffer, "%s/log/client.log", oj_home);
	FILE *fp = fopen(buffer, "ae+");
	if (fp == NULL)
	{
		fprintf(stderr, "openfile error!\n");
		system("pwd");
	}
	va_start(ap, fmt);
	//l =
	vsprintf(buffer, fmt, ap);
	fprintf(fp, "%s\n", buffer);
	if (DEBUG)
		printf("%s\n", buffer);
	va_end(ap);
	fclose(fp);

}
int execute_cmd(const char * fmt, ...)
{
	char cmd[BUFFER_SIZE];

	int ret = 0;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(cmd, fmt, ap);
	ret = system(cmd);
	va_end(ap);
	return ret;
}

const int call_array_size = 512;
int call_counter[call_array_size] = { 0 };
static char LANG_NAME[BUFFER_SIZE];
void init_syscalls_limits(int lang)
{
	int i;
	memset(call_counter, 0, sizeof(call_counter));
	if (DEBUG)
		write_log("init_call_counter:%d", lang);
	if (record_call)    // recording for debuging
	{
		for (i = 0; i < call_array_size; i++)
		{
			call_counter[i] = 0;
		}
	}
	else if (lang <= 2) // C & C++
	{
		for (i = 0; i == 0 || LANG_CV[i]; i++)
		{
			call_counter[LANG_CV[i]] = HOJ_MAX_LIMIT;
		}
	}
	else if (lang == 3)      // Java
	{
		for (i = 0; i == 0 || LANG_JV[i]; i++)
			call_counter[LANG_JV[i]] = HOJ_MAX_LIMIT;
	}
	

}

int after_equal(char * c)
{
	int i = 0;
	for (; c[i] != '\0' && c[i] != '='; i++)
		;
	return ++i;
}
void trim(char * c)
{
	char buf[BUFFER_SIZE];
	char * start, *end;
	strcpy(buf, c);
	start = buf;
	while (isspace(*start))
		start++;
	end = start;
	while (!isspace(*end))
		end++;
	*end = '\0';
	strcpy(c, start);
}
bool read_buf(char * buf, const char * key, char * value)
{
	if (strncmp(buf, key, strlen(key)) == 0)
	{
		strcpy(value, buf + after_equal(buf));
		trim(value);
		if (DEBUG)
			printf("%s\n", value);
		return 1;
	}
	return 0;
}
void read_int(char * buf, const char * key, int * value)
{
	char buf2[BUFFER_SIZE];
	if (read_buf(buf, key, buf2))
		sscanf(buf2, "%d", value);

}
// read the configue file
void init_mysql_conf()
{
	FILE *fp = NULL;
	char buf[BUFFER_SIZE];
	host_name[0] = 0;
	user_name[0] = 0;
	password[0] = 0;
	db_name[0] = 0;
	port_number = 3306;
	max_running = 3;
	sleep_time = 3;
	strcpy(java_xms, "-Xms32m");
	strcpy(java_xmx, "-Xmx256m");
	sprintf(buf, "%s/etc/judge.conf", oj_home);
	fp = fopen("./etc/judge.conf", "re");
	if (fp != NULL)
	{
		while (fgets(buf, BUFFER_SIZE - 1, fp))
		{
			read_buf(buf, "OJ_HOST_NAME", host_name);
			read_buf(buf, "OJ_USER_NAME", user_name);
			read_buf(buf, "OJ_PASSWORD", password);
			read_buf(buf, "OJ_DB_NAME", db_name);
			read_int(buf, "OJ_PORT_NUMBER", &port_number);
			read_int(buf, "OJ_JAVA_TIME_BONUS", &java_time_bonus);
			read_int(buf, "OJ_JAVA_MEMORY_BONUS", &java_memory_bonus);
			read_int(buf, "OJ_SIM_ENABLE", &sim_enable);
			read_buf(buf, "OJ_JAVA_XMS", java_xms);
			read_buf(buf, "OJ_JAVA_XMX", java_xmx);
			read_int(buf, "OJ_OI_MODE", &oi_mode);
			read_int(buf, "OJ_FULL_DIFF", &full_diff);
			read_int(buf, "OJ_SHM_RUN", &shm_run);
			read_int(buf, "OJ_USE_MAX_TIME", &use_max_time);
			read_int(buf, "OJ_USE_PTRACE", &use_ptrace);

		}
		fclose(fp);
		return;
	}
		fclose(fp);
}

int isInFile(const char fname[])
{
	int l = strlen(fname);
	if (l <= 3 || strcmp(fname + l - 3, ".in") != 0)
		return 0;
	else
		return l - 3;
}

void find_next_nonspace(int & c1, int & c2, FILE *& f1, FILE *& f2, int & ret)
{
	// Find the next non-space character or \n.
	while ((isspace(c1)) || (isspace(c2)))
	{
		if (c1 != c2)
		{
			if (c2 == EOF)
			{
				do
				{
					c1 = fgetc(f1);
				} while (isspace(c1));
				continue;
			}
			else if (c1 == EOF)
			{
				do
				{
					c2 = fgetc(f2);
				} while (isspace(c2));
				continue;
#ifdef IGNORE_ESOL
			}
			else if (isspace(c1) && isspace(c2))
			{
				while (c2 == '\n' && isspace(c1) && c1 != '\n') c1 = fgetc(f1);
				while (c1 == '\n' && isspace(c2) && c2 != '\n') c2 = fgetc(f2);

#else
			}
			else if ((c1 == '\r' && c2 == '\n'))
			{
				c1 = fgetc(f1);
			}
			else if ((c2 == '\r' && c1 == '\n'))
			{
				c2 = fgetc(f2);
#endif
			}
			else
			{
				if (DEBUG)
					printf("%d=%c\t%d=%c", c1, c1, c2, c2);
				;
				ret = OJ_PE;
			}
		}
		if (isspace(c1))
		{
			c1 = fgetc(f1);
		}
		if (isspace(c2))
		{
			c2 = fgetc(f2);
		}
	}
}

/***
int compare_diff(const char *file1,const char *file2){
char diff[1024];
sprintf(diff,"diff -q -B -b -w --strip-trailing-cr %s %s",file1,file2);
int d=system(diff);
if (d) return OJ_WA;
sprintf(diff,"diff -q -B --strip-trailing-cr %s %s",file1,file2);
int p=system(diff);
if (p) return OJ_PE;
else return OJ_AC;
}
*/
const char * getFileNameFromPath(const char * path)
{
	for (int i = strlen(path); i >= 0; i--)
	{
		if (path[i] == '/')
			return &path[i + 1];
	}
	return path;
}

void make_diff_out_full(FILE *f1, FILE *f2, int c1, int c2, const char * path)
{

	execute_cmd("echo '========[%s]========='>>diff.out", getFileNameFromPath(path));
	execute_cmd("echo '------test in top 100 lines------'>>diff.out");
	execute_cmd("head -100 data.in>>diff.out");
	execute_cmd("echo '------test out top 100 lines-----'>>diff.out");
	execute_cmd("head -100 '%s'>>diff.out", path);
	execute_cmd("echo '------user out top 100 lines-----'>>diff.out");
	execute_cmd("head -100 user.out>>diff.out");
	execute_cmd("echo '------diff out 200 lines-----'>>diff.out");
	execute_cmd("diff '%s' user.out|head -200>>diff.out", path);
	execute_cmd("echo '=============================='>>diff.out");

}
void make_diff_out_simple(FILE *f1, FILE *f2, int c1, int c2, const char * path)
{
	execute_cmd("echo '========[%s]========='>>diff.out", getFileNameFromPath(path));
	execute_cmd("echo '=======diff out 100 lines====='>>diff.out");
	execute_cmd("diff '%s' user.out|head -100>>diff.out", path);
	execute_cmd("echo '=============================='>>diff.out");
}

/*
* translated from ZOJ judger r367
* http://code.google.com/p/zoj/source/browse/trunk/judge_client/client/text_checker.cc#25
*
*/
int compare_zoj(const char *file1, const char *file2)
{
	int ret = OJ_AC;
	int c1, c2;
	FILE * f1, *f2;
	f1 = fopen(file1, "re");
	f2 = fopen(file2, "re");
	if (!f1 || !f2)
	{
		ret = OJ_RE;
	}
	else
		for (;;)
		{
			// Find the first non-space character at the beginning of line.
			// Blank lines are skipped.
			c1 = fgetc(f1);
			c2 = fgetc(f2);
			find_next_nonspace(c1, c2, f1, f2, ret);
			// Compare the current line.
			for (;;)
			{
				// Read until 2 files return a space or 0 together.
				while ((!isspace(c1) && c1) || (!isspace(c2) && c2))
				{
					if (c1 == EOF && c2 == EOF)
					{
						goto end;
					}
					if (c1 == EOF || c2 == EOF)
					{
						break;
					}
					if (c1 != c2)
					{
						// Consecutive non-space characters should be all exactly the same
						ret = OJ_WA;
						goto end;
					}
					c1 = fgetc(f1);
					c2 = fgetc(f2);
				}
				find_next_nonspace(c1, c2, f1, f2, ret);
				if (c1 == EOF && c2 == EOF)
				{
					goto end;
				}
				if (c1 == EOF || c2 == EOF)
				{
					ret = OJ_WA;
					goto end;
				}

				if ((c1 == '\n' || !c1) && (c2 == '\n' || !c2))
				{
					break;
				}
			}
		}
end:
	if (ret == OJ_WA || ret == OJ_PE)
	{
		if (full_diff)
			make_diff_out_full(f1, f2, c1, c2, file1);
		else
			make_diff_out_simple(f1, f2, c1, c2, file1);
	}
	if (f1)
		fclose(f1);
	if (f2)
		fclose(f2);
	return ret;
}

void delnextline(char s[])
{
	int L;
	L = strlen(s);
	while (L > 0 && (s[L - 1] == '\n' || s[L - 1] == '\r'))
		s[--L] = 0;
}

int compare(const char *file1, const char *file2)
{
#ifdef ZOJ_COM
	//compare ported and improved from zoj don't limit file size
	return compare_zoj(file1, file2);
#endif
#ifndef ZOJ_COM
	//the original compare from the first version of hustoj has file size limit
	//and waste memory
	FILE *f1, *f2;
	char *s1, *s2, *p1, *p2;
	int PEflg;
	s1 = new char[STD_F_LIM + 512];
	s2 = new char[STD_F_LIM + 512];
	if (!(f1 = fopen(file1, "re")))
		return OJ_AC;
	for (p1 = s1; EOF != fscanf(f1, "%s", p1);)
		while (*p1) p1++;
	fclose(f1);
	if (!(f2 = fopen(file2, "re")))
		return OJ_RE;
	for (p2 = s2; EOF != fscanf(f2, "%s", p2);)
		while (*p2) p2++;
	fclose(f2);
	if (strcmp(s1, s2) != 0)
	{
		//              printf("A:%s\nB:%s\n",s1,s2);
		delete[] s1;
		delete[] s2;

		return OJ_WA;
	}
	else
	{
		f1 = fopen(file1, "re");
		f2 = fopen(file2, "re");
		PEflg = 0;
		while (PEflg == 0 && fgets(s1, STD_F_LIM, f1) && fgets(s2, STD_F_LIM, f2))
		{
			delnextline(s1);
			delnextline(s2);
			if (strcmp(s1, s2) == 0) continue;
			else PEflg = 1;
		}
		delete[] s1;
		delete[] s2;
		fclose(f1);
		fclose(f2);
		if (PEflg) return OJ_PE;
		else return OJ_AC;
	}
#endif
}

FILE * read_cmd_output(const char * fmt, ...)
{
	char cmd[BUFFER_SIZE];

	FILE * ret = NULL;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(cmd, fmt, ap);
	va_end(ap);
	if (DEBUG)
		printf("%s\n", cmd);
	ret = popen(cmd, "r");

	return ret;
}


void update_solution(int solution_id, int result, int time, int memory, int sim,
	int sim_s_id, double pass_rate)
{
	if (result == OJ_TL && memory == 0)
		result = OJ_ML;
	char sql[BUFFER_SIZE];
////////////////////////////////////////////////////////////////////////////
	if (oi_mode)
	{
		sprintf(sql,
			"UPDATE solution SET result=%d,time=%d,memory=%d,pass_rate=%f WHERE solution_id=%d LIMIT 1",
			result, time, memory, pass_rate, solution_id);
	}
	else
	{
		sprintf(sql,
			"UPDATE status SET status=%d,run_time=%d,run_memory=%d WHERE submit_id=%d LIMIT 1",
			result, time, memory, solution_id);
	}
	if (mysql_real_query(conn, sql, strlen(sql)))
	{
		;
	}
////////////////////////////////////////////////////////////////////////////////////////
	if (sim)
	{
		sprintf(sql,
			"insert into sim(s_id,sim_s_id,sim) values(%d,%d,%d) on duplicate key update  sim_s_id=%d,sim=%d",
			solution_id, sim_s_id, sim, sim_s_id, sim);
		if (mysql_real_query(conn, sql, strlen(sql)))
		{
			;
		}

	}
}

// urlencoded function copied from http://www.geekhideout.com/urlcode.shtml
/* Converts a hex character to its integer value */
char from_hex(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code)
{
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str)
{
	char *pstr = str, *buf = (char *)malloc(strlen(str) * 3 + 1), *pbuf = buf;
	while (*pstr)
	{
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.'
			|| *pstr == '~')
			*pbuf++ = *pstr;
		else if (*pstr == ' ')
			*pbuf++ = '+';
		else
			*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(
				*pstr & 15);
		pstr++;
	}
	*pbuf = '\0';
	return buf;
}


void addceinfo(int solution_id)
{
	char sql[(1 << 16)], *end;
	char ceinfo[(1 << 16)], *cend;
	FILE *fp = fopen("ce.txt", "re");
	snprintf(sql, (1 << 16) - 1, "DELETE FROM ce_info WHERE submit_id=%d",solution_id);
	mysql_real_query(conn, sql, strlen(sql));
	cend = ceinfo;
	while (fgets(cend, 1024, fp))
	{
		cend += strlen(cend);
		if (cend - ceinfo > 40000)
			break;
	}
	cend = 0;
	end = sql;
	strcpy(end, "INSERT INTO ce_info VALUES(");
	end += strlen(sql);
	*end++ = '\'';
	end += sprintf(end, "%d", solution_id);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += mysql_real_escape_string(conn, end, ceinfo, strlen(ceinfo));
	*end++ = '\'';
	*end++ = ')';
	*end = 0;
	if (mysql_real_query(conn, sql, end - sql))
		printf("%s\n", mysql_error(conn));
	fclose(fp);
}

/* write runtime error message back to database */
void _addreinfo_mysql(int solution_id, const char * filename)
{
	char sql[(1 << 16)], *end;
	char reinfo[(1 << 16)], *rend;
	FILE *fp = fopen(filename, "re");
	snprintf(sql, (1 << 16) - 1, "DELETE FROM runtimeinfo WHERE solution_id=%d",
		solution_id);
	mysql_real_query(conn, sql, strlen(sql));
	rend = reinfo;
	while (fgets(rend, 1024, fp))
	{
		rend += strlen(rend);
		if (rend - reinfo > 40000)
			break;
	}
	rend = 0;
	end = sql;
	strcpy(end, "INSERT INTO runtimeinfo VALUES(");
	end += strlen(sql);
	*end++ = '\'';
	end += sprintf(end, "%d", solution_id);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += mysql_real_escape_string(conn, end, reinfo, strlen(reinfo));
	*end++ = '\'';
	*end++ = ')';
	*end = 0;
	//      printf("%s\n",ceinfo);
	if (mysql_real_query(conn, sql, end - sql))
		printf("%s\n", mysql_error(conn));
	fclose(fp);
}

void addreinfo(int solution_id)
{
	_addreinfo_mysql(solution_id, "error.out");
}

void adddiffinfo(int solution_id)
{
	_addreinfo_mysql(solution_id, "diff.out");
}

int compile(int lang, char * work_dir)
{
	int pid;

	const char * CP_C[] = { "gcc", "Main.c", "-o", "Main", "-fno-asm", "-Wall", 
		"-lm", "--static", "-std=c99", "-DONLINE_JUDGE", NULL
	};
	const char * CP_X[] = { "g++", "-fno-asm", "-Wall",
		"-lm", "--static", "-std=c++11", "-DONLINE_JUDGE", "-o", "Main", "Main.cc", NULL
	};

	char javac_buf[7][32];
	char *CP_J[7];
	for (int i = 0; i < 7; i++)
		CP_J[i] = javac_buf[i];

	sprintf(CP_J[0], "javac");
	sprintf(CP_J[1], "-J%s", java_xms);
	sprintf(CP_J[2], "-J%s", java_xmx);
	sprintf(CP_J[3], "-encoding");
	sprintf(CP_J[4], "UTF-8");
	sprintf(CP_J[5], "Main.java");
	CP_J[6] = (char *)NULL;

	pid = fork();
	if (pid == 0)
	{
		struct rlimit LIM;
		LIM.rlim_max = 60;
		LIM.rlim_cur = 60;
		setrlimit(RLIMIT_CPU, &LIM);
		alarm(60);
		LIM.rlim_max = 10 * STD_MB;
		LIM.rlim_cur = 10 * STD_MB;
		setrlimit(RLIMIT_FSIZE, &LIM);

		if (lang == 3 || lang == 17)
		{
			LIM.rlim_max = STD_MB << 11;
			LIM.rlim_cur = STD_MB << 11;
		}
		else
		{
			LIM.rlim_max = STD_MB * 256;
			LIM.rlim_cur = STD_MB * 256;
		}
		setrlimit(RLIMIT_AS, &LIM);
		freopen("ce.txt", "w", stderr);
		if (lang != 3) { //C or C++
			execute_cmd("mkdir -p bin usr lib lib64 etc/alternatives proc tmp dev");
			execute_cmd("chown judge *");
			execute_cmd("mount -o bind /bin bin");
			execute_cmd("mount -o bind /usr usr");
			execute_cmd("mount -o bind /lib lib");
#ifndef __i386
			execute_cmd("mount -o bind /lib64 lib64");
#endif
			execute_cmd("mount -o bind /etc/alternatives etc/alternatives");
			execute_cmd("mount -o bind /proc proc");
			chroot(work_dir);
		}
		while (setgid(2017) != 0) sleep(1);
		while (setuid(2017) != 0) sleep(1);
		while (setresuid(2017, 2017, 2017) != 0) sleep(1);

		switch (lang)
		{
		case 1:
			execvp(CP_C[0], (char * const *)CP_C);
			break;
		case 2:
			execvp(CP_X[0], (char * const *)CP_X);
			break;
		case 3:
			execvp(CP_J[0], (char * const *)CP_J);
			break;
		default:
			printf("nothing to do!\n");
		}
		exit(0);
	}
	else
	{
		int status = 0;

		waitpid(pid, &status, 0);
		if (DEBUG)
			printf("status=%d\n", status);
		execute_cmd("/bin/umount bin usr lib lib64 etc/alternatives proc dev");
		execute_cmd("/bin/umount %s/*", work_dir);

		return status;
	}

}
/*
int read_proc_statm(int pid){
FILE * pf;
char fn[4096];
int ret;
sprintf(fn,"/proc/%d/statm",pid);
pf=fopen(fn,"r");
fscanf(pf,"%d",&ret);
fclose(pf);
return ret;
}
*/
int get_proc_status(int pid, const char * mark)
{
	FILE * pf;
	char fn[BUFFER_SIZE], buf[BUFFER_SIZE];
	int ret = 0;
	sprintf(fn, "/proc/%d/status", pid);
	pf = fopen(fn, "re");
	int m = strlen(mark);
	while (pf && fgets(buf, BUFFER_SIZE - 1, pf))
	{

		buf[strlen(buf) - 1] = 0;
		if (strncmp(buf, mark, m) == 0)
		{
			sscanf(buf + m + 1, "%d", &ret);
		}
	}
	if (pf)
		fclose(pf);
	return ret;
}
int init_mysql_conn()
{

	conn = mysql_init(NULL);
	const char timeout = 30;
	mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

	if (!mysql_real_connect(conn, host_name, user_name, password, db_name,
		port_number, 0, 0))
	{
		write_log("%s", mysql_error(conn));
		return 0;
	}
	const char * utf8sql = "set names utf8";
	if (mysql_real_query(conn, utf8sql, strlen(utf8sql)))
	{
		write_log("%s", mysql_error(conn));
		return 0;
	}
	return 1;
}

void get_solution(int solution_id, char * work_dir, int lang)
{
	char sql[BUFFER_SIZE], src_pth[BUFFER_SIZE];
	// get the source code
	MYSQL_RES *res;
	MYSQL_ROW row;
	sprintf(sql, "SELECT code FROM codes WHERE submit_id=%d", solution_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);

	// create the src file
	sprintf(src_pth, "Main.%s", lang_ext[lang]);
	if (DEBUG)
		printf("Main=%s", src_pth);
	FILE *fp_src = fopen(src_pth, "we");
	fprintf(fp_src, "%s", row[0]);
	mysql_free_result(res);
	fclose(fp_src);

}


void get_solution_info(int solution_id, int & p_id, char * user_id, int & lang)
{

	MYSQL_RES *res;
	MYSQL_ROW row;

	char sql[BUFFER_SIZE];
	// get the problem id and user id from Table:solution
	sprintf(sql, "SELECT pro_id, user_id, lang FROM status where submit_id=%d", solution_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);
	p_id = atoi(row[0]);
	strcpy(user_id, row[1]);
	lang = atoi(row[2]);
	mysql_free_result(res);
}

void get_problem_info(int p_id, int & time_lmt, int & mem_lmt, int & isspj)
{
	// get the problem info from Table:problem
	char sql[BUFFER_SIZE];
	MYSQL_RES *res;
	MYSQL_ROW row;
	sprintf(sql, "SELECT time_limit,memory_limit FROM problem where pro_id=%d", p_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);
	time_lmt = atoi(row[0]);
	mem_lmt = atoi(row[1]);
	mysql_free_result(res);
}

void prepare_files(char * filename, int namelen, char * infile, int & p_id,
	char * work_dir, char * outfile, char * userfile, int runner_id)
{
	char fname[BUFFER_SIZE];
	strncpy(fname, filename, namelen);
	fname[namelen] = 0;
	sprintf(infile, "%s/data/%d/%s.in", oj_home, p_id, fname);
	execute_cmd("/bin/cp '%s' %s/data.in", infile, work_dir);
	execute_cmd("/bin/cp %s/data/%d/*.dic %s/", oj_home, p_id, work_dir);

	sprintf(outfile, "%s/data/%d/%s.out", oj_home, p_id, fname);
	sprintf(userfile, "%s/run%d/user.out", oj_home, runner_id);
}

void run_solution(int & lang, char * work_dir, int & time_lmt, int & usedtime,
	int & mem_lmt)
{
	nice(19);
	// now the user is "judger"
	//
	chdir(work_dir);
	// open the files
	freopen("data.in", "r", stdin);
	freopen("user.out", "w", stdout);
	freopen("error.out", "a+", stderr);
	// trace me
	if (use_ptrace) ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	// run me
	if (lang != 3)
		chroot(work_dir);

	while (setgid(2017) != 0)
		sleep(1);
	while (setuid(2017) != 0)
		sleep(1);
	while (setresuid(2017, 2017, 2017) != 0)
		sleep(1);

	//      char java_p1[BUFFER_SIZE], java_p2[BUFFER_SIZE];
	// child
	// set the limit
	struct rlimit LIM; // time limit, file limit& memory limit
					   // time limit
	if (oi_mode)
		LIM.rlim_cur = time_lmt + 1;
	else
		LIM.rlim_cur = (time_lmt - usedtime / 1000) + 1;
	LIM.rlim_max = LIM.rlim_cur;
	//if(DEBUG) printf("LIM_CPU=%d",(int)(LIM.rlim_cur));
	setrlimit(RLIMIT_CPU, &LIM);
	alarm(0);
	alarm(time_lmt * 10);

	// file limit
	LIM.rlim_max = STD_F_LIM + STD_MB;
	LIM.rlim_cur = STD_F_LIM;
	setrlimit(RLIMIT_FSIZE, &LIM);
	// proc limit
	switch (lang)
	{
	case 3:  //java
		LIM.rlim_cur = LIM.rlim_max = 80;
		break;
	default:
		LIM.rlim_cur = LIM.rlim_max = 1;
	}

	setrlimit(RLIMIT_NPROC, &LIM);

	// set the stack
	LIM.rlim_cur = STD_MB << 6;
	LIM.rlim_max = STD_MB << 6;
	setrlimit(RLIMIT_STACK, &LIM);
	// set the memory
	LIM.rlim_cur = STD_MB * mem_lmt / 2 * 3;
	LIM.rlim_max = STD_MB * mem_lmt * 2;
	if (lang < 3)
		setrlimit(RLIMIT_AS, &LIM);

	switch (lang)
	{
	case 1:
	case 2:
		execl("./Main", "./Main", (char *)NULL);
		break;
	case 3:
		sprintf(java_xms, "-Xmx%dM", mem_lmt);
		execl("/usr/bin/java", "/usr/bin/java", java_xms, java_xmx,
			"-Djava.security.manager",
			"-Djava.security.policy=./java.policy", "Main", (char *)NULL);
		break;
	}
	fflush(stderr);
	exit(0);
}

int fix_java_mis_judge(char *work_dir, int & ACflg, int & topmemory,
	int mem_lmt)
{
	int comp_res = OJ_AC;
	execute_cmd("chmod 700 %s/error.out", work_dir);
	if (DEBUG)
		execute_cmd("cat %s/error.out", work_dir);
	comp_res = execute_cmd("/bin/grep 'Exception'  %s/error.out", work_dir);
	if (!comp_res)
	{
		printf("Exception reported\n");
		ACflg = OJ_RE;
	}
	execute_cmd("cat %s/error.out", work_dir);

	comp_res = execute_cmd(
		"/bin/grep 'java.lang.OutOfMemoryError'  %s/error.out", work_dir);

	if (!comp_res)
	{
		printf("JVM need more Memory!");
		ACflg = OJ_ML;
		topmemory = mem_lmt * STD_MB;
	}

	if (!comp_res)
	{
		printf("JVM need more Memory or Threads!");
		ACflg = OJ_ML;
		topmemory = mem_lmt * STD_MB;
	}
	comp_res = execute_cmd("/bin/grep 'Could not create'  %s/error.out",
		work_dir);
	if (!comp_res)
	{
		printf("jvm need more resource,tweak -Xmx(OJ_JAVA_BONUS) Settings");
		ACflg = OJ_RE;
		//topmemory=0;
	}
	return comp_res;
}

void judge_solution(int & ACflg, int & usedtime, int time_lmt, int isspj,
	int p_id, char * infile, char * outfile, char * userfile, int & PEflg,
	int lang, char * work_dir, int & topmemory, int mem_lmt,
	int solution_id, int num_of_test)
{
	//usedtime-=1000;
	int comp_res;
	if (!oi_mode)
		num_of_test = 1.0;
	if (ACflg == OJ_AC
		&& usedtime > time_lmt * 1000 * (use_max_time ? 1 : num_of_test))
		ACflg = OJ_TL;
	if (topmemory > mem_lmt * STD_MB)
		ACflg = OJ_ML; //issues79
					   // compare
	if (ACflg == OJ_AC)
	{
		comp_res = compare(outfile, userfile);
		if (comp_res == OJ_WA)
		{
			ACflg = OJ_WA;
			if (DEBUG)
				printf("fail test %s\n", infile);
		}
		else if (comp_res == OJ_PE)
			PEflg = OJ_PE;
		ACflg = comp_res;
	}
	//jvm popup messages, if don't consider them will get miss-WrongAnswer
	if (lang == 3)
	{
		comp_res = fix_java_mis_judge(work_dir, ACflg, topmemory, mem_lmt);
	}
}

int get_page_fault_mem(struct rusage & ruse, pid_t & pidApp)
{
	//java use pagefault
	int m_vmpeak, m_vmdata, m_minflt;
	m_minflt = ruse.ru_minflt * getpagesize();
	if (0 && DEBUG)
	{
		m_vmpeak = get_proc_status(pidApp, "VmPeak:");
		m_vmdata = get_proc_status(pidApp, "VmData:");
		printf("VmPeak:%d KB VmData:%d KB minflt:%d KB\n", m_vmpeak, m_vmdata,
			m_minflt >> 10);
	}
	return m_minflt;
}
void print_runtimeerror(char * err)
{
	FILE *ferr = fopen("error.out", "a+");
	fprintf(ferr, "Runtime Error:%s\n", err);
	fclose(ferr);
}
void clean_session(pid_t p)
{
	//char cmd[BUFFER_SIZE];
	const char *pre = "ps awx -o \"\%p \%P\"|grep -w ";
	const char *post = " | awk \'{ print $1  }\'|xargs kill -9";
	execute_cmd("%s %d %s", pre, p, post);
	execute_cmd("ps aux |grep \\^judge|awk '{print $2}'|xargs kill");
}

void watch_solution(pid_t pidApp, char * infile, int & ACflg, int isspj,
	char * userfile, char * outfile, int solution_id, int lang,
	int & topmemory, int mem_lmt, int & usedtime, int time_lmt, int & p_id,
	int & PEflg, char * work_dir)
{
	// parent
	int tempmemory;

	if (DEBUG)
		printf("pid=%d judging %s\n", pidApp, infile);

	int status, sig, exitcode;
	struct user_regs_struct reg;
	struct rusage ruse;
	if (topmemory == 0)
		topmemory = get_proc_status(pidApp, "VmRSS:") << 10;
	while (1)
	{
		// check the usage

		wait4(pidApp, &status, 0, &ruse);

		//jvm gc ask VM before need,so used kernel page fault times and page size
		if (lang == 3)
		{
			tempmemory = get_page_fault_mem(ruse, pidApp);
		}
		else            //other use VmPeak
		{
			tempmemory = get_proc_status(pidApp, "VmPeak:") << 10;
		}
		if (tempmemory > topmemory)
			topmemory = tempmemory;
		if (topmemory > mem_lmt * STD_MB)
		{
			if (DEBUG)
				printf("out of memory %d %d\n", topmemory, mem_lmt);
			if (ACflg == OJ_AC)
				ACflg = OJ_ML;
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);
			break;
		}
		//sig = status >> 8;/*status >> 8 Ã¥Â·Â®Ã¤Â¸ÂÃ¥Â¤Å¡Ã¦ËÂ¯EXITCODE*/

		if (WIFEXITED(status))
			break;
		if (get_file_size("error.out") && !oi_mode)
		{
			ACflg = OJ_RE;
			//addreinfo(solution_id);
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);
			break;
		}

		if (get_file_size(userfile) > get_file_size(outfile) * 2 + 1024)
		{
			ACflg = OJ_OL;
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);
			break;
		}

		exitcode = WEXITSTATUS(status);
		/*exitcode == 5 waiting for next CPU allocation          * ruby using system to run,exit 17 ok
		*  */
		if ((lang >= 3 && exitcode == 17) || exitcode == 0x05 || exitcode == 0)
			//go on and on
			;
		else
		{

			if (DEBUG)
			{
				printf("status>>8=%d\n", exitcode);

			}
			//psignal(exitcode, NULL);

			if (ACflg == OJ_AC)
			{
				switch (exitcode)
				{
				case SIGCHLD:
				case SIGALRM:
					alarm(0);
				case SIGKILL:
				case SIGXCPU:
					ACflg = OJ_TL;
					break;
				case SIGXFSZ:
					ACflg = OJ_OL;
					break;
				default:
					ACflg = OJ_RE;
				}
				print_runtimeerror(strsignal(exitcode));
			}
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);

			break;
		}
		if (WIFSIGNALED(status))
		{
			/*  WIFSIGNALED: if the process is terminated by signal
			*
			*  psignal(int sig, char *s)，like perror(char *s)，print out s, with error msg from system of sig
			* sig = 5 means Trace/breakpoint trap
			* sig = 11 means Segmentation fault
			* sig = 25 means File size limit exceeded
			*/
			sig = WTERMSIG(status);

			if (DEBUG)
			{
				printf("WTERMSIG=%d\n", sig);
				psignal(sig, NULL);
			}
			if (ACflg == OJ_AC)
			{
				switch (sig)
				{
				case SIGCHLD:
				case SIGALRM:
					alarm(0);
				case SIGKILL:
				case SIGXCPU:
					ACflg = OJ_TL;
					break;
				case SIGXFSZ:
					ACflg = OJ_OL;
					break;

				default:
					ACflg = OJ_RE;
				}
				print_runtimeerror(strsignal(sig));
			}
			break;
		}
		/*     comment from http://www.felix021.com/blog/read.php?1662
		WIFSTOPPED: return true if the process is paused or stopped while ptrace is watching on it
		WSTOPSIG: get the signal if it was stopped by signal
		*/

		// check the system calls
		ptrace(PTRACE_GETREGS, pidApp, NULL, &reg);
		if (call_counter[reg.REG_SYSCALL])
		{
			//call_counter[reg.REG_SYSCALL]--;
		}
		else if (record_call)
		{
			call_counter[reg.REG_SYSCALL] = 1;

		}
		else    //do not limit JVM syscall for using different JVM
		{
			ACflg = OJ_RE;
			char error[BUFFER_SIZE];
			sprintf(error,
				"[ERROR] A Not allowed system call: runid:%d CALLID:%ld\n"
				" TO FIX THIS , ask admin to add the CALLID into corresponding LANG_XXV[] located at okcalls32/64.h ,\n"
				"and recompile judge_client. \n",
				solution_id, (long)reg.REG_SYSCALL);

			write_log(error);
			print_runtimeerror(error);
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);
		}


		ptrace(PTRACE_SYSCALL, pidApp, NULL, NULL);
	}
	usedtime += (ruse.ru_utime.tv_sec * 1000 + ruse.ru_utime.tv_usec / 1000);
	usedtime += (ruse.ru_stime.tv_sec * 1000 + ruse.ru_stime.tv_usec / 1000);

	//clean_session(pidApp);
}
void umount(char * work_dir)
{
	execute_cmd("/bin/umount %s/proc", work_dir);
	execute_cmd("/bin/umount %s/dev", work_dir);
	execute_cmd("/bin/umount %s/lib", work_dir);
	execute_cmd("/bin/umount %s/lib64", work_dir);
	execute_cmd("/bin/umount %s/etc/alternatives", work_dir);
	execute_cmd("/bin/umount %s/usr", work_dir);
	execute_cmd("/bin/umount %s/bin", work_dir);
	execute_cmd("/bin/umount %s/proc", work_dir);
	execute_cmd("/bin/umount bin usr lib lib64 etc/alternatives proc dev");
	execute_cmd("/bin/umount %s/*", work_dir);
}
void clean_workdir(char * work_dir)
{
	umount(work_dir);
	if (DEBUG)
	{
		execute_cmd("mkdir %s/log/", work_dir);
		execute_cmd("/bin/mv %s/* %s/log/", work_dir, work_dir);
	}
	else
	{
		execute_cmd("/bin/rm -f %s/*", work_dir);
	}

}

void init_parameters(int argc, char ** argv, int & solution_id,
	int & runner_id)
{
	if (argc < 3)
	{
		fprintf(stderr, "Usage:%s solution_id runner_id.\n", argv[0]);
		fprintf(stderr, "Multi:%s solution_id runner_id judge_base_path.\n",
			argv[0]);
		fprintf(stderr,
			"Debug:%s solution_id runner_id judge_base_path debug.\n",
			argv[0]);
		exit(1);
	}
	DEBUG = (argc > 4);
	record_call = (argc > 5);
	if (argc > 5)
	{
		strcpy(LANG_NAME, argv[5]);
	}
	if (argc > 3)
		strcpy(oj_home, argv[3]);
	else
		strcpy(oj_home, "/home/judge");

	chdir(oj_home); // change the dir// init our work

	solution_id = atoi(argv[1]);
	runner_id = atoi(argv[2]);
}
int get_sim(int solution_id, int lang, int pid, int &sim_s_id)
{
	char src_pth[BUFFER_SIZE];
	//char cmd[BUFFER_SIZE];
	sprintf(src_pth, "Main.%s", lang_ext[lang]);

	int sim = execute_cmd("/usr/bin/sim.sh %s %d", src_pth, pid);
	if (!sim)
	{
		execute_cmd("/bin/mkdir ../data/%d/ac/", pid);

		execute_cmd("/bin/cp %s ../data/%d/ac/%d.%s", src_pth, pid, solution_id,
			lang_ext[lang]);
		//c cpp will
		if (lang == 0)
			execute_cmd("/bin/ln ../data/%d/ac/%d.%s ../data/%d/ac/%d.%s", pid,
				solution_id, lang_ext[lang], pid, solution_id,
				lang_ext[lang + 1]);
		if (lang == 1)
			execute_cmd("/bin/ln ../data/%d/ac/%d.%s ../data/%d/ac/%d.%s", pid,
				solution_id, lang_ext[lang], pid, solution_id,
				lang_ext[lang - 1]);

	}
	else
	{

		FILE * pf;
		pf = fopen("sim", "r");
		if (pf)
		{
			fscanf(pf, "%d%d", &sim, &sim_s_id);
			fclose(pf);
		}

	}
	if (solution_id <= sim_s_id)
		sim = 0;
	return sim;
}
void mk_shm_workdir(char * work_dir)
{
	char shm_path[BUFFER_SIZE];
	sprintf(shm_path, "/dev/shm/hustoj/%s", work_dir);
	execute_cmd("/bin/mkdir -p %s", shm_path);
	execute_cmd("/bin/ln -s %s %s/", shm_path, oj_home);
	execute_cmd("/bin/chown judge %s ", shm_path);
	execute_cmd("chmod 755 %s ", shm_path);
	//sim need a soft link in shm_dir to work correctly
	sprintf(shm_path, "/dev/shm/hustoj/%s/", oj_home);
	execute_cmd("/bin/ln -s %s/data %s", oj_home, shm_path);

}
int count_in_files(char * dirpath)
{
	const char * cmd = "ls -l %s/*.in|wc -l";
	int ret = 0;
	FILE * fjobs = read_cmd_output(cmd, dirpath);
	fscanf(fjobs, "%d", &ret);
	pclose(fjobs);

	return ret;
}

void print_call_array()
{
	printf("int LANG_%sV[256]={", LANG_NAME);
	int i = 0;
	for (i = 0; i < call_array_size; i++)
	{
		if (call_counter[i])
		{
			printf("%d,", i);
		}
	}
	printf("0};\n");

	printf("int LANG_%sC[256]={", LANG_NAME);
	for (i = 0; i < call_array_size; i++)
	{
		if (call_counter[i])
		{
			printf("HOJ_MAX_LIMIT,");
		}
	}
	printf("0};\n");

}
int main(int argc, char** argv)
{
	char work_dir[BUFFER_SIZE];
	//char cmd[BUFFER_SIZE];
	char user_id[BUFFER_SIZE];
	int solution_id = 1000;
	int runner_id = 0;
	int p_id, time_lmt, mem_lmt, lang, isspj, sim, sim_s_id, max_case_time = 0;

	init_parameters(argc, argv, solution_id, runner_id);  //初始化 提交号和运行号

	init_mysql_conf();

	if (!init_mysql_conn())
	{
		exit(0); //exit if mysql is down
	}
	//set work directory to start running & judging
	//
	sprintf(work_dir, "%s/run%s/", oj_home, argv[2]);

	clean_workdir(work_dir);

	if (shm_run)
		mk_shm_workdir(work_dir);

	chdir(work_dir);

	get_solution_info(solution_id, p_id, user_id, lang);
	//get the limit
	
	get_problem_info(p_id, time_lmt, mem_lmt, isspj);
	mem_lmt /= 1024;
	time_lmt /= 1024;
	//copy source file

	get_solution(solution_id, work_dir, lang);
	if (lang == 3)    //Java
	{
		// the limit for java
		time_lmt = time_lmt + java_time_bonus;
		mem_lmt = mem_lmt + java_memory_bonus;
		// copy java.policy
		execute_cmd("/bin/cp %s/etc/java0.policy %s/java.policy", oj_home,
			work_dir);

	}
	if (DEBUG)
		printf("time: %d mem: %d\n", time_lmt, mem_lmt);

	// compile
	// set the result to compiling
	int Compile_OK;

	Compile_OK = compile(lang, work_dir);
	if (Compile_OK != 0)
	{
		addceinfo(solution_id);
		update_solution(solution_id, OJ_CE, 0, 0, 0, 0, 0.0);
		mysql_close(conn);
		clean_workdir(work_dir);
		write_log("compile error");
		exit(0);
	}
	else
	{
		update_solution(solution_id, OJ_RI, 0, 0, 0, 0, 0.0);
		umount(work_dir);
	}
	// run
	char fullpath[BUFFER_SIZE];
	char infile[BUFFER_SIZE];
	char outfile[BUFFER_SIZE];
	char userfile[BUFFER_SIZE];
	sprintf(fullpath, "%s/data/%d", oj_home, p_id); // the fullpath of data dir

													// open DIRs
	DIR *dp;
	dirent *dirp;

	if ((dp = opendir(fullpath)) == NULL)
	{

		write_log("No such dir:%s!\n", fullpath);
		mysql_close(conn);
		exit(-1);
	}

	int ACflg, PEflg;
	ACflg = PEflg = OJ_AC;
	int namelen;
	int usedtime = 0, topmemory = 0;


	// read files and run
	// read files and run
	// read files and run
	double pass_rate = 0.0; //For OI MODE
	int num_of_test = 0;
	int finalACflg = ACflg;
	
	for (; (oi_mode || ACflg == OJ_AC || ACflg == OJ_PE) && (dirp = readdir(dp)) != NULL;)
	{
		namelen = isInFile(dirp->d_name); // check if the file is *.in or not
		if (namelen == 0)
			continue;


		prepare_files(dirp->d_name, namelen, infile, p_id, work_dir, outfile,
			userfile, runner_id);
		init_syscalls_limits(lang);
		pid_t pidApp = fork();

		if (pidApp == 0)
		{
			run_solution(lang, work_dir, time_lmt, usedtime, mem_lmt);
		}
		else
		{

			num_of_test++;

			watch_solution(pidApp, infile, ACflg, isspj, userfile, outfile,
				solution_id, lang, topmemory, mem_lmt, usedtime, time_lmt,
				p_id, PEflg, work_dir);

			judge_solution(ACflg, usedtime, time_lmt, isspj, p_id, infile,
				outfile, userfile, PEflg, lang, work_dir, topmemory,
				mem_lmt, solution_id, num_of_test);
			if (use_max_time)
			{
				max_case_time =
					usedtime > max_case_time ? usedtime : max_case_time;
				usedtime = 0;
			}
			//clean_session(pidApp);
		}
		if (oi_mode)
		{
			if (ACflg == OJ_AC)
			{
				++pass_rate;
			}
			if (finalACflg < ACflg)
			{
				finalACflg = ACflg;
			}

			ACflg = OJ_AC;
		}
	}
	if (ACflg == OJ_AC && PEflg == OJ_PE)
		ACflg = OJ_PE;
	if (sim_enable && ACflg == OJ_AC && (!oi_mode || finalACflg == OJ_AC)
		&& lang < 5)   //bash don't supported
	{
		sim = get_sim(solution_id, lang, p_id, sim_s_id);
	}
	else
	{
		sim = 0;
	}

	if (use_max_time)
	{
		usedtime = max_case_time;
	}
	if (ACflg == OJ_TL)
	{
		usedtime = time_lmt * 1000;
	}
	if (oi_mode)
	{
		if (num_of_test > 0)
			pass_rate /= num_of_test;
		update_solution(solution_id, finalACflg, usedtime, topmemory >> 10, sim,
			sim_s_id, pass_rate);
	}
	else
	{
		update_solution(solution_id, ACflg, usedtime, topmemory >> 10, sim,
			sim_s_id, 0);
	}
	if ((oi_mode && finalACflg == OJ_WA) || ACflg == OJ_WA)
	{
		if (DEBUG)
			printf("add diff info of %d..... \n", solution_id);
		if (!isspj)
			adddiffinfo(solution_id);
	}
	clean_workdir(work_dir);

	if (DEBUG)
		write_log("result=%d", oi_mode ? finalACflg : ACflg);
	mysql_close(conn);
	if (record_call)
	{
		print_call_array();
	}
	closedir(dp);
	return 0;
}
