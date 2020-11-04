#searches through currently running processes in /proc on a unix system to do some operations with them
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

//lists the subdirectories within a given directory
void listDir(const char* dir)
{
	char cmd[50];
	char tempstr[50];
	DIR *dp; // current directory pointer
	struct dirent *ep; // current subdirectory pointer

	dp = opendir(dir);

	if (!dp)
	{
		return;
	}

	while((ep = readdir(dp)) != NULL)
	{
		if (ep->d_type == DT_DIR)
		{
			if (ep->d_name[0] > '0' && ep->d_name[0] < '9')
			{
				sprintf(tempstr, "	tid: %s", ep->d_name);
				puts(tempstr);
				
				sprintf(cmd, "head -1 %s/%s/status", dir, ep->d_name);
				system(cmd);
			}
		}
	}
	closedir(dp);
}

//find lines within /proc/pid/maps containing ".so"
//these are the modules loaded by the process
char findSoInFile(char* fname)
{
	FILE *fp;
	char output[512];
	char temp[512];
	char str[] = ".so";

	if((fp = fopen(fname, "r")) == NULL)
	{
		return(-1);
	}
	while(fgets(temp, 512, fp) != NULL)
	{
		if((strstr(temp, str)) != NULL)
		{
			sprintf(output, "\n%s", temp);
			puts(output);
		}
	}
}

//find lines within /proc/pid/maps with executable permissions
//these are the executable pages within the process
char findXInFile(char* fname)
{
	FILE *fp;
	char output[512];
	char temp[512];
	char str1[] = " --x- ";
	char str2[] = " r-x- ";
	char str3[] = " rwx- ";
	char str4[] = " r-xp ";
	char str5[] = " rwxp ";

	if((fp = fopen(fname, "r")) == NULL)
	{
		return(-1);
	}
	while(fgets(temp, 512, fp) != NULL)
	{
		if((strstr(temp, str1)) != NULL || (strstr(temp, str2)) != NULL || (strstr(temp, str3)) != NULL || (strstr(temp, str4)) != NULL || (strstr(temp, str5)) != NULL)
		{
			sprintf(output, "\n%s", temp);
			puts(output);
		}
	}
}

//contatenates two strings, returns a new one
//puts s2 on the end of s1
char* concat(const char* s1, const char* s2)
{
	char* ret = malloc(strlen(s1) + strlen(s2) + 1);
	strcpy(ret, s1);
	strcat(ret, s2);
	return ret;
}

//changes each char in a string to a decimal representation of itself
int toDeci(char* str, int base)
{
	int length = strlen(str);
	int power = 1;
	int num = 0;
	int i = 0;
	char temp[16];

	for (i = length - 1; i >= 0; i--)
	{
		int x = str[i] - '0' - 38;
		if (x <= 0)
		{
			x = 0;
		}
		
		if(x > base)
		{
			printf("Invalid Number\n");
			return -1;
		}
		num += x * power;
		power = power * base;
	}
	return num;
}

//prints any data type in binary
void printBits(size_t const size, void const* const ptr)
{
	unsigned char* b = (unsigned char*) ptr;
	unsigned char byte;
	int i = 0, j = 0;
	
	for(i = size - 1; i >= 0; i--)
	{
		for (j = 7; j >= 0; j--)
		{
			byte = (b[i] >> j) & 1;
			printf("%u", byte);
		}
	}
	puts("");
}
int main(int argc, char* argv[])
{
	char cmd[50];

	DIR *dp; // current directory pointer
	struct dirent *ep; // current subdirectory pointer

	//open /proc
	dp = opendir("/proc");
	
	int i = 0;
	char tempstr[50]; //will be used for just about everything
	while(ep = readdir(dp))
	{
		//if can't open current directory, continue
		if (!dp)
		{
			continue;
		}
		//if we're looking at a directory
		if (ep->d_type == DT_DIR)
		{	
			//if the directory name is a number (meaning it's a process folder)
			if(ep->d_name[0] > '0' && ep->d_name[0] < '9')
			{
				//print "pid: <pid>"
				sprintf(tempstr, "pid: %s", ep->d_name);
				puts(tempstr);
			
				//get the name of the process
				sprintf(cmd, "head -1 /proc/%s/status", ep->d_name);
				system(cmd);
			}
		}
	}
	

	puts("\n");
	//print the pid of the process given to the program
	sprintf(tempstr, "pid: %s", argv[1]);
	puts(tempstr);
	
	//print the name of the process given to the program
	sprintf(cmd, "head -1 /proc/%s/status", argv[1]);
	system(cmd);

	//open /proc/pid/task to list threads
	sprintf(tempstr, "/proc/%s/task", argv[1]);
	dp = opendir(tempstr);
	while(ep = readdir(dp))
	{
		if(!dp)
		{
			continue;
		}
		if(ep->d_type == DT_DIR)
		{
			if(ep->d_name[0] > '0' && ep->d_name[0] < '9')
			{
				sprintf(tempstr, "	tid: %s", ep->d_name);
				puts(tempstr);
					
				sprintf(tempstr, "/proc/%s/task", argv[1]);
				sprintf(cmd, "head -1 %s/%s/status", tempstr, ep->d_name);
				system(cmd);
			}
			
		}
	}

	//list the process' loaded modules and executable pages
	sprintf(tempstr, "/proc/%s/maps", argv[1]);
	puts("--------------------------------------Loaded Modules--------------------------------------\n");
	findSoInFile(tempstr);
	puts("--------------------------------------Executable Pages--------------------------------------\n");
	findXInFile(tempstr);

	//a bunch of variables
	pid_t pid;
	pid = atoi(argv[1]);
	FILE *fp;
	FILE *newfp;
	char temp[512];
	char* mem;
	char* begin;
	char* end;
	int* bAddr;
	int* eAddr;
	int bAddrPad;
	int eAddrPad;
	char* startPadString = "";
	char* endPadString = "";
	char* startAddr;
	char* endAddr;

	//open /proc/pid/maps
	fp = fopen(tempstr, "r");

	while(fgets(temp, 512, fp) != NULL)
	{
		//grab first chunk of text from /maps and make some variables
		mem = strtok(temp, " ");

		begin = strtok(mem, "-");
		end = strtok(NULL, "\0");
		
		bAddr = (int *)begin;
		eAddr = (int *)end;
		bAddrPad = 16 - strlen(begin);
		eAddrPad = 16 - strlen(end);
	

		//pad start address to length of 16
		if(bAddrPad > 0)
		{
			startPadString = concat("0", begin);
			for(i = 1; i < bAddrPad; i++)
			{
				startPadString = concat("0", startPadString);
			}
		}
		//pad end address to length of 16
		if(eAddrPad > 0)
		{
			endPadString = concat("0", end);
			for(i = 1; i < eAddrPad; i++)
			{
				endPadString = concat("0", endPadString);
			}
		}
	
		long int startOff = toDeci(startPadString, 16);
		long int endOff = toDeci(endPadString, 16);
	
		long int size = (endOff - startOff);
		char* bytes = malloc(size * sizeof(char));

		sprintf(tempstr, "/proc/%s/mem", argv[1]);
		newfp = fopen(tempstr, "r");
	
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		waitpid(pid, NULL, 0);

		fseek(newfp, startOff, SEEK_SET);
		fread(bytes, size, (endOff - startOff), newfp);
		
		//supposed to print contents of memory in hex format
		/*for (i = 0; i < size; i++)
		{
			printf("%02X", bytes[i]);
		}
		printf("\n");*/
		//supposed to print contents of memory in binary format
		//printBits(size, bytes);
		/*sprintf(tempstr, "python procEnum.py %s", bytes);
		system(tempstr);*/
		
		free(bytes);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		
		fclose(newfp);
	}
	
	return 0;
}
