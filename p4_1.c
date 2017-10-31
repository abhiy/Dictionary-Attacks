#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>

#define SHA_DIGEST_LENGTH 20

const char hash_pwd[]={"c604b40452110ca7b432ea2d51867f774ea4eb60"};

void computeHash(char* line, char* buf){
	int i;
    unsigned char temp[SHA_DIGEST_LENGTH];
    memset(temp, 0x0, SHA_DIGEST_LENGTH);
    SHA1((unsigned char *)line, strlen(line), temp);
    for (i=0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
    }
}

char* dictAttack(FILE *fp, const char* hash_pwd){
	rewind(fp);
	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	int i;
	while ((read = getline(&line, &len, fp)) != -1) {
		char buf[SHA_DIGEST_LENGTH*2];

		//Trimming out the newline character
		char pwd[100];
		strcpy(pwd, line);
		pwd[strlen(line)-2] = '\0';

		computeHash(pwd, buf);

		if(strncmp(buf, hash_pwd, 2*SHA_DIGEST_LENGTH) == 0){
			printf("Password found\n");
			return line;
		}
    }
    printf("Password not found\n");
    return "";
}

int main(){
	clock_t start, end;
	double cpu_time_used;

	FILE* fp;
	int i;
	fp = fopen("10kpwds.txt", "r");
	if(fp == NULL){
		printf("Couldn't open file, retry\n");
		exit(0);
	}

	start = clock();
	printf("The password is: %s", dictAttack(fp, hash_pwd));
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Time taken to crack the password: %f seconds\n", cpu_time_used);
}