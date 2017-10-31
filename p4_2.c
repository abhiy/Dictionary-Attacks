#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>

const char hash_pwd1[]={"bd17a274120510b73cc32a41d1eda0fc36ed458a"};
const char hash_pwd2[]={"73b64be4d4f6d838de43460c607805141875ff43"};
const char hash_pwd3[]={"fa54a2c671b251d64060f2776072bf48590abf2e"};

const char salt1[] = {"V0aFg83KN01xCFRosTJ5"};
const char salt2[] = {"GhP49SwLN21VdeSsERt1"};
const char salt3[] = {"NQe0P3ts18bSuNdAe13v"};

void computeHash(char* pwd, const char* salt, unsigned char* buf){
	int i;
	char salt_pwd[100];
	strcpy(salt_pwd, salt);
	strcat(salt_pwd, pwd);

	unsigned char temp[SHA_DIGEST_LENGTH];
    memset(temp, 0x0, SHA_DIGEST_LENGTH);
    SHA1((unsigned char *)salt_pwd, strlen(salt_pwd), temp);

    for (i=0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
    }
}

char* dictAttack(FILE *fp, const char* salt, const char* hash_pwd){
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

		computeHash(pwd, salt, buf);

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
	fp = fopen("10kpwds.txt", "r");
	if(fp == NULL){
		printf("Couldn't open file, retry\n");
		exit(0);
	}

	start = clock();
	printf("The 1st password is: %s", dictAttack(fp, salt1, hash_pwd1));
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Time taken to crack the password: %f seconds\n", cpu_time_used);

	start = clock();
	printf("The 2nd password is: %s", dictAttack(fp, salt2, hash_pwd2));
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Time taken to crack the password: %f seconds\n", cpu_time_used);

	start = clock();
	printf("The 3rd password is: %s", dictAttack(fp, salt3, hash_pwd3));
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Time taken to crack the password: %f seconds\n", cpu_time_used);
}