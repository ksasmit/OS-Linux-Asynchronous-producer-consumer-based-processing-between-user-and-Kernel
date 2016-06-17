#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>


#include "sys_job.h"
#define __NR_submitjob 359
#ifndef __NR_submitjob
#error submitjob system call not defined
#endif
/**
 * Below header files for establishing Netlink socket connection
 */
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <linux/types.h>
#define NETLINK_USER 17

#define MAX_PAYLOAD 1024 /* maximum payload size*/

// Structure for netlink socket return
struct net_link_ret {
	int id;
	int job_type;
	int type; /* 0-int, 1- string*/
	char result[80];
	int size;
} nls_ret;

	struct nlmsghdr *nlh = NULL;
	int sock_fd= 0;
	struct msghdr msg;
// Structure to store user inputs
typedef struct _USER_INPUT
{
	int  encrypt;      // set if encryption is requested.
	int  decrypt;      // set if decryption is requested.
	int  checksum;     // set if checksum is requested.
	int  compress;     // set if compress is requested.
	int  decompress;   // set if decompress is requested.
	int  list;         // set if list all jobs
	int  delete;       // set if delete a job
	int  flush;        //  set if flush all jobs
	int  modify;       // set if modify a job
	int  new_priority; // set if new_priority a job
	// NOTE: only one of the above should be set at a time.

	int  job_id;  // store job id to delete/modify	
	int  algoSpecified; // set if algo type is passed. If not, we use to default.
	int  passwordSpecified; // set if password is passed.
	char *algoType; // the name of the cipher requested.
	// need to check this against supported ciphers list for validation.
	char *password;   // the human readable password string. use getpass(3) in future to read passwords.				  
	char *priority;  // new priority
	char *inputFile;  // inputFile name.
	char *outputFile; // outputFile name.
} USER_INPUT;
	USER_INPUT userInput;
void *print_message_function()
{	int kern_ret = 0;
		if(!userInput.list && !userInput.flush && !userInput.modify && !userInput.new_priority &&  !userInput.delete){
		memset(nlh, 0, MAX_PAYLOAD);
		kern_ret = recvmsg(sock_fd, &msg, 0);
		printf("Message received from the kernel for process id = %d through netlink: %d\n", kern_ret, getpid());
		memcpy(&nls_ret, NLMSG_DATA(nlh), sizeof(struct net_link_ret));
		if (nls_ret.type == 0)
			printf("Received netlink message:Job id = %d Job type: %d and return = %d\n", nls_ret.id, nls_ret.job_type, (int)*(nls_ret.result));
	}
     printf("Returning from the thread \n");
return NULL;
}

/*
   This function uses getopt() and parses the given options.
   It fills up the options structure which is then used to invoke the system call.
 */
int parse_input(USER_INPUT *userInput, int argc, char **argv)
{
	int input_arg = 0;
	int errorFlag = 0;

	while ((input_arg = getopt(argc, argv, "edcuslfr:m:n:a:p:h")) != -1)
	{
		switch (input_arg)
		{
		case 'e':
			userInput->encrypt = 1; // encryption
			break;
		case 'd':
			userInput->decrypt = 1; // decryption
			break;
		case 'c':
			userInput->compress = 1; // compress
			break;
		case 'u':
			userInput->decompress = 1; // decompress
			break;
		case 's':
			userInput->checksum = 1; // checksum
			break;
		case 'l':
			userInput->list = 1; // list
			break;
		case 'f':
			userInput->flush = 1; // flush
			break;
		case 'r':
			userInput->delete = 1; // delete
			userInput->job_id = atoi(optarg);
			break;
		case 'm':
			userInput->modify = 1; // modify
			userInput->job_id = atoi(optarg);
			break;
		case 'n':
			userInput->new_priority = 1; // modify
			userInput->priority = optarg;
			break;
		case 'a':
			if (userInput->algoSpecified)
			{
				errorFlag = 1;
				break;				
			}
			userInput->algoSpecified = 1;
			userInput->algoType = optarg; // algo type
			break;
		case 'p':
			if (userInput->passwordSpecified)
			{
				errorFlag = 1;
				break;				
			}
			userInput->passwordSpecified = 1;
			userInput->password = optarg;
			break;
		case 'h': // help
			printf("Usage: %s -edcuslf -p Password [-r job_id] [-a ALGO_TYPE] [-m job_id] [-n new priority] infile outfile\n", argv[0]);
			printf("-e = encrypt, -d = decrypt, -c = compress, -u = uncompress, -s = checksum, -l = list, -f = flush all jobs, -r = remove a job -m = modify job priority, -n = new priority with -m\n");
			printf("-a : Optional, to choose algorithm. Default for encryption: AES, for Checksum: CRC32\n");
			printf("-p : password to encrypt/ decrypt the file\n");
			printf("-h : display help message\n");
			printf("infile  : input file name\n");
			printf("outfile : output file name\n");
			return 1;
		default: // unknown param
			errorFlag = 1;
		}
	}

	if ((errorFlag == 1) || ((argc != (optind + 2)) && !(userInput->list ||
					userInput->flush ||
					userInput->delete || 
					userInput->modify || 
					userInput->checksum)))//unknown or insufficient or extra argument passed
	{
		printf("Usage: %s -edcuslf -p Password [-r job_id] [-a ALGO_TYPE] [-m job_id] [-n new priority] infile outfile\n", argv[0]);
		printf("-h : display help message\n");
		return -1;
	}
	else if (!(userInput->list || userInput->flush || userInput->delete || userInput->modify || userInput->checksum))
	{
		userInput->inputFile  = argv[optind];
		userInput->outputFile = argv[optind + 1];
		return 0;
	}
	else if (userInput->checksum && (argc != (optind + 1)))
	{
		return -1;
	}
	else if (userInput->checksum)
	{
		userInput->inputFile  = argv[optind];
		return 0;
	}

	return 0;
}

/*
   This function is used to validate the user input.
   We can add several input validation as requirement changes.
   Below are the validation for USER_INPUT
 */
int validate_input(USER_INPUT *userInput)
{
	// we cant have both d and e together
	if ((userInput->encrypt == 1) && (userInput->decrypt == 1))
	{
		printf("Both e and d speciified together!\n");
		return -1;
	}

	if ((userInput->decompress == 1) && (userInput->compress == 1))
	{
		printf("Both u and c speciified together!\n");
		return -1;
	}

	if (((userInput->decompress == 1) && (userInput->encrypt == 1)) || 
		((userInput->decompress == 1) && (userInput->decrypt == 1)) ||
		((userInput->compress == 1)   && (userInput->encrypt == 1)) ||
		((userInput->compress == 1)   && (userInput->decrypt == 1)) ||
		((userInput->checksum == 1)   && (userInput->decrypt == 1)) ||
		((userInput->checksum == 1)   && (userInput->encrypt == 1)) ||
		((userInput->checksum == 1)   && (userInput->compress == 1)) ||
		((userInput->checksum == 1)   && (userInput->decompress == 1)) ||
		((userInput->list == 1) && (userInput->encrypt == 1)) || 
		((userInput->decompress == 1) && (userInput->list == 1)) ||
		((userInput->delete == 1)   && (userInput->encrypt == 1)) ||
		((userInput->compress == 1)   && (userInput->delete == 1)) ||
		((userInput->checksum == 1)   && (userInput->list == 1)) ||
		((userInput->checksum == 1)   && (userInput->delete == 1)) ||
		((userInput->list == 1)   && (userInput->compress == 1)) ||
		((userInput->delete == 1)   && (userInput->decompress == 1)) ||
		((userInput->delete == 1)   && (userInput->list == 1))||
		((userInput->modify == 1)   && (userInput->encrypt == 1)) ||
		((userInput->modify == 1)   && (userInput->decrypt == 1)) ||
		((userInput->compress == 1)   && (userInput->modify == 1)) ||
		((userInput->checksum == 1)   && (userInput->modify == 1)) ||
		((userInput->modify == 1)   && (userInput->delete == 1))||
		((userInput->modify == 1)   && (userInput->decompress == 1)) ||
		((userInput->modify == 1)   && (userInput->list == 1)) ||
		((userInput->new_priority == 1)   && (userInput->list == 1))||
		((userInput->new_priority == 1)   && (userInput->flush == 1))||
		((userInput->new_priority == 1)   && (userInput->delete == 1)) ||
		((userInput->flush == 1)   && (userInput->decrypt == 1)) ||
		((userInput->flush == 1)   && (userInput->encrypt == 1)) ||
		((userInput->flush == 1)   && (userInput->compress == 1)) ||
		((userInput->flush == 1)   && (userInput->decompress == 1)) ||
		((userInput->flush == 1)   && (userInput->checksum == 1)) ||
		((userInput->flush == 1)   && (userInput->list == 1)) ||
		((userInput->flush == 1)   && (userInput->delete == 1)) ||
		((userInput->flush == 1)   && (userInput->modify == 1)))
	{
		printf("multiple operations speciified together!\n");
		return -1;
	}

	// no password failure
	if (((userInput->encrypt == 1) || (userInput->decrypt == 1)) && userInput->passwordSpecified == 0)
	{
		printf("No password passed!\n");
		return -1;
	}

	if (((userInput->modify == 1) && !(userInput->new_priority == 1)))
	{
		printf("modify and priority not passed correctly!\n");
		return -1;
	}

	if (userInput->new_priority == 1)
	{
		if(strcmp(userInput->priority, "high") && strcmp(userInput->priority, "low"))
		{
			printf("Invalid priority!\n");
			return -1;
		}
	}

	// password should atleast be 6 char long
	if (((userInput->encrypt == 1) || (userInput->decrypt == 1)) && strlen(userInput->password) < KEYLENGTH_MIN)
	{
		printf("Password too short!\n");
		return -1;
	}

	if (userInput->algoSpecified)
	{
		if ((userInput->encrypt == 1) || (userInput->decrypt == 1))
		{
			if (strcmp(userInput->algoType, "aes") && strcmp(userInput->algoType, "blowfish"))
			{
				printf("Invalid Algorithm!\n");
				return -1;
			}
		}

		if (userInput->checksum == 1)
		{
			if (strcmp(userInput->algoType, "md5") && strcmp(userInput->algoType, "crc32"))
			{
				printf("Invalid Algorithm!\n");
				return -1;
			}
		}
	}
	else
	{
		if ((userInput->encrypt == 1) || (userInput->decrypt == 1))
		{
			userInput->algoType = "aes";
		}

		if (userInput->checksum == 1)
		{
			userInput->algoType = "crc32";
		}	
	}

	return 0;
}

int main(int argc, char *argv[])
{
	pthread_t thread1;
	int status = 0;
	int c =0;
	//int kern_ret = 0;
	int iret;
	//USER_INPUT userInput;
	unsigned char password[SHA_DIGEST_LENGTH];
	int passwordLength = 0;
	SYS_JOB *sysJobArg = NULL;
	SYS_JOB sysJob;
	memset(&userInput, 0, sizeof(USER_INPUT));
	struct sockaddr_nl src_addr, dest_addr;
	//struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	//int sock_fd;
	//struct msghdr msg;
	sock_fd=socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(sock_fd<0)
		return -1;

	memset(&src_addr, 0, sizeof(src_addr));// src - user 
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pad = 0;
	src_addr.nl_pid = getpid();

	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr)); //dest - kernel
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 1;
	nlh->nlmsg_type = 0;

	strcpy(NLMSG_DATA(nlh), "Hello");

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	iret = pthread_create( &thread1, NULL, *print_message_function,NULL);
     if(iret)
     {
         printf("Error - pthread_create() return code: %d\n",iret);
         exit(EXIT_FAILURE);
     }

	// parse the user passed input
	status = parse_input(&userInput, argc, argv);
	if (status != 0)
	{
		if (status != 1)
		{
			printf("Input Parsing failed!\n");
			printf("Please use -h for usage help\n");
			return status;
		}
		return 0; // we came here as -h was passed
	}

	// validate the user passed input
	status = validate_input(&userInput);
	if (status != 0)
	{
		printf("Input validation failed!\n");
		printf("Please check the input passed for errors\n");
		return status;
	}

	// fill the syscall structure to be passed
	memset(&sysJob, 0, sizeof(sysJob));
	sysJobArg = &sysJob;

	if (userInput.passwordSpecified)
	{
		passwordLength = strlen(userInput.password);
		SHA1((const unsigned char *)userInput.password, passwordLength, password);
		password[DIGEST_SIZE]=0;
		strcpy(sysJob.key,(const char *)password);	
		sysJob.keyLength = strlen(sysJob.key);
		printf("Key = %s, KeyLength = %d\n", sysJob.key, sysJob.keyLength); 
	}

	sysJob.process_id = getpid();

	if (userInput.encrypt)
	{
		sysJob.job_type = ENCRYPT;
		if (strcmp(userInput.algoType, "aes"))
			sysJob.algo = AES;
		else
			sysJob.algo = BLOWFISH;
	} 
	else if (userInput.decrypt)
	{
		sysJob.job_type = DECRYPT;
		if (strcmp(userInput.algoType, "aes"))
			sysJob.algo = AES;
		else
			sysJob.algo = BLOWFISH;
	}
	else if (userInput.compress)
	{
		sysJob.job_type = COMPRESS;
	}
	else if (userInput.decompress)
	{
		sysJob.job_type = DECOMPRESS;
	}
	else if (userInput.checksum)
	{
		sysJob.job_type = CHECKSUM;
		if (strcmp(userInput.algoType, "crc32"))
			sysJob.algo = CRC32;
		else
			sysJob.algo = MD5;
	}
	else if (userInput.list)
	{
		sysJobArg = (SYS_JOB*) malloc(sizeof(SYS_JOB) * MAX_QUEUE_LENGTH);
		sysJobArg->job_type = LIST_JOBS;
		// allocate job queue to read jobs
	}
	else if (userInput.delete)
	{
		sysJob.job_type = DELETE_JOB;
		sysJob.job_id = userInput.job_id;
	}
	else if (userInput.flush)
	{
		sysJob.job_type = FLUSH_JOBS;
	}
	else if (userInput.modify)
	{
		sysJob.job_type = CHANGE_PRIORITY;
		sysJob.job_id = userInput.job_id;
		if (!strcmp(userInput.priority, "high"))
			sysJob.priority = HIGH_PRIORITY;
		else 
			sysJob.priority = LOW_PRIORITY;
	}

	if (userInput.new_priority)
	{
		if (!strcmp(userInput.priority, "high"))
			sysJob.priority = HIGH_PRIORITY;
		else 
			sysJob.priority = LOW_PRIORITY;
	}

	if (!(userInput.list || userInput.flush || userInput.delete || userInput.modify))
	{
		sysJob.infile  = userInput.inputFile;
		if(!userInput.checksum)
			sysJob.outfile = userInput.outputFile;
	}

	// only priority during job submission itself??
	if(!userInput.list && !userInput.flush && !userInput.modify && !userInput.new_priority &&  !userInput.delete){
		printf("Sending message to kernel\n");
		sendmsg(sock_fd,&msg,0);
	}

	status = syscall(__NR_submitjob, (void *)sysJobArg);
	//sleep(20);
	if (status < 0) {
		printf("Error occured: %s\n", strerror(-status));
	}

	if(userInput.list)
	{
		int index;
		//print jobs here
		printf("\n number of jobs in queue: %d\n", status);
		for(index = 0; index < status; index++)
		{
			printf("| Job Id: %d |", sysJobArg[index].job_id);
			printf("Process id: %d |", sysJobArg[index].process_id);
			printf("Job Type: "); 
			switch(sysJobArg[index].job_type)
			{
				case ENCRYPT:
					printf("ENCRYPT    |");
					break;
				case DECRYPT:
					printf("DECRYPT    |");
					break;
				case CHECKSUM:
					printf("CHECKSUM   |");
					break;
				case COMPRESS:
					printf("COMPRESS   |");
					break;
				case DECOMPRESS:
					printf("DECOMPRESS |");
					break;
			}
			printf("Job Priority: ");
			switch(sysJobArg[index].priority)
			{
				case HIGH_PRIORITY:
					printf("HIGH_PRIORITY |");
					break;
				case LOW_PRIORITY:
					printf("LOW_PRIORITY  |");
					break;	
			}
			printf("\n");
		}
		if (sysJobArg)
			free(sysJobArg);
		sysJobArg = NULL;
	}
	// *if asynchronous jobs, wait, netlink
	// if list or delete, print job info
	c=1;
	sleep(5000);
	
	if (sysJobArg && !(userInput.list || userInput.flush || userInput.delete || userInput.modify))
	{
		printf("Job_id assigned is %d for process id = %d\n", sysJobArg->job_id, getpid());
	}

	/*****************************************************************
	  Netlink reception begins here
	 ******************************************************************/
/*	 
	if(!userInput.list && !userInput.flush && !userInput.modify && !userInput.new_priority &&  !userInput.delete){
		memset(nlh, 0, MAX_PAYLOAD);
		kern_ret = recvmsg(sock_fd, &msg, 0);
		printf("Message received from the kernel for process id = %d through netlink: %d\n", kern_ret, getpid());
		memcpy(&nls_ret, NLMSG_DATA(nlh), sizeof(struct net_link_ret));
		if (nls_ret.type == 0)
			printf("Received netlink message:Job id = %d Job type: %d and return = %d\n", nls_ret.id, nls_ret.job_type, (int)*(nls_ret.result));
	}
*/	
pthread_join( thread1, NULL);
	exit(status);
}
