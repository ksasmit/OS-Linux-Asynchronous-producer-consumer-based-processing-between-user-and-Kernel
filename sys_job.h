/*
  sys_job.h header file
  Contains the structure definition for the void pointer we pass to system call.
  This acts like a contract between the kernel and the user program
*/

#define EXTRA_CREDIT
#define DEBUG
#define KEYLENGTH_MIN 6

/* types of job */
#define CHECKSUM   1
#define ENCRYPT    2
#define DECRYPT    3
#define COMPRESS   4
#define DECOMPRESS 5
//#define CONCATENATE 6 

#define LIST_JOBS  7
#define CHANGE_PRIORITY 8
#define DELETE_JOB 9
/* This defines capacity of job queue. To be fixed */
#define QUEUE_LENGTH 10 

/* types of checksum */
#define CRC32   1
#define MD5     2

/* types of encryption */
#define AES      1
#define BLOWFISH 2

#define HIGH_PRIORITY 1
#define LOW_PRIORITY 0

/****** standard Digest length********/
#define DIGEST_SIZE 16

/* job structure */
typedef struct _SYS_JOB {
	pid_t process_id;/* process id */
	int   job_type;  /* type of job */
	int   algo;      /* subtype or algorithm for job */
	int   job_id;    /* job_id */
	int   priority;  /* priority of job, default 0 */ 
	char  key[16];      /* passkey for encryption */
	int   keyLength; /* length of key hash */
	char  *infile;   /* input file name */
	char  *outfile;  /* output file name */
} SYS_JOB;
