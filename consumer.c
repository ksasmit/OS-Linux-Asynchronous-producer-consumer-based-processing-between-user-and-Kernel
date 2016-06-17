#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>
/**
 * Header files for netLink socket opertaion
 */
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/sock.h>

#define NETLINK_USER 17
#define MAX_SIZE 80
#define MAX_PAYLOAD 1024 /* maximum payload size*/
// Structure for netlink socket return
struct net_link_ret {
	int id;
	int type; /* 0-int, 1- string*/
	char result[80];
	int size;
};


/**
 * all consumer related header files here only. They are not 
 * to be inlcuded else where 
 */
#include "sys_job.h"
#include "resource.h"
#include "operations.h"

struct sock *nl_sk = NULL;
asmlinkage extern long (*sysptr)(void *arg);
int send_data_to_user(int id, void *res, int size, int type, int pid)
{
	int ret = 0;
	struct net_link_ret nls_ret;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlmh = NULL;
	struct task_struct *t = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
	if (t == NULL || pid == 0) {
		printk(KERN_INFO "No such process %d exists\n", pid);
		return -ESRCH;
	}
	nls_ret.id = id;
	memset(&nls_ret.result, 0, MAX_SIZE);
	memcpy(&nls_ret.result, res, size);
	nls_ret.size = size;
	nls_ret.type = type;
	skb = alloc_skb(NLMSG_SPACE(MAX_PAYLOAD), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	ret = -EINVAL;
	nlmh = nlmsg_put(skb, 0, 0, 0, MAX_PAYLOAD,0);
	memcpy(NLMSG_DATA(nlmh), &nls_ret, 2*sizeof(struct net_link_ret));
	//pid = nlmh->nlmsg_pid;
	ret = netlink_unicast(nl_sk, skb, pid, 0);
	if (ret < 0)
		goto nlmsg_fail;
	return ret;
nlmsg_fail: /* Required by nlmsg_put */
	kfree_skb(skb);
	return ret;
}
asmlinkage long submitjob(void *arg) {
	int err = 0, q_len;
	SYS_JOB *job_packet = NULL;
	SYS_JOB *p_job = NULL;

	printk("submitjob received arg %p\n", arg);
	err = validate_job(arg);

	if (err != 0) {
		printk("validate_job failed\n");
		goto out;
	}

	job_packet = (SYS_JOB *) kzalloc(sizeof(SYS_JOB), 
		GFP_KERNEL);
	if (!job_packet) {
		printk(KERN_INFO "Insufficient memory\n");
		err = -ENOMEM;
		goto out;
	}

	// do copy from user here
	err = copy_userInput_to_kernel(arg, job_packet);
	if (err != 0)
		goto out;

#ifdef DEBUG	
	printk(KERN_INFO "job type: %d, infile: %s, ofile: %s, "
		"algo:%d\n", job_packet->job_type, job_packet->infile, 
		job_packet->outfile, job_packet->algo);
#endif

	// check if these are syncronous jobs, do them right away
	switch(job_packet->job_type){

	case LIST_JOBS:
		printk(KERN_INFO " LIST_JOBS called\n");
		// use arg as list needs to be returned, and allocation is done
		err = list_jobs(arg);
		if(err < 0){
			printk("LIST_JOBS Failed!!!!\n");
			err = -EFAULT;
			goto out;
		}
		printk(KERN_INFO "list_jobs Successfull!\n");
		goto out;
		break;
	// add remove and update priority here, 
	}

	
	/************************************************************************ 
	* remove a job from queue(change of mind)
	*************************************************************************/
	/* err = remove_job_id(&job_queue, job_packet->job_id);
	if (err == -1) {
		printk(KERN_INFO "Job with id: %d is not found.\n", job_packet->job_id);
		err = -EINVAL;
		goto out;
	} */

	
	// Asynchronous jobs, add to queue and exit
	/************************************************************************ 
	* Prepare to add job packet to queue, lock will be taken at queue.
	* do this only for jobs that are not list, delete or change proirity
	*************************************************************************/
	q_len = add_job(&job_queue, job_packet);
	if (q_len < 0) {
		printk(KERN_INFO "Job could not be scheduled for processing\n");
		err = -EBUSY;
		goto out;
	}

	/************************************************************************ 
	* fetch job from queue, dispatch for processing
	*************************************************************************/
	p_job = pick_job(&job_queue);
	if(!p_job){
		printk(KERN_INFO "Job could not be picked\n");
		err = -EBUSY;
		goto out;
	}

#ifdef DEBUG	
	printk(KERN_INFO "job type: %d, infile: %s, ofile: %s, jobid: %d, "
		"algo:%d\n", p_job->job_type, p_job->infile, 
		p_job->outfile, p_job->job_id, p_job->algo);
#endif

	// move this to consume function in consumer thread 
	/**********************************************************************
	* Dispatching for processing
	**********************************************************************/
	switch(p_job->job_type){

	case CHECKSUM:
		printk(KERN_INFO " Dispatching for Checksum\n");
		err = checksum(p_job->infile);
		if(err < 0){
			printk("Checksum Failed!!!!\n");
			err = -EFAULT;
			goto out;
		}
		printk(KERN_INFO "Checksum Successfull!\n");
		break;

	case COMPRESS:
		printk(KERN_INFO " Dispatching for Compression\n");
		err =  compress_file(p_job->infile, p_job->outfile);
		if(err < 0){
			printk("Compression Failed!!!!\n");
			err = -EFAULT;
			goto out;
		}
		printk(KERN_INFO "Compression Successfull!\n");

		break;

	case DECRYPT:
		printk(KERN_INFO " Dispatching for Decryption\n");
		err =  decrypt_file(p_job->infile, p_job->outfile, p_job->key, p_job->algo);
		if(err < 0){
			printk("****Decryption Failed!!!!\n");
			err = -EFAULT;
			goto out;
		}
		printk(KERN_INFO " Decryption Successfull!\n");
		break;

	case DECOMPRESS:
		printk(KERN_INFO " Dispatching for De-Compression\n");
		err =  decompress_file(p_job->infile, p_job->outfile);
		if(err < 0){
			printk("De-Compression Failed!!!!\n");
			err = -EFAULT;
			goto out;
		}
		printk(KERN_INFO "De-Compression Successfull!\n");

		break;

	case ENCRYPT:
		printk(KERN_INFO " Dispatching for Encryption\n");
		err =  encrypt_file(p_job->infile, p_job->outfile, p_job->key, p_job->algo);
		if(err < 0){
			printk("****Encryption Failed!!!!\n");
			err = -EFAULT;
			goto out;
		}
		printk(KERN_INFO " Encryption Successfull!\n");
		break;

	default:
		printk(KERN_INFO " wrong option given\n");
		break;

	}

	printk(KERN_INFO "Job with id: %d is done.\n", p_job->job_id);
	
out:

/*	err = num_to_str(msg, int size, err)
	if (!err)
		printk(KERN_INFO "num_to_str failed\n");*/
	//send_data_to_user(1/*job id*/, &err, sizeof(int), 0 /*type*/, 1 /*job pid*/);
	send_data_to_user(job_packet->job_id, &err, sizeof(int), 0 /*type*/, job_packet->process_id);
	if (job_packet)
		free_job(job_packet);
	return err;
}

void nls_callback(struct sk_buff *skb)
{
	struct nlmsghdr *nlmh = NULL;
	if (skb == NULL) {
		printk(KERN_INFO "skb is NULL\n");
		return ;
	}
	nlmh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "%s: received netlink message payload: %s\n",
		__func__, (char *) NLMSG_DATA(nlmh));
}
static int __init init_sys_submitjob(void) {
	/* initialize mutex to unlocked state */
	mutex_init(&queue_lock);

	if (sysptr == NULL){
		sysptr = submitjob;
		struct netlink_kernel_cfg cfg = {
			.input = nls_callback,
		};

		nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
		//nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0,nls_callback, NULL, THIS_MODULE);
		if(!nl_sk){
			printk(KERN_ALERT "Error creating socket.\n");
			return -10;
		}
	}
	return 0;
}

static void  __exit exit_sys_submitjob(void) {
	
	struct list_head *pos, *q;

	mutex_destroy(&queue_lock);

	/* destroy the job queue */
	list_for_each_safe(pos, q, &job_queue) {
		 //tmp = list_entry(pos, QUEUE_NODE, list);
		 list_del(pos);
	}

	if (sysptr != NULL){
		
		sock_release(nl_sk->sk_socket);
		sysptr = NULL;
	}
	printk("removed sys_submitjob module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);

MODULE_LICENSE("GPL");
