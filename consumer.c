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
#include <linux/kthread.h>
#include <linux/delay.h>

/**
 * all consumer related header files here only. They are not
 * to be inlcuded else where
 */
#include "sys_job.h"
#include "resource.h"
#include "operations.h"

int do_work(SYS_JOB *p_job)
{
	int err = 0;
	int validate_outfile = 1;

	if (p_job == NULL)
		return -EINVAL;
	/* printk("\n inputfile: %s\n", p_job->infile);
	   printk("\n outputfile: %s\n", p_job->outfile);
    */
	if (p_job->job_type == CHECKSUM)
		validate_outfile = 0;

	/* check if output and input file are valid */
	err = check_file_validity(p_job->infile,
					p_job->outfile, validate_outfile);
	if (err != 0) {
		printk(KERN_INFO "file validation failed!\n");
		goto out;
	}

	/**********************************************************************
	* Dispatching for processing
	**********************************************************************/
	switch (p_job->job_type) {

	case CHECKSUM:
		printk(KERN_INFO " Dispatching for Checksum for job id %d\n"
				, p_job->job_id);
		err = checksum(p_job->infile);
		if (err < 0) {
			printk("Checksum Failed!!!!\n");
			goto out;
		}
		/* printk(KERN_INFO "after Checksum for job id %d\n",
			p_job->job_id); */
		printk(KERN_INFO "Checksum Successfull!\n");
		break;

	case COMPRESS:
		printk(KERN_INFO " Dispatching for Compression\n");
		err =  compress_file(p_job->infile, p_job->outfile);
		if (err < 0) {
			printk("Compression Failed!!!!\n");
			goto out;
		}
		printk(KERN_INFO "Compression Successfull!\n");

		break;

	case DECRYPT:
		printk(KERN_INFO " Dispatching for Decryption\n");
		err =  decrypt_file(p_job->infile, p_job->outfile,
			p_job->key, p_job->algo);
		if (err < 0) {
			printk("****Decryption Failed!!!!\n");
			goto out;
		}
		printk(KERN_INFO " Decryption Successfull!\n");
		break;

	case DECOMPRESS:
		printk(KERN_INFO " Dispatching for De-Compression\n");
		err =  decompress_file(p_job->infile, p_job->outfile);
		if (err < 0) {
			printk("De-Compression Failed!!!!\n");
			goto out;
		}
		printk(KERN_INFO "De-Compression Successfull!\n");

		break;

	case ENCRYPT:
		printk(KERN_INFO " Dispatching for Encryption\n");
		err =  encrypt_file(p_job->infile, p_job->outfile,
			p_job->key, p_job->algo);
		if (err < 0) {
			printk("****Encryption Failed!!!!\n");
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
	msleep(5000);
	return err;
}

int consume (void *arg)
{
	SYS_JOB *p_job = NULL;
	int err = 0;
	SYS_JOB temp = {0};
	struct netlink_kernel_cfg cfg = {
		.input = nls_callback,
	};

consumption_start:
	p_job = NULL;
	err = 0;
	memset(&temp, 0, sizeof(SYS_JOB));
	/* // rmmod requested */
	mutex_lock(&queue_lock);
	if (stop_consumption) {
		atomic_set(&consumer_flag, 1);
		wake_up_interruptible(&consumer_wq);
		mutex_unlock(&queue_lock);
		goto kill_self;
	}
	mutex_unlock(&queue_lock);

	printk(KERN_INFO "Consumer awake: %s (%d)\n",
		current->comm, current->pid);
	/* // check if there is work to be done? */
	mutex_lock(&queue_lock);
	if ((curr_queue_length == 0) || stop_consumption) {
		if (curr_queue_length == 0)
			atomic_set(&consumer_flag, 0);

		if (stop_consumption) {
			atomic_set(&consumer_flag, 1);
			wake_up_interruptible(&consumer_wq);
			mutex_unlock(&queue_lock);
			goto kill_self;
		}
		mutex_unlock(&queue_lock);
		printk(KERN_INFO "Consumer thread %s (%d) being added "
			"to waitqueue\n", current->comm, current->pid);
		wait_event_interruptible(consumer_wq,
			atomic_read(&consumer_flag) == 1);
		goto consumption_start;
	}


	/**********************************
	* fetch job from queue, dispatch for processing
	**********************************/
	p_job = pick_job(&job_queue);
	if (p_job != NULL) {
		temp.job_id = p_job->job_id;
		temp.job_type = p_job->job_type;
		temp.process_id = p_job->process_id;
		memcpy(&temp.key, p_job->key, DIGEST_SIZE);
		temp.infile = kmalloc(strlen(p_job->infile) + 1, GFP_KERNEL);
		if (temp.infile == NULL) {
			mutex_unlock(&queue_lock);
			err = -ENOMEM;
			goto clean_temp;
		}
		memset(temp.infile, 0, strlen(p_job->infile) + 1);
		memcpy(temp.infile, p_job->infile, strlen(p_job->infile));
		if (temp.job_type != CHECKSUM) {
			temp.outfile = kmalloc(strlen(p_job->outfile) + 1,
							GFP_KERNEL);
			if (temp.outfile == NULL) {
				mutex_unlock(&queue_lock);
				err = -ENOMEM;
				goto clean_temp;
			}
			memset(temp.outfile, 0, strlen(p_job->outfile) + 1);
			memcpy(temp.outfile, p_job->outfile,
					strlen(p_job->outfile));
		}
	}
	free_job(p_job);
	mutex_unlock(&queue_lock);

	if (temp.job_id != 0) {
		if (waitqueue_active(&producer_wq)) {
			atomic_set(&producer_flag, 1);
			wake_up_interruptible(&producer_wq);
		}
		printk(KERN_INFO "Consumer %s (%d) start processing job %d\n",
				current->comm, current->pid, temp.job_id);
#ifdef DEBUG
		printk(KERN_INFO "job type: %d, infile: %s, ofile:\
		%s, jobid: %d, "
			"algo:%d\n", temp.job_type, temp.infile,
			temp.outfile, temp.job_id, temp.algo);
#endif
		err = do_work(&temp);
	}

	mutex_lock(&queue_lock);
	if (!stop_consumption) {
		send_netlink_msg_to_user(temp.job_id, &err,
			sizeof(int), 0,
			temp.process_id, temp.job_type);
	} else {
		printk("\nrmmod is done\n");
		nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
		if (!nl_sk) {
			printk(KERN_ALERT "Error creating socket.\n");
			goto socket_failure;
		}
		send_netlink_msg_to_user(temp.job_id, &err,
			sizeof(int), 0,
			temp.process_id, temp.job_type);
		sock_release(nl_sk->sk_socket);
	}
socket_failure:
	mutex_unlock(&queue_lock);

clean_temp:
	if (temp.infile)
		kfree(temp.infile);
	if (temp.outfile)
		kfree(temp.outfile);
	memset(&temp, 0, sizeof(SYS_JOB));

	mutex_lock(&queue_lock);
	if (!stop_consumption) {
		mutex_unlock(&queue_lock);
		wait_event_interruptible(consumer_wq,
			atomic_read(&consumer_flag) == 1);
		goto consumption_start;
	} else {
		atomic_set(&consumer_flag, 1);
		wake_up_interruptible(&consumer_wq);
	}
	mutex_unlock(&queue_lock);
kill_self:
	printk(KERN_INFO "Killing consumer %s (%d)\n",
		current->comm, current->pid);
	do_exit(0);
}

asmlinkage long submitjob(void *arg)
{
	int err = 0;
	SYS_JOB *job_packet = NULL;
	int inform_producer = -EIDRM;

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

	err = copy_userInput_to_kernel(arg, job_packet);
	if (err != 0) {
		printk(KERN_INFO "error after %d\n", err);
		goto out;
	}

#ifdef DEBUG
	printk(KERN_INFO "job type: %d, infile: %s, ofile: %s, "
		"algo:%d\n", job_packet->job_type, job_packet->infile,
		job_packet->outfile, job_packet->algo);
#endif

	/**
	 * check if these are syncronous jobs,
	 * do them right away. The job packet
	 * requesting these tasks in kernel space
	 *	must be freed always: be it
	 * failure or success as it never goes
	 *	into job_queue. It queries or
	 * modifies the existing queue items.
	 */
	switch (job_packet->job_type) {

	case LIST_JOBS:
		/*printk(KERN_INFO " LIST_JOBS called\n");
		 use arg as list needs to be returned,
		 and allocation is done */
		err = list_jobs(arg);
		if (err < 0) {
			printk("LIST_JOBS Failed!!!!\n");
			goto out;
		}
		printk(KERN_INFO "list_jobs Successfull!\n");
		goto out;
		break;

	case CHANGE_PRIORITY:
		/* //printk(KERN_INFO "CHANGE_PRIORITY called\n"); */
		err = change_job_priority(&job_queue, job_packet->job_id,
			job_packet->priority);
		if (err < 0) {
			printk(KERN_INFO "Job priority not changed.\n");
			goto out;
		}
		printk(KERN_INFO "Changed priority job_id %d successfully.\n",
			job_packet->job_id);

		goto out;
		break; /* trivial here but following convention */

	case DELETE_JOB:
		/* //printk(KERN_INFO "DELETE_JOB called\n"); */
		err = remove_job_id(&job_queue, job_packet->job_id);
		if (err < 0) {
			printk(KERN_INFO "Job with id: %d is not found.\n",
				job_packet->job_id);
			goto out;
		}
		printk(KERN_INFO "Deleted job with id: %d successfully.\n",
			job_packet->job_id);
		send_netlink_msg_to_user(job_packet->job_id,
			&inform_producer, sizeof(int), 0,
			job_packet->process_id, job_packet->job_type);
		goto out;
		break;
	case FLUSH_JOBS:
		/* //printk(KERN_INFO "FLUSH_JOBS called\n"); */
		err = flush_job_queue(&job_queue);
		if (err < 0) {
			printk(KERN_INFO "Job queue could not be flushed..\n");
			goto out;
		}
		printk(KERN_INFO "Flushed job queue successfully.\n");
		atomic_set(&producer_flag, 1);
		wake_up_interruptible(&producer_wq);
		goto out;
		break;
	}

wait_for_producers_to_flush:
	mutex_lock(&queue_lock);
	if (waitqueue_active(&producer_wq) && flush_producers) {
		printk("\nwaiting for waitqueue flush!!\n");
		mutex_unlock(&queue_lock);
		goto wait_for_producers_to_flush;
	} else {
		flush_producers = 0;
		/* /printk("\nflush_producers = 0\n"); */
		mutex_unlock(&queue_lock);
	}

try_again:
	mutex_lock(&queue_lock);
	if (stop_consumption || flush_producers) {
		mutex_unlock(&queue_lock);
		/* //printk("getting flushed %d", flush_producers); */
		return -EIDRM;
	}
	if (curr_queue_length >= MAX_QUEUE_LENGTH) {
		if (producers_in_waitqueue >= NUM_CONSUMERS*5) {
			mutex_unlock(&queue_lock);
			printk("\nwaitqueue full!!\n");
			return -EAGAIN;
		}

		producers_in_waitqueue++;
		mutex_unlock(&queue_lock);
		atomic_set(&producer_flag, 0);
		wait_event_interruptible(producer_wq,
					atomic_read(&producer_flag) == 1);
		mutex_lock(&queue_lock);
		producers_in_waitqueue--;
		mutex_unlock(&queue_lock);
		goto try_again;
	}

	/****************************************************
	* Prepare to add job packet to queue, lock will be taken at queue.
	* do this executes only for jobs that are not list, delete or change
	* proirity
	*****************************************************/
	err = add_job(&job_queue, job_packet);
	mutex_unlock(&queue_lock);
	if (err < 0) {
		printk(KERN_INFO "Job not scheduled for processing\n");
		goto out;
	}

	err = copy_to_user(&((SYS_JOB *)arg)->job_id,
					&job_packet->job_id, sizeof(int));
	/* //printk(KERN_INFO "Job id to user %d  job id
		at kernel %d\n",
		((SYS_JOB *)arg)->job_id, job_packet->job_id); */
	if (err < 0) {
		printk(KERN_INFO "Error in copying job_id to user space\n");
		goto out;
	}

out:
	if (err >= 0 && (job_packet->job_type != LIST_JOBS
				  && job_packet->job_type != CHANGE_PRIORITY
				  && job_packet->job_type != DELETE_JOB
				  && job_packet->job_type != FLUSH_JOBS)) {
		if (waitqueue_active(&consumer_wq)) {
			atomic_set(&consumer_flag, 1);
			wake_up_interruptible(&consumer_wq);
		}
	} else {
		if (job_packet)
			free_job(job_packet);
	}

	return err;
}

/* see we can change this a bit!!! */
void kill_consumers(void)
{
	atomic_set(&consumer_flag, 1);
	wake_up_interruptible(&consumer_wq);
	atomic_set(&producer_flag, 1);
	wake_up_interruptible(&producer_wq);
}

static int __init init_sys_submitjob(void)
{
	int i = 0;
	int ret = 0;
	/* // Create netlink socket for user-kernel communication */
	struct netlink_kernel_cfg cfg = {
		.input = nls_callback,
	};
	/* initialize mutex to unlocked state */
	mutex_init(&queue_lock);
	if (sysptr == NULL) {
		sysptr = submitjob;

		INIT_LIST_HEAD(&job_queue);
		curr_queue_length = 0;
		stop_consumption = 0;
		producers_in_waitqueue = 0;

		/* // wait queues */
		init_waitqueue_head(&producer_wq);
		init_waitqueue_head(&consumer_wq);
		atomic_set(&producer_flag, 0);
		atomic_set(&consumer_flag, 0);

		nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
		if (!nl_sk) {
			printk(KERN_ALERT "Error creating socket.\n");
			return -10;
		}

		/* consumer threads spawning*/
		for (i = 0; i < NUM_CONSUMERS; i++) {
			consumers[i] = kthread_create(consume, NULL,
						"consumer_%d", i);

			if (IS_ERR(consumers[i])) {
				printk(KERN_ERR "Thread not created\n");
				ret = PTR_ERR(consumers[i]);
				consumers[i] = NULL;
				goto error;
			}
		}

		for (i = 0; i < NUM_CONSUMERS; i++)
				wake_up_process(consumers[i]);
	}
error:
	if (ret) {
		/* kill the spawned threads if error occured*/
		for (i = 0; NUM_CONSUMERS; i++) {
			if (consumers[i] != NULL)
				kthread_stop(consumers[i]);
		}

		sock_release(nl_sk->sk_socket);
	}
	return ret;
}

static void  __exit exit_sys_submitjob(void)
{

	struct list_head *pos, *q;
	QUEUE_NODE *temp_node = NULL;
	int inform_producer = -EIDRM;

	mutex_lock(&queue_lock);

	/* destroy the job queue */
	list_for_each_safe(pos, q, &job_queue) {
		temp_node = list_entry(pos, QUEUE_NODE, list);

		/* // inform proceses waiting on these jobs */
		send_netlink_msg_to_user(temp_node->job_packet->job_id,
					&inform_producer, sizeof(int), 0,
					temp_node->job_packet->process_id,
					temp_node->job_packet->job_type);

		free_job(temp_node->job_packet);
		list_del(pos);
	}
	curr_queue_length = 0;
	curr_queue_length++;
	stop_consumption = 1;
	sock_release(nl_sk->sk_socket);
	mutex_unlock(&queue_lock);

	kill_consumers();

	while (waitqueue_active(&consumer_wq) ||
			waitqueue_active(&producer_wq))
		msleep(1000);


	if (sysptr != NULL) {
		sysptr = NULL;
	}
	printk("removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
