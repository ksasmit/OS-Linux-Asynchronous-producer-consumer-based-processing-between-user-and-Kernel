/* This file defines all functios and definitions related
 * to job queue. You're free to add more functions as need arises
 * and is justified. These definitions are in infancy and will be
 * modified as development progresses */

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
/* Structure for netlink socket return */
struct net_link_ret {
	int id;
	int job_type;
	int type; /* 0-int, 1- string*/
	char result[80];
	int size;
};
struct sock *nl_sk = NULL;

void nls_callback(struct sk_buff *skb)
{
	struct nlmsghdr *nlmh = NULL;

	if (skb == NULL) {
		printk(KERN_INFO "skb is NULL\n");
		return;
	}
	nlmh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "%s: received netlink message payload: %s\n",
		__func__, (char *) NLMSG_DATA(nlmh));
}

asmlinkage extern long (*sysptr)(void *arg);

int send_netlink_msg_to_user(int id, void *res, int size, int type, int pid,
								int j_type)
{
	int ret = 0;
	struct net_link_ret nls_ret;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlmh = NULL;
	struct task_struct *t = pid_task(find_pid_ns(pid, &init_pid_ns),
	 PIDTYPE_PID);

	if (t == NULL || pid == 0) {
		printk(KERN_INFO "No such process %d exists\n", pid);
		return -ESRCH;
	}
	nls_ret.id = id;
	nls_ret.job_type = j_type;
	memset(&nls_ret.result, 0, MAX_SIZE);
	memcpy(&nls_ret.result, res, size);
	nls_ret.size = size;
	nls_ret.type = type;
	skb = alloc_skb(NLMSG_SPACE(MAX_PAYLOAD), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	ret = -EINVAL;
	nlmh = nlmsg_put(skb, 0, 0, 0, MAX_PAYLOAD, 0);
	memcpy(NLMSG_DATA(nlmh), &nls_ret, 2*sizeof(struct net_link_ret));

	ret = netlink_unicast(nl_sk, skb, pid, 0);
	if (ret < 0)
		goto nlmsg_fail;
	return ret;
nlmsg_fail: /* Required by nlmsg_put */
	kfree_skb(skb);
	return ret;
}

static LIST_HEAD(job_queue);
struct mutex queue_lock;

/**
 * Following pointer maintains the position where HIGH_PRIORITY
 * jobs are inserted in job_queue.
 */
static struct list_head *local_high_head;
static int curr_queue_length;
static int job_id_counter = 101;

static wait_queue_head_t producer_wq;
static wait_queue_head_t consumer_wq;
static atomic_t producer_flag = ATOMIC_INIT(0);
static atomic_t consumer_flag = ATOMIC_INIT(0);

#define NUM_CONSUMERS 5
static struct task_struct *consumers[NUM_CONSUMERS] = {NULL};

static int stop_consumption;
static int flush_producers;
static int producers_in_waitqueue;

/* job queue node, this is what gets attached to queue
 * when producer successfully submits job to
 * consumer */
typedef struct {
	struct list_head list;
	SYS_JOB *job_packet;
} QUEUE_NODE;

/**
 * Frees job_packet in case of deletion/ completion
 * of service request.
 * @param kernel_data: pointer to packet to be freed
 */
void free_job(SYS_JOB *kernel_data)
{
	if (kernel_data == NULL)
		return;

	if (kernel_data->infile)
		kfree(kernel_data->infile);
	if (kernel_data->outfile)
		kfree(kernel_data->outfile);
	if (kernel_data)
		kfree(kernel_data);
	return;
}

long list_jobs(SYS_JOB *arg)
{
	long status = 0;
	struct list_head *pos, *temp, *q;
	QUEUE_NODE *temp_node = NULL;
	int length = 0;

	mutex_lock(&queue_lock);
	q = &job_queue;

	if (list_empty(q))
		goto exit_final;

	list_for_each_safe(pos, temp, q) {
		temp_node = list_entry(pos, QUEUE_NODE, list);

		status = copy_to_user(&arg[length].job_id,
		&temp_node->job_packet->job_id, sizeof(int));
		if (status != 0) {
			printk(KERN_ALERT "failed to copy userData->job_id");
			goto exit_final;
		}

		status = copy_to_user(&arg[length].process_id,
		&temp_node->job_packet->process_id, sizeof(pid_t));
		if (status != 0) {
			printk(KERN_ALERT "failed to copy userData->process_id");
			goto exit_final;
		}

		status = copy_to_user(&arg[length].job_type,
		&temp_node->job_packet->job_type, sizeof(int));
		if (status != 0) {
			printk(KERN_ALERT "failed to copy userData->job_type");
			goto exit_final;
		}

		status = copy_to_user(&arg[length].algo,
		&temp_node->job_packet->algo, sizeof(int));
		if (status != 0) {
			printk(KERN_ALERT "failed to copy userData->algo");
			goto exit_final;
		}

		status = copy_to_user(&arg[length].priority,
		&temp_node->job_packet->priority, sizeof(int));
		if (status != 0) {
			printk(KERN_ALERT "failed to copy userData->priority\n");
			goto exit_final;
		}
		length++;
	}

	status = copy_to_user(&arg[0].keyLength,
	&length, sizeof(int));
	if (status != 0) {
		printk(KERN_ALERT "failed to copy length\n");
		goto exit_final;
	}

	status = 0;
exit_final:
	mutex_unlock(&queue_lock);
	return status;
}

/** Flush the job queue */
int flush_job_queue(struct list_head *q)
{
	int err = 0;
	struct list_head *pos, *temp;
	QUEUE_NODE *temp_node = NULL;
	int inform_producer = -EIDRM;

	mutex_lock(&queue_lock);

	/* If list is empty, no work is to be done */
	if (list_empty(q)) {
		printk(KERN_ALERT "Job queue is empty, operation aborted!\n");
		err = -ENODATA;
		goto out;
	}

	list_for_each_safe(pos, temp, &job_queue) {
		temp_node = list_entry(pos, QUEUE_NODE, list);
		send_netlink_msg_to_user(temp_node->job_packet->job_id,
			&inform_producer, sizeof(int), 0,
			temp_node->job_packet->process_id,
			temp_node->job_packet->job_type);
		free_job(temp_node->job_packet);
		list_del(pos);
	}
	curr_queue_length = 0;
	local_high_head = q;
	flush_producers = 1;
	atomic_set(&producer_flag, 1);

out:
	mutex_unlock(&queue_lock);
	return err;
}

/**
 * adds low priority job at the tail of queue and high priority job at
 * local_high_head of queue. If there are no low_priority jobs in queue,
 * local_high_head points to head of the queue.
 * Returns job_id on success and appropriate errno is set in case of
 * failure.
 */
long add_job(struct list_head *q, SYS_JOB *j)
{
	long err = 0;
	long queue_length;
	struct list_head *pos;
	QUEUE_NODE *new_queue_node = NULL;

	/* mutex_lock(&queue_lock); */

	/**
	 * set local high head to head of list. If the list is not empty, then
	 * there is no need to set it as it would have been set appropriately
	 * earlier.
	 */
	if (list_empty(q))
		local_high_head = q;

	/* TBD: find if there is inbuilt method to get length of list */
	queue_length = 0;
	list_for_each(pos, q)
		queue_length++;

#ifdef DEBUG
	printk(KERN_INFO "queue length before: %d\n", (int)queue_length);
#endif

	if (queue_length == MAX_QUEUE_LENGTH) {
		err = -EAGAIN;
		printk(KERN_ALERT "Job queue full, try again\n");
		goto out;
	}

	new_queue_node = (QUEUE_NODE *) kzalloc(sizeof(QUEUE_NODE), GFP_KERNEL);
	if (!new_queue_node) {
		printk(KERN_ALERT "Insufficient memory\n");
		err = -ENOMEM;
		goto out;
	}
	j->job_id = job_id_counter++;
	new_queue_node->job_packet = j;

	/* figure out place of insertion */
	if (new_queue_node->job_packet->priority == LOW_PRIORITY) {
		list_add_tail(&(new_queue_node->list), q);
		if (local_high_head == q)
			local_high_head = &(new_queue_node->list);
	}

	else if (new_queue_node->job_packet->priority == HIGH_PRIORITY) {
		list_add_tail(&(new_queue_node->list), local_high_head);
	}

	/* TBD: wake up/spawn at least one consumer thread */
	err = j->job_id;
	curr_queue_length++;
out:
    /* mutex_unlock(&queue_lock); */
	return err;
}

/**
 * removes and returns highest priority job from queue to caller. In case if
 * a low priority job has been waiting for longer than certain threashold,
 * it gets picked. This is to ensure fairness and to prevent starvation.
 * Mainly consumer gets served through this call. The job is picked from
 * either of the 2 heads (misleading but we maintained queue head/ local high
 * head to manage priorities in single queue).
 */
SYS_JOB *pick_job(struct list_head *q)
{
	SYS_JOB *j = NULL;
	QUEUE_NODE *temp_node_H = NULL; /* peeking into head */
	QUEUE_NODE *temp_node_LH = NULL; /* peeking into local_high_head */
	struct list_head *temp = NULL;

	/* mutex_lock(&queue_lock); */
	/**
	 * If list is empty, no work is to be done, put all consumers
	 * in sleep state
	 */
	if (list_empty(q)) {
		printk(KERN_ALERT "No jobs pending, sleep !\n");
		goto out;
	}

	temp_node_H = list_entry(q->next, QUEUE_NODE, list);
	if (local_high_head == q) {/* there are only HIGH_PRIORITY jobs in list */
		j = temp_node_H->job_packet;
#ifdef DEBUG
/*I want to hold LOW_PRIORITY jobs for debugging purpose.*/
		if (temp_node_H->job_packet->priority == LOW_PRIORITY)
			goto out;
#endif
		list_del(q->next);
	}
	else {
		temp_node_LH = list_entry(local_high_head, QUEUE_NODE, list);
		/**
		 * If executes when there are both types of jobs and LOW_PRIORITY one
		 * at local high head is starving.
		 */
		if (temp_node_H->job_packet->job_id - temp_node_LH->job_packet->job_id >
		WAIT_THRESHOLD) {
			j = temp_node_LH->job_packet;
			temp = local_high_head;
			local_high_head = temp_node_LH->list.next;
			list_del(temp);
		}
		/**
		 * Else executes when either there are only LOW_PRIORITY jobs or there
		 * are both types of jobs but no one is starving.
		 */
		else {
			j = temp_node_H->job_packet;
#ifdef DEBUG
/*I want to hold LOW_PRIORITY jobs for debugging purpose.*/
			if (temp_node_H->job_packet->priority == LOW_PRIORITY)
				goto out;
#endif
			if (&(temp_node_H->list) == local_high_head)
				local_high_head = temp_node_H->list.next;
			list_del(q->next);
		}
	}
	curr_queue_length--;

out:
	/* mutex_unlock(&queue_lock); */
	return j;
}

/**
 * Remove a job from a queue with specific job_id. Returns error number
 * if requested job is not found in the queue. On success, returns 0
 */
int remove_job_id(struct list_head *q, int job_id)
{
	int err = 0;
	struct list_head *pos, *temp;
	QUEUE_NODE *temp_node = NULL;

	mutex_lock(&queue_lock);

	/**
	 * If list is empty, no work is to be done.
	 */
	if (list_empty(q)) {
		printk(KERN_ALERT "Job queue is empty, operation aborted!\n");
		err = -ENODATA;
		goto out;
	}

#ifdef DEBUG
	printk(KERN_INFO "Queue before removal(CL: %d LH:%x H:%x\n",
		curr_queue_length,
		(unsigned int)local_high_head, (unsigned int)q);
	list_for_each(pos, q) {
		temp_node = list_entry(pos, QUEUE_NODE, list);
		printk(KERN_INFO "%d, %x ", temp_node->job_packet->job_id,
			(unsigned int)&(temp_node->list));
	}
	printk("\n");
#endif

	list_for_each_safe(pos, temp, q) {
		temp_node = list_entry(pos, QUEUE_NODE, list);
		if (temp_node->job_packet->job_id == job_id) {

#ifdef EXTRA_CREDIT
			/* check if process has permission to remove job */
			if (current->pid != temp_node->job_packet->process_id) {
				printk(KERN_INFO "Permission denied\n");
				err = -EPERM;
				goto out;
			}
#endif
			if (&(temp_node->list) == local_high_head)
				local_high_head = temp_node->list.next;

			list_del(pos);
			curr_queue_length--;
			free_job(temp_node->job_packet);
			goto out;
		}
	}
	err = -ESRCH;

out:
#ifdef DEBUG
	printk(KERN_INFO "Queue after removal(CL: %d LH:%x H:%x\n",
		curr_queue_length,
		(unsigned int)local_high_head, (unsigned int)q);
	list_for_each(pos, q) {
		temp_node = list_entry(pos, QUEUE_NODE, list);
		printk(KERN_INFO "%d, %x ", temp_node->job_packet->job_id,
			(unsigned int)&(temp_node->list));
	}
	printk("\n");
#endif

	mutex_unlock(&queue_lock);
	return err;
}

/**
 * Change the priority of given job. On success, returns 0, otherwise -1.
 * In case if job has the same priority what is requested, no changes are done.
 */
long change_job_priority(struct list_head *q, int job_id, int new_priority)
{
	int err = 0;
	struct list_head *pos, *temp;
	QUEUE_NODE *temp_node = NULL;

	mutex_lock(&queue_lock);

	/**
	 * If list is empty, no work is to be done.
	 */
	if (list_empty(q)) {
		printk(KERN_INFO "Job queue is empty, operation aborted!\n");
		err = -ENODATA;
		goto out;
	}

#ifdef DEBUG
	printk(KERN_INFO "Queue before Prio change(CL: %d LH:%x H:%x\n",
	 curr_queue_length,
		(unsigned int)local_high_head, (unsigned int)q);
	list_for_each(pos, q) {
		temp_node = list_entry(pos, QUEUE_NODE, list);
		printk(KERN_INFO "%d, %x ", temp_node->job_packet->job_id,
			(unsigned int)&(temp_node->list));
	}
	printk(KERN_INFO "\n");
#endif

	list_for_each_safe(pos, temp, q) {
		temp_node = list_entry(pos, QUEUE_NODE, list);
		if (temp_node->job_packet->job_id == job_id) {

#ifdef EXTRA_CREDIT
			/* check if process has permission to change priority */
			if (current->pid != temp_node->job_packet->process_id) {
				printk(KERN_INFO "Permission denied\n");
				err = -EPERM;
				goto out;
			}
#endif

			if (temp_node->job_packet->priority == new_priority) {
				printk(KERN_INFO "Job already has requested priority\n");
				goto out;
			}
			else {
				if (&(temp_node->list) == local_high_head)
					local_high_head = temp_node->list.next;

				list_del(pos);
				temp_node->job_packet->priority = new_priority;

				/* figure out place of insertion */
				if (temp_node->job_packet->priority == LOW_PRIORITY) {
					list_add_tail(&(temp_node->list), q);
					if (local_high_head == q)
						local_high_head = &(temp_node->list);
				}

				else if (temp_node->job_packet->priority == HIGH_PRIORITY) {
					list_add_tail(&(temp_node->list), local_high_head);
				}
				goto out;
			}
		}
	}
	err = -ESRCH;

out:

#ifdef DEBUG
	printk(KERN_INFO "Queue after Prio change(CL: %d LH:%x H:%x\n",
		curr_queue_length,
		(unsigned int)local_high_head, (unsigned int)q);
	list_for_each(pos, q) {
		temp_node = list_entry(pos, QUEUE_NODE, list);
		printk(KERN_INFO "%d, %x ", temp_node->job_packet->job_id,
			(unsigned int)&(temp_node->list));
	}
	printk(KERN_INFO "\n");
#endif

	mutex_unlock(&queue_lock);
	return err;
}
