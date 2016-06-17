/* This file defines all functios and definitions related
 * to job queue. You're free to add more functions as need arises 
 * and is justified. These definitions are in infancy and will be
 * modified as development progresses */
 
static LIST_HEAD(job_queue);
struct mutex queue_lock;
static struct list_head job_queue;
static struct list_head *local_high_head;
static int queue_length = 0;

/* job queue node, this is what gets attached to queue
 * when producer successfully submits job to 
 * consumer */
typedef struct {
	struct list_head list;
	SYS_JOB *job_packet;
} QUEUE_NODE;

/* mutex lock protecting job queue */
//static DEFINE_MUTEX(queue_lock);

void free_job(SYS_JOB *kernel_data)
{
	if(kernel_data->infile)
		kfree(kernel_data->infile);
	if(kernel_data->outfile)
		kfree(kernel_data->outfile);
	if(kernel_data)
		kfree(kernel_data);
	return ;
}

long list_jobs(SYS_JOB *arg)
{
	long status = 0;
	struct list_head *pos, *temp, *q;
	QUEUE_NODE *temp_node = NULL;

	mutex_lock(&queue_lock);
	q = &job_queue;
	queue_length = 0;
	
	list_for_each_safe(pos, temp, q) {		    
		temp_node = list_entry(pos, QUEUE_NODE, list);
		// copy stuff temp_node->job_packet->job_id

		status = copy_to_user(&arg[queue_length].job_type,
								&temp_node->job_packet->job_id,
								sizeof(int));
		if (status != 0) {
			printk("failed to copy userData->job_id");
			goto exit_final;
		}

		status = copy_to_user(&arg[queue_length].process_id,
								&temp_node->job_packet->process_id,
								sizeof(pid_t));
		if (status != 0) {
			printk("failed to copy userData->process_id");
			goto exit_final;
		}
		
		status = copy_to_user(&arg[queue_length].job_type,
								&temp_node->job_packet->job_type,
								sizeof(int));
		if (status != 0) {
			printk("failed to copy userData->job_type");
			goto exit_final;
		}

		status = copy_to_user(&arg[queue_length].algo,
								&temp_node->job_packet->algo,
								sizeof(int));
		if (status != 0) {
			printk("failed to copy userData->algo");
			goto exit_final;
		}

		status = copy_to_user(&arg[queue_length].priority,
								&temp_node->job_packet->priority,
								sizeof(int));
		if (status != 0) {
			printk("failed to copy userData->priority");
			goto exit_final;
		}

		queue_length++;
	}
	
	status = queue_length;
	
exit_final:
	mutex_unlock(&queue_lock);
	return status;
}

/**
 * adds low priority job at the tail of queue and high priority job at 
 * local_high_head of queue. If there are no low_priority jobs in queue,
 * local_high_head points to head of the queue.  
 * Returns queue length on success and appropriate errno is set in case of
 * failure.
 */
long add_job(struct list_head *q, SYS_JOB *j) {
	long err = 0;
	long queue_length;
	struct list_head *pos;
	QUEUE_NODE *new_queue_node = NULL;

	mutex_lock(&queue_lock);

	/**
	 * set local high tail to head of list. If the list is not empty, then 
	 * there is no need to set it as it would have been set appropriately 
	 * earlier.
	 */
	if (list_empty(q)) {
		local_high_head = q;
	}

	/* TBD: find if there is inbuilt method to get length of list */
    queue_length = 0;
    list_for_each(pos, q) {
    	queue_length++;
    }

#ifdef DEBUG
    printk(KERN_INFO "queue length before: %d\n", (int)queue_length);
#endif

    if (queue_length == QUEUE_LENGTH) {
    	err = -EBUSY;
    	printk(KERN_INFO "Job queue full, try again\n");
    	goto out;
    }

    new_queue_node = (QUEUE_NODE *) kzalloc(sizeof(QUEUE_NODE), GFP_KERNEL);
    if (!new_queue_node) {
		printk(KERN_INFO "Insufficient memory\n");
		err = -ENOMEM;
		goto out;
	}
	j->job_id = queue_length + 1;
	new_queue_node->job_packet = j;

	/* figure out place of insertion */
	if (new_queue_node->job_packet->priority == 0) {/* low priority, insert at tail */
		list_add_tail(&(new_queue_node->list), q);
		if (local_high_head == q)
			local_high_head = &(new_queue_node->list);
	}

	else if (new_queue_node->job_packet->priority == 1) {
		list_add_tail(&(new_queue_node->list), local_high_head);
	}

	/* TBD: wake up/spawn at least one consumer thread */
    err = queue_length + 1;
out:
    	mutex_unlock(&queue_lock);
	return err;
}

/**
 * removes and returns highest priority job from queue to caller.
 * Mainly consumer gets served through this call. Highest priority
 * job is picked from head of list.
 */
SYS_JOB *pick_job(struct list_head *q) {
	SYS_JOB *j = NULL;
	QUEUE_NODE *temp_node = NULL;

	mutex_lock(&queue_lock);
	/**
	 * If list is empty, no work is to be done, put all consumers 
	 * in sleep state
	 */
	if (list_empty(q)) {
		printk(KERN_INFO "No jobs pending, sleep !\n");
		goto out;
	}

	temp_node = list_entry(q->next, QUEUE_NODE, list);
	j = temp_node->job_packet;
	/* local_high_head is updated in case it points to node being removed */
	if (&(temp_node->list) == local_high_head)
		local_high_head = temp_node->list.next;
	list_del(q->next);

out:
	mutex_unlock(&queue_lock);
	return j;
}

/**
 * Remove a job from a queue with specific job_id. Return error(-1)
 * if requested job is not found in the queue. On success, returns 0
 */
int remove_job_id(struct list_head *q, int job_id) {
	int err = 0;
	struct list_head *pos, *temp;
	QUEUE_NODE *temp_node = NULL;

	mutex_lock(&queue_lock);

	list_for_each_safe(pos, temp, q) {		    
		temp_node = list_entry(pos, QUEUE_NODE, list);
		if (temp_node->job_packet->job_id == job_id) {
			if (&(temp_node->list) == local_high_head)
				local_high_head = temp_node->list.next;

			list_del(pos);
			goto out;
		}
	}


	err = -1;

out:
	mutex_unlock(&queue_lock);
	return err;
}

/**
 * remove job queue on exit. This is called when exit_sys_submitjob
 * is executed.
 */
void queue_exit(struct list_head *q) {
	//kfree(q);
}
