/* This file defines all functios and definitions related
 * to operations performed by this prod-consumer asynchronus system.
 * These definitions are in infancy and will be modified as
 * development progresses. You're free to change arguments as per requirement
 * but once finalized, try not to change them later. These arguments are passed
 * by consumer extracted from job packet */

#include <linux/fs_struct.h>

/*
	function to validate the input sent in by caller
*/
long validate_job(void *arg)
{
	long status = 0;
	SYS_JOB *user_args = (SYS_JOB *) arg;
	/* printk("validate_job called\n"); */

	/* check if userArgs is valid and if it can be accessed.*/
	if (user_args == NULL) {
		printk("user_args NULL\n");
		return -EINVAL;
	}

	if (!access_ok(VERIFY_READ,
				  user_args,
				  sizeof(SYS_JOB))) {
		printk("user_args invalid\n");
		return -EFAULT;
	}

	if(user_args->job_type != CHECKSUM &&
	   user_args->job_type != ENCRYPT &&
	   user_args->job_type != DECRYPT &&
	   user_args->job_type != COMPRESS &&
	   user_args->job_type != DECOMPRESS &&
	   user_args->job_type != LIST_JOBS &&
	   user_args->job_type != DELETE_JOB &&
	   user_args->job_type != FLUSH_JOBS &&
	   user_args->job_type != CHANGE_PRIORITY){
		   return -EINVAL;
	   }

	if(user_args->job_type == ENCRYPT ||
	   user_args->job_type == DECRYPT) {
		   if(user_args->algo != AES &&
			  user_args->algo != BLOWFISH){
				  return -EINVAL;
			  }
	   }

	 if(user_args->job_type == CHECKSUM) {
		   if(user_args->algo != MD5 &&
			  user_args->algo != CRC32){
				  return -EINVAL;
			  }
	   }

	if(user_args->priority != HIGH_PRIORITY &&
	   user_args->priority != LOW_PRIORITY){
		  return -EINVAL;
	  }

	if(user_args->job_type == DELETE_JOB &&
	   user_args->job_id == 0) {
		   return -EINVAL;
	   }

	if(user_args->job_type == CHANGE_PRIORITY &&
	   user_args->job_id == 0) {
		   return -EINVAL;
	   }

	if(user_args->job_type == DELETE_JOB ||
	   user_args->job_type == LIST_JOBS ||
	   user_args->job_type == FLUSH_JOBS ||
	   user_args->job_type == CHANGE_PRIORITY) {
		   goto exit_final;
	   }

	/* check if input file name pointer is valid and is accesible*/
	if (user_args->infile == NULL) {
		printk("userArgs->inputFile NULL\n");
		return -EINVAL;
	}

	if (!access_ok(VERIFY_READ,
				  user_args->infile,
				  sizeof(user_args->infile))) {
		printk("userArgs->inputFile invalid\n");
		return -EFAULT;
	}

	if (user_args->job_type == CHECKSUM) {
		   goto exit_final;
	}

	/* check if output file name pointer is valid and is accesible */
	if (user_args->outfile == NULL) {
		printk("userArgs->outputFile NULL\n");
		return -EINVAL;
	}

	if (!access_ok(VERIFY_READ,
				  user_args->outfile,
				  sizeof(user_args->outfile))) {
		printk("userArgs->outputFile invalid\n");
		return -EFAULT;
	}

	if(user_args->job_type == ENCRYPT ||
	   user_args->job_type == DECRYPT) {
		/* check if key pointer is valid and is accessible */
		if (user_args->key == NULL) {
			printk("userArgs->keyHash NULL\n");
			return -EINVAL;
		}

		if (!access_ok(VERIFY_READ,
					  user_args->key,
					  user_args->keyLength)) {
			printk("userArgs->keyHash invalid\n");
			return -EFAULT;
		}

		/* validation on keyLength, should be 6 or greater */
		if (user_args->keyLength < KEYLENGTH_MIN) {
			printk("Invalid keyLength value\n");
			return -EINVAL;
		}
	}

	// some validation on process id?
exit_final:
	//printk("all validation passed\n");
	return status;
}

/*
   utility function to open a file in read mode
 */
struct file *open_file_to_read(char *filename)
{
	struct file *filp = NULL;
	/*printk("open_file_to_read called\n");*/

	/*printk("filename %s\n",filename);*/
	filp = filp_open(filename, O_RDONLY, 0);
	if ((filp == NULL) || IS_ERR(filp)) {
		//printk("\nopen_file_to_read failed %ld\n", PTR_ERR(filp));
		filp = NULL;
		goto exit_final;
	}

	if ((filp->f_op == NULL) || (filp->f_op->read == NULL)) {
		printk("file operations error\n");
		filp_close(filp, NULL);
		filp = NULL;
		goto exit_final;
	}

exit_final:
	return filp;
}

/*
   utility function to open a file in write mode,
   will create one if it does not exist
 */
struct file *open_file_to_write(char *filename, umode_t mode)
{
	struct file *filp = NULL;
	/*printk("open_file_to_write called\n");*/

	/*printk("filename %s\n",filename);*/
	filp = filp_open(filename, O_WRONLY|O_CREAT, mode);
	if ((filp == NULL) || IS_ERR(filp)) {
		printk("open_file_to_write failed %ld\n", PTR_ERR(filp));
		filp = NULL;
		goto exit_final;
	}

	if ((filp->f_op == NULL) || (filp->f_op->write == NULL)) {
		printk("file operations error\n");
		filp_close(filp, NULL);
		filp = NULL;
		goto exit_final;
	}

exit_final:
	return filp;
}


/*
   This function checks the validity of input
   and outputfile like if there are directory or ths same.
   Returns 0 on success, else appropriate errno is returned.
 */

long check_file_validity(char *inputfile, char *outputfile, int validate_outfile)
{
	struct file *filp_input = NULL;
	struct file *filp_output = NULL;
	struct inode *inputfile_inode = NULL;
	struct inode *outputfile_inode = NULL;
	long return_status = 0;
	/*printk("check_file_validity called\n");*/

	if (inputfile == NULL) {
		printk("inputFile NULL\n");
		return_status = -EINVAL;
		goto exit_final;
	}

	filp_input = open_file_to_read(inputfile);
	if (filp_input == NULL) {
		printk("No such file failure\n");
		return_status = -ENOENT;;
		goto exit_final;
	}

	if (d_is_dir(filp_input->f_path.dentry)) {
		printk("input file is a directory!\n");
		return_status = -EISDIR;
		goto inputFile_is_directory;
	}

	if (!d_is_reg(filp_input->f_path.dentry)) {
		printk("input file is not regular!\n");
		return_status = -EINVAL;
		goto inputFile_is_directory;
	}

	if(validate_outfile)
	{
		if (outputfile == NULL) {
			printk("outputFile NULL\n");
			return_status = -EINVAL;
			goto open_outfile_file_failed;
		}

		filp_output = open_file_to_read(outputfile);
		if (filp_output == NULL) {
			printk("Outfile does not exist!\n");
			return_status = 0;
			goto outfile_does_not_exist;
		}

		if (d_is_dir(filp_output->f_path.dentry)) {
			printk("output file is a directory!\n");
			return_status = -EISDIR;
			goto file_validation_failed;
		}

		if (!d_is_reg(filp_output->f_path.dentry)) {
			printk("output file is bot regular!\n");
			return_status = -EINVAL;
			goto file_validation_failed;
		}

		outputfile_inode = filp_output->f_path.dentry->d_inode;
	}
	else
		goto outfile_does_not_exist;

	inputfile_inode = filp_input->f_path.dentry->d_inode;

	/** check if they are same file or symlink to same file
	   also cehck their file system is same or not*/
	if ((inputfile_inode->i_ino == outputfile_inode->i_ino)
			&& (!strcmp(inputfile_inode->i_sb->s_type->name,
					outputfile_inode->i_sb->s_type->name))) {
		printk("same file is input and output!\n");
		return_status = -EPERM;
		goto file_validation_failed;
	}

file_validation_failed:
	filp_close(filp_output, NULL);
outfile_does_not_exist:
open_outfile_file_failed:
inputFile_is_directory:
	filp_close(filp_input, NULL);
exit_final:
	return return_status;
}

/*
   This function copies the user input to kernel space.
 */
long copy_userInput_to_kernel(SYS_JOB *user_data,
						    SYS_JOB *kernel_data)
{
	long status = 0;
	int validate_outfile = 1;

	int pathlen = 0;
	char *buffer = NULL;
	char *temp = NULL;
	char *path = NULL;
	struct path pwd;
	char slash = '/';
	/* printk("copy_userInput_to_kernelData called\n"); */

	status = copy_from_user(&kernel_data->job_type,
							&user_data->job_type,
							sizeof(int));
	if (status != 0) {
		printk("failed to copy userData->job_type");
		goto exit_final;
	}

	status = copy_from_user(&kernel_data->process_id,
							&user_data->process_id,
							sizeof(pid_t));
	if (status != 0) {
		printk("failed to copy userData->process_id");
		goto exit_final;
	}

	status = copy_from_user(&kernel_data->algo,
							&user_data->algo,
							sizeof(int));
	if (status != 0) {
		printk("failed to copy userData->algo");
		goto exit_final;
	}

	status = copy_from_user(&kernel_data->priority,
							&user_data->priority,
							sizeof(int));
	if (status != 0) {
		printk("failed to copy userData->priority");
		goto exit_final;
	}

	status = copy_from_user(&kernel_data->weak_validation,
							&user_data->weak_validation,
							sizeof(int));
	if (status != 0) {
		printk("failed to copy userData->weak_validation");
		goto exit_final;
	}

	status = copy_from_user(&kernel_data->keyLength,
							&user_data->keyLength,
							sizeof(int));
	if (status != 0) {
		printk("failed to copy userData->keyLength");
		goto exit_final;
	}

	status = copy_from_user(&kernel_data->job_id,
							&user_data->job_id,
							sizeof(int));
	if (status != 0) {
		printk("failed to copy userData->job_id");
		goto exit_final;
	}

	if(kernel_data->job_type == LIST_JOBS ||
	   kernel_data->job_type == DELETE_JOB ||
	   kernel_data->job_type == FLUSH_JOBS ||
	   kernel_data->job_type == CHANGE_PRIORITY) {
		   goto exit_final;
	   }
	/* we need to allocate memory for all the pointer members
	// this is needed as the user pointers are virtual addresses */

	/*some issue with getname and putname, need to root cause*/
	/*inputfile*/

	// need to make this absolute paths as kernel threads run in root
	kernel_data->infile = kmalloc(strlen(user_data->infile) + 1,
							GFP_KERNEL);
	if (kernel_data->infile == NULL) {
		printk("kmalloc userData->inputFile failed");
		status = -ENOMEM;
		goto kmalloc_inputFile_failed;
	}

	memset(kernel_data->infile, 0, strlen(user_data->infile) + 1);

	status = copy_from_user(kernel_data->infile,
						user_data->infile,
						strlen(user_data->infile));
	if (status != 0) {
		printk("failed to copy userData->inputFile");
		goto copy_to_kernel_inputFile_failed;
	}

	/* we need to NULL terminate the string*/
	kernel_data->infile[strlen(user_data->infile)] = '\0';

	if (kernel_data->job_type != CHECKSUM) {
		/* outputFile */
		kernel_data->outfile = kmalloc(strlen(user_data->outfile) + 1,
									GFP_KERNEL);
		if (kernel_data->outfile == NULL) {
			printk("kmalloc userData->outputFile failed");
			status = -ENOMEM;
			goto kmalloc_outputFile_failed;
		}

		memset(kernel_data->outfile, 0, strlen(user_data->outfile) + 1);

		status = copy_from_user(kernel_data->outfile,
							user_data->outfile,
							strlen(user_data->outfile));
		if (status != 0) {
			printk("failed to copy userData->outputFile");
			goto copy_to_kernel_outputFile_failed;
		}

		kernel_data->outfile[strlen(user_data->outfile)] = '\0';
		/*printk("%s\n", kernelData->outputFile);*/
	}

	if(kernel_data->job_type == ENCRYPT ||
	   kernel_data->job_type == DECRYPT) {
		/* keyHash */

		status = copy_from_user(kernel_data->key,
							user_data->key,
							sizeof(char)*DIGEST_SIZE);
		if (status != 0) {
			printk("failed to copy userData->keyHash");
			goto copy_to_kernel_outputFile_failed;
		}
	}

	if (kernel_data->job_type == CHECKSUM)
		validate_outfile = 0;

	if (!kernel_data->weak_validation)
	{
		/* check if output and input file are same */
		status = check_file_validity(kernel_data->infile,
					kernel_data->outfile, validate_outfile);
		if (status != 0) {
			printk("file validation failed!\n");
			goto copy_to_kernel_outputFile_failed;
		}
	}
	else
	{
		printk("\ndiffer validation for now\n");
	}

	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buffer == NULL)
	{
	   status = -ENOMEM;
	   goto exit_final;
	}

	memset(buffer,0,PAGE_SIZE);
	get_fs_pwd(current->fs, &pwd);
	path = d_path(&pwd, buffer, (PAGE_SIZE/2));
	if (IS_ERR(path)) {
			 status = PTR_ERR(path);
			 goto exit_final;
	 }
	// printk("\npwd: %s", path);
	temp = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (temp == NULL)
	{
	   status = -ENOMEM;
	   goto exit_final;
	}

    pathlen = buffer + (PAGE_SIZE/2) - path;

	if (pathlen <= (PAGE_SIZE/2)) {
		if (kernel_data->infile && kernel_data->infile[0] != '/')
		{
			pathlen = buffer + (PAGE_SIZE/2) - path;
			memset(temp, 0,PAGE_SIZE);
			//pathlen = strlen(path);
			memcpy(temp, path, pathlen);
			//printk("\ntemp: %s", temp);
			strncat(temp, &slash, 1);
			//printk("\ntemp after slash: %s", temp);
			strncat(temp, kernel_data->infile, strlen(kernel_data->infile));
			// printk("\ntemp: %s", temp);

			pathlen = strlen(temp);
			if(kernel_data->infile)
				kfree(kernel_data->infile);
			kernel_data->infile = kmalloc(pathlen + 1 , GFP_KERNEL);
			if (kernel_data->infile == NULL)
			{
				status = -ENOMEM;
				goto copy_to_kernel_outputFile_failed;
			}
			memset(kernel_data->infile, 0, pathlen + 1);
			memcpy(kernel_data->infile, temp, pathlen);
			//printk("\npwd in kernel : %s\n", kernel_data->infile);
		}

		if(validate_outfile)
		{
			if(kernel_data->outfile && kernel_data->outfile[0] != '/') {
				pathlen = buffer + (PAGE_SIZE/2) - path;
				memset(temp, 0,PAGE_SIZE);
				//pathlen = strlen(path);
				memcpy(temp, path, pathlen);
				//printk("\ntemp: %s", temp);
				strncat(temp, &slash, 1);
				strncat(temp, kernel_data->outfile, strlen(kernel_data->outfile));
				// printk("\ntemp: %s", temp);

				pathlen = strlen(temp);
				if(kernel_data->outfile)
					kfree(kernel_data->outfile);
				kernel_data->outfile = kmalloc(pathlen + 1 , GFP_KERNEL);
				if (kernel_data->outfile == NULL)
				{
				   status = -ENOMEM;
				   goto copy_to_kernel_outputFile_failed;
				}
				memset(kernel_data->outfile, 0, pathlen + 1);
				memcpy(kernel_data->outfile, temp, pathlen);
				//printk("\npwd out kernel : %s\n", kernel_data->outfile);
			}
		}
	} else {
		status = -ERANGE;
		//printk("\ngetting pwd failed");
	}

	goto exit_final;

copy_to_kernel_outputFile_failed:
	if (kernel_data->outfile) {
		kfree(kernel_data->outfile);
		kernel_data->outfile = NULL;
	}
kmalloc_outputFile_failed:
copy_to_kernel_inputFile_failed:
	if(kernel_data->infile) {
		kfree(kernel_data->infile);
		kernel_data->infile = NULL;
	}
kmalloc_inputFile_failed:
exit_final:
	if(temp)
		kfree(temp);
	if (buffer)
		kfree(buffer);
	return status;
}

int compress_file(char *infile, char *outfile) {
	/* compression code goes here. Return appropriate error if there are any
	 * */
	struct crypto_comp *tfm;
	int read_len, write_len;
	mm_segment_t oldfs;
	struct file *rfilp = NULL;
	struct file *wfilp = NULL;
	int ret = 0;
	char *inbuf;
	char *outbuf = NULL;
	int outlen = PAGE_SIZE;
	char *algo = "deflate";
	inbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!inbuf) {
		ret = -ENOMEM;
		printk(KERN_ALERT "\n Error: Memory Unavailable!!");
		goto out;
	}
	outbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!outbuf) {
		ret = -ENOMEM;
		printk(KERN_ALERT "\n Error: Memory Unavailable!!");
		goto out;
	}
	rfilp = filp_open(infile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
		printk("\n Error: Opening I/P file ");
		ret = (int) PTR_ERR(rfilp);
		goto out;
	}
	if (!rfilp->f_op->read) {
		ret = (int) PTR_ERR(rfilp);
		printk("\n Error: I/P file doesn't allow read operation.");
		goto out;
	}
	wfilp = filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0777 & ~current_umask());
	if (!wfilp || IS_ERR(wfilp)) {
		ret = (int) PTR_ERR(wfilp);
		printk(KERN_ALERT "\n Error: Opening O/P file ");
		goto out;
	}
	if (!wfilp->f_op->write) {
		ret = (int) PTR_ERR(wfilp);
		printk(KERN_ALERT "\n Error: O/P file doesn't allow write operation");
		goto out;
	}
	tfm = crypto_alloc_comp(algo, 0, 0);
	if (!tfm) {
		ret = -EINVAL;
		printk(KERN_ALERT "\n Error: problem with tfm");
	}
	rfilp->f_pos = 0;
	wfilp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	read_len = vfs_read(rfilp, inbuf, PAGE_SIZE, &rfilp->f_pos);
	if (read_len < 0) {
		printk(KERN_ALERT "\n Error: reading I/P file");
		ret = read_len;
		goto outrw;
	}
	ret = crypto_comp_compress(tfm, inbuf, read_len, outbuf, &outlen);
	if (ret < 0) {
		printk(KERN_ALERT "\n Error: Compression failed");
		//printk(KERN_ALERT "\n inbuf = %s, read_len = %d, outbuf = %s, outlen = %d, ret = %d",inbuf, read_len, outbuf, outlen, ret);
		//printk(KERN_ALERT "\n read_len = %d, outlen = %d, ret = %d", read_len, outlen, ret);
		goto outrw;
	}
	write_len = vfs_write(wfilp, outbuf, outlen, &wfilp->f_pos);
	//printk(KERN_ALERT "\n write_len = %d", write_len);
	if (write_len < 0) {
		printk(KERN_ALERT "\n Error: writing O/P file");
		ret = write_len;
		goto outrw;
	}

outrw:
	set_fs(oldfs);
out:
	if(rfilp){
		filp_close(rfilp, NULL);
		rfilp = NULL;
	}
	if(wfilp){
		filp_close(wfilp, NULL);
		wfilp = NULL;
	}
	if(inbuf){
		kfree(inbuf);
		inbuf = NULL;
	}
	if(outbuf){
		kfree(outbuf);
		outbuf = NULL;
	}
	return ret;
}

int decompress_file(char *infile, char *outfile) {
	/* decompression code goes here. Return appropriate error if there are any
	 * */
	struct crypto_comp *tfm;
	int read_len, write_len;
	mm_segment_t oldfs;
	struct file *rfilp = NULL;
	struct file *wfilp = NULL;
	char *inbuf;
	char *outbuf = NULL;
	int ret = 0;
	int outlen = PAGE_SIZE;
	char *algo = "deflate";
	tfm = crypto_alloc_comp(algo, 0, 0);
	if (!tfm) {
		ret = -EINVAL;
		printk(KERN_ALERT "\n Error: problem with tfm");
	}
	inbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!inbuf) {
		ret = -ENOMEM;
		printk(KERN_ALERT "\n Error: Memory Unavailable!!");
		goto out;
	}
	outbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!outbuf) {
		ret = -ENOMEM;
		printk(KERN_ALERT "\n Error: Memory Unavailable!!");
		goto out;
	}
	rfilp = filp_open(infile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
		printk("\n Error: Opening I/P file ");
		ret = (int) PTR_ERR(rfilp);
		goto out;
	}
	if (!rfilp->f_op->read) {
		ret = (int) PTR_ERR(rfilp);
		printk("\n Error: I/P file doesn't allow read operation.");
		goto out;
	}
	wfilp = filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0777 & ~current_umask());
	if (!wfilp || IS_ERR(wfilp)) {
		ret = (int) PTR_ERR(wfilp);
		printk(KERN_ALERT "\nError: Opening O/P file ");
		goto out;
	}
	if (!wfilp->f_op->write) {
		ret = (int) PTR_ERR(wfilp);
		printk(KERN_ALERT "\nError: O/P file doesn't allow write operation");
		goto out;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	rfilp->f_pos = 0;
	wfilp->f_pos = 0;
	read_len = vfs_read(rfilp, inbuf, PAGE_SIZE, &rfilp->f_pos);
	if (read_len < 0) {
		printk(KERN_ALERT "\nError: reading I/P file");
		ret = read_len;
		goto outrw;
	}
	ret = crypto_comp_decompress(tfm, inbuf, read_len, outbuf, &outlen);
	if (ret < 0) {
		printk(KERN_ALERT "\nError: Decompression failed");
		//printk(KERN_ALERT "\nread_len = %d, outlen = %d, ret = %d", read_len, outlen, ret);
		//printk(KERN_ALERT "\n inbuf = %s, read_len = %d, outbuf = %s, outlen = %d, ret = %d",inbuf, read_len, outbuf, outlen, ret);
		goto outrw;
	}
	write_len = vfs_write(wfilp, outbuf, outlen, &wfilp->f_pos);
	//printk(KERN_ALERT "\nwrite_len = %d", write_len);
	if (write_len < 0) {
		printk(KERN_ALERT "\nError:writing O/P file");
		ret = write_len;
		goto outrw;
	}
outrw:
	set_fs(oldfs);
out:
	if (rfilp) {
		filp_close(rfilp, NULL);
		rfilp = NULL;
	}
	if (wfilp) {
		filp_close(wfilp, NULL);
		wfilp = NULL;
	}
	if (inbuf) {
		kfree(inbuf);
		inbuf = NULL;
	}
	if (outbuf) {
		kfree(outbuf);
		outbuf = NULL;
	}
	return ret;
}

int decrypt_file(char *infile, char *outfile, char *key, int algo) {
	mm_segment_t old_fs;
	int err = 0; // returns errno
	int iter = 0;
	int ret, bytes_read, bytes_written;

	bool done = false;
	bool dest_file_doesnt_exist = false;

	struct file *ifp = NULL; // pointer to input file to be encrypted/ decrypted
	struct file *ofp = NULL; // pointer to temp o/p file
	struct file *dest_file = NULL; // pointer final o/p file
	struct crypto_blkcipher *cipher_handle = NULL;
	struct scatterlist *src = NULL;
	struct scatterlist *dst = NULL;
	struct blkcipher_desc desc;

	char* plaintext_buf = NULL;
	char* ciphertext_buf = NULL;
	char* ciphered_key = NULL;
	char* deciphered_key = NULL;
	char *tempfile = NULL;
	/***********************************************************************
	 * checking files validity
	 ***********************************************************************/
	if (check_file_validity(infile, outfile, 1) != 0){
		printk("Invalid Files!\n");
		err = -EINVAL;
		goto out;
	}
	//stripping off an extra byte in key
	key[DIGEST_SIZE]=0;
	/************************************************************************
	 * open input file
	 *************************************************************************/
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	ifp = open_file_to_read(infile);
	if (!ifp){
		printk("Error in opening input file.\n");
		err = -EPERM;
		goto out;
	}

	cipher_handle = crypto_alloc_blkcipher("ctr(aes-generic)", 0,CRYPTO_ALG_ASYNC);

	if (IS_ERR(cipher_handle)) {
		printk("Error allocating cipher handle\n");
		err = -EINVAL;
		goto out;
	}

	plaintext_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!plaintext_buf){
		err = -ENOMEM;
		goto out;
	}
	ciphertext_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ciphertext_buf){
		err = -ENOMEM;
		goto out;
	}
	ciphered_key = kzalloc(strlen(key), GFP_KERNEL);
	if (!ciphered_key){
		err = -ENOMEM;
		goto out;
	}
	deciphered_key = kzalloc(strlen(key), GFP_KERNEL);
	if (!deciphered_key){
		err = -ENOMEM;
		goto out;
	}

	src = kzalloc(sizeof(struct scatterlist),GFP_KERNEL);
	if (!src) {
		printk("ERROR: failed to allocate scatterlist\n");
		err = -ENOMEM;
		goto out;
	}
	dst = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
	if (!dst) {
		printk("ERROR: failed to allocate scatterlist\n");
		err = -ENOMEM;
		goto out;
	}

	/* set the caller provided key for the block cipher referenced by \
	 * the cipher handle
	 */
	ret = crypto_blkcipher_setkey(cipher_handle, key, strlen(key));
	if (ret < 0) {
		printk("Error in setting cipher key.");
		err = -EINVAL;
		goto out;
	}

	desc.tfm = cipher_handle;
	desc.flags = 0; // can be set to 0 or CRYPTO_TFM_REQ_MAY_SLEEP
	ifp->f_pos = 0;
	bytes_read = vfs_read(ifp, ciphered_key, strlen(key), &ifp->f_pos);

	if (bytes_read < 0) {
		printk("Raeding from file failed\n");
		err = -EPERM;
		goto out;
	}
	//printk("Bytes Read = %d\n", bytes_read);

	sg_init_one(src, ciphered_key, strlen(key));
	sg_init_one(dst, deciphered_key, strlen(key));

	ret = crypto_blkcipher_decrypt(&desc, dst, src, strlen(key));
	if (ret < 0) {
		printk("Error in starting decryption\n");
		err = -EFAULT;
		goto out;
	}

	//printk(" deciphered key = %s len = %d\n", deciphered_key, strlen(deciphered_key));
	//printk(" ciphered key = %s len = %d\n", ciphered_key, strlen(ciphered_key));
	//key[strlen(deciphered_key)] = 0;
	if (strcmp((const char*)deciphered_key, (const char*)key)){
		err = -EACCES;
		printk("Invalid Password for decryption\n");
		goto out;;
	}

	/*
	 * Authentication successfull
	 */


	/************************************************************************
	 * Open out file & check files
	 *************************************************************************/
	/*
	 * Open output file for read and write, append it on each write,\
	 * and create file if it doesn't exist.
	 * O_TRUNC         truncate size to 0
	 * O_EXCL          error if create and file exists
	 */
	//printk("Decryption creating  temp file!\n");
	tempfile = kzalloc(strlen(outfile) + 5, GFP_KERNEL);

	if (!tempfile)
	{
		err = -ENOMEM;
		goto out;
	}
	/********************************************************
	* new file will have name as "infile.md5"
	********************************************************/
	strcpy(tempfile, outfile);
	strcat(tempfile, ".tmp");

	ofp = open_file_to_write(tempfile,0);
	if (!ofp){
		printk("Error in opening temp file!\n");
		err = -ENOENT;
		goto out;

	}

	ofp->f_inode->i_mode = ifp->f_inode->i_mode;

	// destination file open
	dest_file = filp_open(outfile , O_EXCL, 0); // opens existing outfile
	if (IS_ERR((void *)dest_file)) {
		printk("outfile doesn't exist, process is creating new\n");
		dest_file_doesnt_exist = true;
	}

	if (dest_file_doesnt_exist) {
		dest_file = filp_open(outfile , O_CREAT, 0); // create new out file
		if (IS_ERR((void *)dest_file)) {
			printk("Error in opening output file\n");
			err = -ENOENT;
			goto out;
		}
	}
	dest_file->f_inode->i_mode = ifp->f_inode->i_mode;

	// chcek if input and output files are same
	if (ifp->f_inode->i_sb->s_magic == dest_file->f_inode->i_sb->s_magic) {
		if (ifp->f_inode->i_ino == dest_file->f_inode->i_ino) {
			printk("Input and output files provided are same\n");
			err = -EINVAL;
			goto cleanup; // temp_file needs to be deleted
		}
	}

	/************************************************************************
	 * batch mode read and write for decryption
	 *************************************************************************/
	sg_init_one(dst, plaintext_buf, PAGE_SIZE);
	sg_init_one(src, ciphertext_buf, PAGE_SIZE);

	do { // start first batch anyway
#ifdef EXTRA_CREDIT
		crypto_blkcipher_set_iv (cipher_handle, (const u8 *) &iter, 4);
#endif

		// buf contains plain text
		bytes_read = vfs_read(ifp, ciphertext_buf, PAGE_SIZE, &ifp->f_pos);

		if (bytes_read < 0) { // DANGER ZONE, raise alarm
			printk("Raeding from file failed\n");
			err = -EFAULT;
			goto cleanup;
		}
		else if (bytes_read == PAGE_SIZE) { //Full read:Yet to reach at the last batch
#ifdef EXTRA_CREDIT
			ret = crypto_blkcipher_decrypt_iv(&desc, dst, src, PAGE_SIZE);
#else
			ret = crypto_blkcipher_decrypt(&desc, dst, src, PAGE_SIZE);
#endif
			if(ret < 0) {
				printk("Error in encrypting plaintext\n");
				err = -EFAULT;
				goto cleanup;
			}

			bytes_written = vfs_write(ofp, plaintext_buf, PAGE_SIZE, &ofp->f_pos);
			if (bytes_written < 0) {
				printk("Writing to file failed\n");
				err = -EFAULT;
				goto cleanup;
			}
#ifdef DEBUG
			printk("Read: %d bytes, wrote: %d bytes, Full read: %d\n",\
					bytes_read, bytes_written, iter);
#endif
		}
		else if(bytes_read < PAGE_SIZE) {
			done = true; // finished the process
#ifdef EXTRA_CREDIT
			ret = crypto_blkcipher_decrypt_iv(&desc, dst, src, bytes_read);
#else
			ret = crypto_blkcipher_decrypt(&desc, dst, src, bytes_read);
#endif
			if(ret < 0) {
				printk("Error in encrypting plaintext\n");
				err = -EFAULT;
				goto cleanup;
			}

			bytes_written = vfs_write(ofp, plaintext_buf, bytes_read, &ofp->f_pos);
			if (bytes_written < 0) {
				printk("Writing to file failed\n");
				err = -EFAULT;
				goto cleanup;
			}
#ifdef DEBUG
			printk("Read: %d bytes, wrote: %d bytes, partial read: %d\n",\
					bytes_read, bytes_written, iter);
#endif
		}
		else {
			printk("Reading from file failed\n");
			err = -EACCES;
			goto cleanup;
		}
		iter++;
	} while (!done);


	lock_rename(ofp->f_path.dentry->d_parent,\
			dest_file->f_path.dentry->d_parent);

	// rename temp file to destination file
	ret = vfs_rename(ofp->f_path.dentry->d_parent->d_inode,\
			ofp->f_path.dentry, \
			dest_file->f_path.dentry->d_parent->d_inode, \
			dest_file->f_path.dentry, NULL, 0);

	unlock_rename(ofp->f_path.dentry->d_parent,\
			dest_file->f_path.dentry->d_parent);

	if (ret != 0) {
		printk("Error in renaming.\n");
		err = -EINVAL;
		goto cleanup; // rename is part of output writing
	}

	goto out; // skip cleanup, all went fine


cleanup:
	ret = vfs_unlink(ofp->f_path.dentry->d_parent->d_inode, ofp->f_path.dentry, NULL);
	if (ret != 0) {
		printk("Error in deleting temp file.\n");
		err = -EINVAL;
		goto out;
	}

	if (dest_file_doesnt_exist) { // process created it fresh
		//unlink dest_file
		ret = vfs_unlink(dest_file->f_path.dentry->d_parent->d_inode, dest_file->f_path.dentry, NULL);
		if (ret != 0) {
			printk("Error in deleting outfile.\n");
			err = -EINVAL;
			goto out;
		}
	}

	// get back to old file system
	set_fs(old_fs);

out:
	if (!IS_ERR(cipher_handle)) {
		crypto_free_blkcipher(cipher_handle);
	}

	// close only if it was successfully opened
	if (!IS_ERR((void *)ifp) && (ifp != NULL)) {
		filp_close(ifp, NULL);
	}
	if (!IS_ERR((void *)ofp) && (ofp != NULL)) {
		filp_close(ofp, NULL);
	}
	if (!IS_ERR((void *)dest_file) && (dest_file != NULL)) {
		filp_close(dest_file, NULL);
	}

	if (plaintext_buf)
		kfree(plaintext_buf);
	if (ciphertext_buf)
		kfree(ciphertext_buf);
	if (ciphered_key)
		kfree(ciphered_key);
	if (deciphered_key)
		kfree(deciphered_key);
	if (src)
		kfree(src);
	if (dst)
		kfree(dst);

	return err;
}

int encrypt_file(char *infile, char *outfile, char *key, int algo) {
	mm_segment_t old_fs;
	int err = 0; // returns errno
	int iter = 0;
	int ret, bytes_read, bytes_written;

	bool done = false;
	bool dest_file_doesnt_exist = false;

	struct file *ifp = NULL; // pointer to input file to be encrypted/ decrypted
	struct file *ofp = NULL; // pointer to temp o/p file
	struct file *dest_file = NULL; // pointer final o/p file
	struct crypto_blkcipher *cipher_handle = NULL;
	struct scatterlist *src = NULL;
	struct scatterlist *dst = NULL;
	struct blkcipher_desc desc;

	char* plaintext_buf = NULL;
	char* ciphertext_buf = NULL;
	char* ciphered_key = NULL;
	char *tempfile = NULL;
	//printk("\ninputfile : %s", infile);
	//printk("\noutputfile : %s", outfile);
	/***********************************************************************
	 * checking files validity
	 ***********************************************************************/
	if (check_file_validity(infile, outfile, 1) != 0){
		printk("Invalid Files!\n");
		err = -EINVAL;
		goto out;
	}

	/************************************************************************
	 * open input file
	 *************************************************************************/
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	ifp = open_file_to_read(infile);
	if (!ifp){
		printk("Error in opening input file.\n");
		err = -EPERM;
		goto out;
	}

	cipher_handle = crypto_alloc_blkcipher("ctr(aes-generic)", 0,CRYPTO_ALG_ASYNC);

	if (IS_ERR(cipher_handle)) {
		printk("Error allocating cipher handle\n");
		err = -EINVAL;
		goto out;
	}

	plaintext_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!plaintext_buf){
		err = -ENOMEM;
		goto out;
	}
	ciphertext_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ciphertext_buf){
		err = -ENOMEM;
		goto out;
	}
	ciphered_key = kzalloc(strlen(key), GFP_KERNEL);
	if (!ciphered_key){
		err = -ENOMEM;
		goto out;
	}

	src = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
	if (!src) {
		printk("ERROR: failed to allocate scatterlist\n");
		err = -ENOMEM;
		goto out;
	}
	dst = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
	if (!dst) {
		printk("ERROR: failed to allocate scatterlist\n");
		err = -ENOMEM;
		goto out;
	}

//stripping off the extra byte in key
	key[DIGEST_SIZE]=0;

	/* set the caller provided key for the block cipher referenced by \
	 * the cipher handle
	 */
	ret = crypto_blkcipher_setkey(cipher_handle, key, strlen(key));
	if (ret < 0) {
		printk("Error in setting cipher key.\n");
		err = -EINVAL;
		goto out;
	}

	desc.tfm = cipher_handle;
	desc.flags = 0; // can be set to 0 or CRYPTO_TFM_REQ_MAY_SLEEP

	/************************************************************************
	 * Open out file & check files
	 *************************************************************************/
	/*
	 * Open output file for read and write, append it on each write,\
	 * and create file if it doesn't exist.
	 * O_TRUNC         truncate size to 0
	 * O_EXCL          error if create and file exists
	 */
	//printk(" encryption creating  temp file!\n");
	tempfile = kzalloc(strlen(outfile) + 5, GFP_KERNEL);
	if (!tempfile)
	{
		err = -ENOMEM;
		goto out;
	}
	/********************************************************
	* new file will have name as "infile.md5"
	********************************************************/
	strcpy(tempfile, outfile);
	strcat(tempfile, ".tmp");
	ofp = open_file_to_write(tempfile,0);
	if (!ofp){
		printk("Error in opening temp file!\n");
		err = -ENOENT;
		goto out;

	}

	ofp->f_inode->i_mode = ifp->f_inode->i_mode;

	// destination file open
	dest_file = filp_open(outfile , O_EXCL, 0); // opens existing outfile
	if (IS_ERR((void *)dest_file)) {
		printk("outfile doesn't exist, process is creating new\n");
		dest_file_doesnt_exist = true;
	}

	if (dest_file_doesnt_exist) {
		dest_file = filp_open(outfile , O_CREAT, 0); // create new out file
		if (IS_ERR((void *)dest_file)) {
			printk("Error in opening output file\n");
			err = -ENOENT;
			goto out;
		}
	}
	dest_file->f_inode->i_mode = ifp->f_inode->i_mode;

	// chcek if input and output files are same
	if (ifp->f_inode->i_sb->s_magic == dest_file->f_inode->i_sb->s_magic) {
		if (ifp->f_inode->i_ino == dest_file->f_inode->i_ino) {
			printk("Input and output files provided are same\n");
			err = -EINVAL;
			goto cleanup; // temp_file needs to be deleted
		}
	}

	/**********************************************************************
	 * cipher method + key insertion in ecrypted file: preemble
	 ***********************************************************************/

	/* set sg entry to point at key buffer. As length is passed, key buffer
	 * can be passed as const void
	 */
//	printk("sg_init_one done for key src =%s size = %d\n", key, strlen(key));
	sg_init_one(src, key, strlen(key));
	sg_init_one(dst, ciphered_key, strlen(key));

	ret = crypto_blkcipher_encrypt(&desc, dst, src, strlen(key));
	if (ret < 0) {
		printk("Error in encryting the cipher key\n");
		err = -EFAULT;
		goto cleanup;
	}

	bytes_written = vfs_write(ofp, ciphered_key, strlen(key), &ofp->f_pos);
	if (bytes_written < 0) {
		printk("Writing to file failed\n");
		err = -EACCES;
		goto cleanup;
	}
//	printk("preamle written = %d\n", bytes_written);

	/**********************************************************************
	 * batch mode read and write for encryption
	 ***********************************************************************/
	sg_init_one(src, plaintext_buf, PAGE_SIZE);
	sg_init_one(dst, ciphertext_buf, PAGE_SIZE);

	do { // start first batch anyway

#ifdef EXTRA_CREDIT
		crypto_blkcipher_set_iv (cipher_handle, (const u8 *) &iter, 4);
#endif
		// buf contains plain text
		bytes_read = vfs_read(ifp, plaintext_buf, PAGE_SIZE, &ifp->f_pos);

		if (bytes_read < 0) { // DANGER ZONE, raise alarm
			printk("Raeding from file failed\n");
			err = -EFAULT;
			goto cleanup;
		}
		else if (bytes_read == PAGE_SIZE) { //Full read:Yet to reach at the last batch

			// perform encrpyt here
#ifdef EXTRA_CREDIT
			ret = crypto_blkcipher_encrypt_iv(&desc, dst, src, PAGE_SIZE);
#else
			ret = crypto_blkcipher_encrypt(&desc, dst, src, PAGE_SIZE);
#endif
			if (ret < 0) {
				printk("Error in encryting plaintext\n");
				err = -EFAULT;
				goto cleanup;
			}

			bytes_written = vfs_write(ofp, ciphertext_buf, PAGE_SIZE, &ofp->f_pos);
			if (bytes_written < 0) {
				printk("Writing to file failed\n");
				err = -EACCES;
				goto cleanup;
			}
#ifdef DEBUG
			printk("Read: %d bytes, wrote: %d bytes, Full read: %d\n",\
					bytes_read, bytes_written, iter);
#endif
		}
		else if (bytes_read < PAGE_SIZE) {
			done = true; // finished the process

#ifdef EXTRA_CREDIT
			ret = crypto_blkcipher_encrypt_iv(&desc, dst, src, bytes_read);
#else
			ret = crypto_blkcipher_encrypt(&desc, dst, src, bytes_read);
#endif
			if (ret < 0) {
				printk("Error in encryting plaintext\n");
				err = -EFAULT;
				goto cleanup;
			}

			bytes_written = vfs_write(ofp, ciphertext_buf, bytes_read,\
					&ofp->f_pos);
			if (bytes_written < 0) {
				printk("Writing to file failed\n");
				err = -EFAULT;
				goto cleanup;
			}
		}
		else {
			printk("Reading from file failed\n");
			err = -EACCES;
			goto cleanup;
		}
		iter++;
	} while(!done);

	lock_rename(ofp->f_path.dentry->d_parent,\
			dest_file->f_path.dentry->d_parent);

	// rename temp file to destination file
	ret = vfs_rename(ofp->f_path.dentry->d_parent->d_inode,\
			ofp->f_path.dentry, \
			dest_file->f_path.dentry->d_parent->d_inode, \
			dest_file->f_path.dentry, NULL, 0);

	unlock_rename(ofp->f_path.dentry->d_parent,\
			dest_file->f_path.dentry->d_parent);

	if (ret != 0) {
		printk("Error in renaming.\n");
		err = -EINVAL;
		goto cleanup; // rename is part of output writing
	}

	goto out; // skip cleanup, all went fine


cleanup:
	ret = vfs_unlink(ofp->f_path.dentry->d_parent->d_inode, ofp->f_path.dentry, NULL);
	if (ret != 0) {
		printk("Error in deleting temp file.\n");
		err = -EINVAL;
		goto out;
	}

	if (dest_file_doesnt_exist) { // process created it fresh
		//unlink dest_file
		ret = vfs_unlink(dest_file->f_path.dentry->d_parent->d_inode, dest_file->f_path.dentry, NULL);
		if (ret != 0) {
			printk("Error in deleting outfile.\n");
			err = -EINVAL;
			goto out;
		}
	}

	// get back to old file system
	set_fs(old_fs);

out:
	if(tempfile)
		kfree(tempfile);

	if (!IS_ERR(cipher_handle)) {
		crypto_free_blkcipher(cipher_handle);
	}

	// close only if it was successfully opened
	if (!IS_ERR((void *)ifp) && (ifp != NULL)) {
		filp_close(ifp, NULL);
	}
	if (!IS_ERR((void *)ofp) && (ofp != NULL)) {
		filp_close(ofp, NULL);
	}
	if (!IS_ERR((void *)dest_file) && (dest_file != NULL)) {
		filp_close(dest_file, NULL);
	}

	if (plaintext_buf)
		kfree(plaintext_buf);
	if (ciphertext_buf)
		kfree(ciphertext_buf);
	if (ciphered_key)
		kfree(ciphered_key);
	if (src)
		kfree(src);
	if (dst)
		kfree(dst);

	return err;


}

/********************************
 * Supporting the MD5 right now
 * will add more algos support later.
 *******************************/
int checksum(char *infile) {
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct file *f_in, *f_out;
	unsigned char *hash_buff, *buf, *outfile, temp[2];
	int i, bytes, pending, cur, err = 0;
	mm_segment_t oldfs;

	if(!infile){
		printk(KERN_ALERT "input file is invalid\n");
		err = -EINVAL;
		goto out;
	}

	hash_buff = kzalloc(DIGEST_SIZE, GFP_KERNEL);
	if (!hash_buff)
	{
		err = -ENOMEM;
		goto out;
	}

	outfile = kzalloc(strlen(infile) + 5, GFP_KERNEL);
	if (!outfile)
	{
		err = -ENOMEM;
		goto outfree;
	}
	/********************************************************
	* new file will have name as "infile.md5"
	********************************************************/
	strcpy(outfile, infile);
	strncat(outfile, ".md5", 4);

	//printk(KERN_INFO "outfile = %s\n", outfile);
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	f_in = filp_open(infile, O_RDONLY, 0);
	if (!f_in || IS_ERR(f_in))
	{
		err = PTR_ERR(f_in);
		set_fs(oldfs);
		goto outfilefree;
	}

	f_out = filp_open(outfile, O_WRONLY|O_CREAT, 0);
	if (!f_out || IS_ERR(f_out))
	{
		err = PTR_ERR(f_out);
		set_fs(oldfs);
		goto filpclose;
	}

	pending = f_in->f_op->llseek(f_in, 0, SEEK_END);
	f_in->f_pos = 0;
	cur = pending > PAGE_SIZE ? PAGE_SIZE: pending;
	buf = kzalloc(cur, GFP_KERNEL);
	if (!buf)
	{
		err = -ENOMEM;
		set_fs(oldfs);
		goto ofilpclose;
	}
	tfm = crypto_alloc_hash("md5", 0, 0);
	desc.tfm = tfm;
	desc.flags = 0;
	crypto_hash_init(&desc);

	//printk(KERN_INFO " Hash Init done \n");
	do{
		pending -= cur;
		bytes = vfs_read(f_in, buf, cur, &f_in->f_pos);
		sg_init_one(&sg, buf, bytes);
		crypto_hash_update(&desc, &sg, bytes);
	}while(pending > 0);
	crypto_hash_final(&desc, hash_buff);
	//printk(KERN_INFO "final buf = %s\n", hash_buff);
	for (i=0; i<DIGEST_SIZE; i++)
	{
		sprintf(temp, "%02x", hash_buff[i]);
	}

	bytes = vfs_write(f_out, hash_buff, strlen(hash_buff), &f_out->f_pos);
	set_fs(oldfs);
	if(buf)
		kfree(buf);
ofilpclose:
	if (f_out)
		filp_close(f_out, NULL);
filpclose:
	if (f_in)
		filp_close(f_in, NULL);
outfilefree:
	if (outfile)
		kfree(outfile);
outfree:
	if (hash_buff)
		kfree(hash_buff);
out:
	return err;
}
