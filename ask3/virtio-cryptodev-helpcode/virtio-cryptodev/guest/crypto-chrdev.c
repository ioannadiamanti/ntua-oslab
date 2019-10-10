/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist *sgs[2],syscall_type_sg,host_fd_sg;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	/* ?? */
	spin_lock_irq(&crdev->lock);
	
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[0] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[1] = &host_fd_sg;
	
	if(virtqueue_add_sgs(crdev->vq, sgs, 1,1,&syscall_type_sg, GFP_ATOMIC)<0){
		debug("Failed to get host fd\n");
		ret=-EIO;
		spin_unlock_irq(&crdev->lock);
		goto fail;
	}
	if(!virtqueue_kick(crdev->vq)){
		debug("Failed to notify host for added data in vq\n");
		ret = -EIO;
		spin_unlock_irq(&crdev->lock);
		goto fail;
	}

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;

	/* If host failed to open() return -ENODEV. */
	/* ?? */

	if(*host_fd <0){
		ret = -ENODEV;
		spin_unlock_irq(&crdev->lock);
		goto fail;
	}

	crof->host_fd = *host_fd;
	spin_unlock_irq(&crdev->lock);
	
fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type,len;
	int *answer;
	struct scatterlist *sgs[3],syscall_type_sg,host_fd_sg,answer_sg;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;
	
	answer = kzalloc(sizeof(*answer), GFP_KERNEL);
	*answer = -1;
	
	/**
	 * Send data to the host.
	 **/
	/* ?? */
	spin_lock_irq(&crdev->lock);
	
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[0] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[1] = &host_fd_sg;
	
	sg_init_one(&answer_sg, answer, sizeof(*answer));
	sgs[2] = &answer_sg;
	
	if(virtqueue_add_sgs(crdev->vq, sgs, 2,1,&syscall_type_sg, GFP_ATOMIC)<0){
		debug("Could not add sgs to send host fd\n");
		ret=-EIO;
		goto fail;
	}
	if(!virtqueue_kick(crdev->vq)){
		debug("Failed to notify host for added data in vq\n");
		ret = -EIO;
		goto fail;
	}
	

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;

	if(*answer<0){
		debug("Failed to close file\n");
		ret=-EIO;
		goto fail;
	}
		
	kfree(crof);
fail:
	spin_unlock_irq(&crdev->lock);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err,*host_ret;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg,output_msg_sg, input_msg_sg,cmd_sg,sess_sg,sess_key_sg,ses_sg,crypt_op_sg,
	                   src_sg,iv_sg,dst_sg,host_ret_sg,*sgs[10];
	struct session_op *sess;
	struct crypt_op *cryp;
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	unsigned char *output_msg, *input_msg,*sess_key,*src,*iv,*dst=NULL;
	unsigned int *syscall_type,*ioctl_cmd;
	
	__u32 *ses;

	debug("Entering");
	

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	output_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	input_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;
	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;
	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	ses = kzalloc(sizeof(*ses), GFP_KERNEL);
	
	cryp = kzalloc(sizeof(*cryp), GFP_KERNEL);



	host_ret = kzalloc(sizeof(*host_ret), GFP_KERNEL);
	
	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;
	
	sg_init_one(&cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &cmd_sg;
	
	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		if(copy_from_user(sess,(struct session_op *)arg,sizeof(*sess))){
			debug("Copy sess from user failed\n");
			return -EIO;
		}
		sess_key = kzalloc(sess->keylen, GFP_KERNEL);
		if(copy_from_user(sess_key,sess->key,sess->keylen)){
			debug("Copy sess_key from user failed\n");
			return -EIO;
		}
		sg_init_one(&sess_key_sg, sess_key, sess->keylen);
		sgs[num_out++] = &sess_key_sg;
		
		memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36);
		input_msg[0] = '\0';
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		sgs[num_out + num_in++] = &input_msg_sg;
		sg_init_one(&sess_sg, sess, sizeof(*sess));
		sgs[num_out+num_in++] = &sess_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		if(copy_from_user(ses,(u_int32_t *)arg,sizeof(*ses))){
			debug("Copy ses from user failed\n");
			return -EIO;
		}
		sg_init_one(&ses_sg, ses, sizeof(*ses));
		sgs[num_out++] = &ses_sg;
		memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36);
		input_msg[0] = '\0';
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		sgs[num_out + num_in++] = &input_msg_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		
		if(copy_from_user(cryp,(struct crypt_op *)arg,sizeof(*cryp))){
			debug("Copy cryp from user failed\n");
			return -EIO;
		}
		
		iv = kzalloc(EALG_MAX_BLOCK_LEN, GFP_KERNEL);		
		if(copy_from_user(iv,cryp->iv,EALG_MAX_BLOCK_LEN)){
			debug("Copy iv from user failed\n");
			return -EIO;
		}
		
		src = kzalloc(cryp->len, GFP_KERNEL);
		if(copy_from_user(src,cryp->src,cryp->len)){
			debug("Copy src from user failed\n");
			return -EIO;
		}
		
		dst = kzalloc(cryp->len, GFP_KERNEL);
		
		sg_init_one(&crypt_op_sg, cryp, sizeof(*cryp));
		sgs[num_out++] = &crypt_op_sg;
		
		sg_init_one(&src_sg, src,cryp->len);
		sgs[num_out++] = &src_sg;
		
		sg_init_one(&iv_sg, iv, EALG_MAX_BLOCK_LEN);
		sgs[num_out++] = &iv_sg;
		
		memcpy(output_msg, "Hello HOST from ioctl CIOCCRYPT.", 33);
		input_msg[0] = '\0';
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		sgs[num_out + num_in++] = &input_msg_sg;
		
		sg_init_one(&dst_sg, dst, cryp->len);
		sgs[num_out + num_in++] = &dst_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
	sgs[num_out + num_in++] = &host_ret_sg;
		
	/* ?? Lock ?? */
	
	spin_lock_irq(&crdev->lock);
	
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
		
	spin_unlock_irq(&crdev->lock);
	
	if(*host_ret<0){
		ret= -EIO;
		debug("Ioctl failed\n");
	}
	else{
		switch(cmd){
		case CIOCGSESSION:
			if(copy_to_user((struct session_op *)arg,sess,sizeof(*sess))){
				debug("Copy sess to user failed\n");
				return -EIO;
			}
			break;
		
		case CIOCCRYPT:
			if(copy_to_user(((struct crypt_op *)arg)->dst,dst,cryp->len)){
				debug("Copy cryp to user failed\n");
				return -EIO;
			}

			break;
		case CIOCFSESSION:
			debug("Finished crypto session\n");
			break;
		default:
			debug("Unsupported ioctl command\n");
			break;
		}
	}
	
	debug("We said: '%s'", output_msg);
	debug("Host answered: '%s'", input_msg);

	kfree(output_msg);
	kfree(input_msg);
	kfree(syscall_type);
	kfree(sess);
	kfree(ses);
	kfree(cryp);
	kfree(host_ret);
	kfree(ioctl_cmd);



	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
