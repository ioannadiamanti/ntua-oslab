/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < Your name here >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));
	/* ? */
	if(state->buf_timestamp != sensor->msr_data[state->type]->last_update){
		return 1;
	}
	else{
		/* The following return is bogus, just for the stub to compile */
		return 0; /* ? */
	}
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	uint32_t temp;
	long m,d,x;

	debug("leaving\n");

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	/* ? */
	WARN_ON ( !(sensor = state->sensor));
	
	if(!lunix_chrdev_state_needs_refresh(state)){
		spin_unlock_irq(&sensor->lock);
	 	return -EAGAIN;
	 }
	spin_lock_irq(&sensor->lock); 
	temp = sensor->msr_data[state->type]->values[0];
	state->buf_timestamp = sensor->msr_data[state->type]->last_update;
	spin_unlock_irq(&sensor->lock);
	/* Why use spinlocks? See LDD3, p. 1119 */

	/*
	 * Any new data available?
	 */

	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */

	/* ? */
	if(state->type == 0){
		x = lookup_voltage[temp];
	}
	else if (state->type == 1){
		x = lookup_temperature[temp];
	}
	else{
		x = lookup_light[temp];
	}
	m = x%1000;
	if(m<0) m = m*(-1);
	d = x/1000;
	state->buf_lim = sprintf(state->buf_data,"%ld.%ld",d,m);
	
	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */


	struct lunix_chrdev_state_struct *state;
	int mi;
	int ret;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0){
		debug("I'm going to out\n");
		goto out;
	}
	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	
	
	/* Allocate a new Lunix character device private state structure */
	/* ? */
	state = kmalloc(sizeof(struct lunix_chrdev_state_struct),GFP_KERNEL);
	mi = iminor(inode);
	state->type = mi%8;
	state->sensor = &lunix_sensors[mi/8];
	state->buf_timestamp=0;
	state->buf_lim = 0;
	sema_init(&state->lock, 1);
	filp->private_data = state;
	debug("SUCCESSFUL INITIALIZATION\n");
	

out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/* ? */
	debug("releasing state struct\n");
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	debug("requesting to read %zu bytes",cnt);
	/* Lock? */
	if(down_interruptible(&state->lock)) return -ERESTARTSYS;
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		debug("no data in buffer\n");
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* ? */
			debug("waiting for an update\n");
			up(&state->lock);
			if(wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state))) return -ERESTARTSYS;
			if(down_interruptible(&state->lock)) return -ERESTARTSYS;
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
		}
	}
	debug("got new data\n");
	/* End of file */
	/* ? */
	
	/* Determine the number of cached bytes to copy to userspace */
	/* ? */
	if (*f_pos + cnt > state->buf_lim) cnt=state->buf_lim-*f_pos;
	if(copy_to_user(usrbuf,&state->buf_data[*f_pos],cnt)){
		ret = -EFAULT;
		goto out;
	}
	debug("successful copy to user\n");
	*f_pos+=cnt;
  	ret = cnt;
	/* Auto-rewind on EOF mode? */
	/* ? */
	if(*f_pos == state->buf_lim) *f_pos =0;
out:
	/* Unlock? */
	up(&state->lock);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
        .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no= MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/* ? */
	/* register_chrdev_region? */
	ret = register_chrdev_region(dev_no,128,"lunix");

	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/* ? */
	/* cdev_add? */
	ret=cdev_add (&lunix_chrdev_cdev, dev_no, 128);

	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering destroy\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
