/*
writer : Yun Yurim
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define PROC_DIRNAME "myproc"
#define PROC_FILENAME "myproc"

#define q_MAX 1000

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

// to use kernel's circular queue
typedef struct _sphw
{
	const char* fs_name;			// file system name : ext4 / f2fs
	long time;						// write time
	unsigned long long block_no;	// block number
}sphw;


extern sphw c_q[q_MAX];				// the circular queue in kernel
extern int q_front;					// front of the circular queue, also in kernel
extern void push_cq(sphw value);	// function for the circular queue
									// 		insert sphw at the front of the circular queue
									//		also in kernel

// buffer for copying information proc file in kernel to userspace
char result[q_MAX][100];

// customized open : open proc file
static int my_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "Simple Module Open!!\n");

	return 0;
}

// customized write : write sphw info to proc file
static ssize_t my_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos)
{
	int i;
	printk(KERN_INFO "Simple Module Write!!\n");

	// Buffering
	// 		Pop queue from front to front-1, as there's no information of q_rear
	for(i = q_front ; i != (q_front-1 >= 0 ? q_front-1 : q_front-1+q_MAX) ; i=(i+1)%q_MAX)
	{
		sprintf(result[i], "time : %ld || FS_name : %s || block_no : %llu\n",c_q[i].time, c_q[i].fs_name, c_q[i].block_no);
	}

	return count;
}

// customized read : read sphw info to proc file
static ssize_t my_read(struct file *file, char __user *user_buffer, size_t count, loff_t *ppos)
{
	printk(KERN_INFO "Simple Module Read!!\n");

	// Read buffered information
	//		Copying information in proc file to userspace
	if(copy_to_user(user_buffer, result, sizeof(result)))
	{
		return -EFAULT;
	}

	return count;
}

// overloading
static const struct file_operations myproc_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = my_write,
	.read = my_read,
};

// initialize : make proc file
static int __init simple_init(void)
{
	printk(KERN_INFO "Simple Module Init!!\n");

	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_file = proc_create(PROC_FILENAME, 0600, proc_dir, &myproc_fops);

	return 0;
}

// When dispatching this module, remove all this module made
static void __exit simple_exit(void)
{
	printk(KERN_INFO "Simple Module Exit!!\n");

	remove_proc_entry(PROC_FILENAME, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);

	return;
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("YUNYURIM");
MODULE_DESCRIPTION("It's Simple!!");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");








