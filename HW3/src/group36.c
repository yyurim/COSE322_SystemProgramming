#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/netfilter_ipv4.h>

#include <linux/string.h>

#define PROC_DIRNAME "group36"  // proc directory name
#define FILENAME_ADD "add"      // proc file to add black list
#define FILENAME_SHOW "show"    // proc file to show black list
#define FILENAME_DEL "del"      // proc file to delete black list


#define WRITE_BUFSIZE 50        // command buffer : add/delete
#define SHOW_BUFSIZE 200        // show buffer
#define PORT_MAX 50             // maximum black list number

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *add_file;
static struct proc_dir_entry *show_file;
static struct proc_dir_entry *del_file;

// struct to manage ports to be filtered
typedef struct _port
{
	char type;
	int num;
}port;


static port black_list[PORT_MAX];	// list of ports to be filtered
static int port_size;		        // size of black list

static bool finish_cat = true;      // flag variable to finish "cat"

// convert string to struct iphdr->addr
unsigned int as_addr_to_net(char *str)
{
	unsigned char arr[4];
	sscanf(str, "%d.%d.%d.%d", &arr[0], &arr[1], &arr[2], &arr[3]);
	return *(unsigned int *)arr;
}


// customized hook : monitor NF_INET_PRE_ROUTING
// packet sanity check, before routing
// specifically deal with proxy
static unsigned int hook_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// get ip header of skb
	struct iphdr *ih = ip_hdr(skb);

	// get tcp header of skb
	struct tcphdr *th = tcp_hdr(skb);

	int sport, dport;               // source port, destination port
	char saddr[16], daddr[16];      // source ip address, destination ip address
	bool syn,fin,ack,rst;           // tcp flags

	int i;                          // iterator to manage black list

	snprintf(saddr, 16, "%pI4", &ih->saddr);    // formatted print as IP
	snprintf(daddr, 16, "%pI4", &ih->daddr);    // formatted print as IP
	sport = ntohs(th->source);                  // format source port info in tcp header
	dport = ntohs(th->dest);                    // format destination port info in tcp header

	//  get tcp flags from tcp header
	syn = th->syn;
	fin = th->fin;
	ack = th->ack;
	rst = th->rst;

	// filtering : whether this packet must be filterted or not : cannot come in local?
	for(i = 0 ; i < port_size ; i++)
	{
		// if source port of this packet is in the black list with flag I,
		// drop this packet before routing
		if((black_list[i].num==sport)&&(black_list[i].type=='I')){
			// logging
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n","DROP(INBOUND)", ih->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
			return NF_DROP;
		}
        // if source port of this packet is in the black list with flag P,
        // this packet is for proxy
        else if((black_list[i].num==sport)&&(black_list[i].type=='P'))
		{

			// proxy destination
			ih->daddr = as_addr_to_net("131.1.1.1");
			th->dest = th->source;

			// logging
			snprintf(saddr, 16, "%pI4", &ih->saddr);    // formatted print as IP
			snprintf(daddr, 16, "%pI4", &ih->daddr);    // formatted print as IP
			dport = (unsigned int)(th->dest);
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n","PROXY(INBOUND)", ih->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);

			//  get this packet in local for routing
			return NF_ACCEPT;
        }
	}

	// logging
	printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n","INBOUND", ih->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);

	//  get this packet in local
	return NF_ACCEPT;
}

// overload hook functions for pre-routing
static struct nf_hook_ops hook_pre_routing_ops = {
	.hook = hook_pre_routing,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};

// customized hook : monitor NF_INET_FORWARD
static unsigned int hook_forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// get ip header of skb
	struct iphdr *ih = ip_hdr(skb);

	// get tcp header of skb
	struct tcphdr *th = tcp_hdr(skb);

	int sport, dport;               // source port, destination port
	char saddr[16], daddr[16];      // source ip address, destination ip address
	bool syn,fin,ack,rst;           // tcp flags

	int i;                          // iterator to manage black list

	snprintf(saddr, 16, "%pI4", &ih->saddr);    // formatted print as IP
	snprintf(daddr, 16, "%pI4", &ih->daddr);    // formatted print as IP
	sport = ntohs(th->source);                  // format source port info in tcp header
	dport = ntohs(th->dest);                    // format destination port info in tcp header

	//  get tcp flags from tcp header
	syn = th->syn;
	fin = th->fin;
	ack = th->ack;
	rst = th->rst;

	// filtering : whether this packet must be filterted or not : must be forwarded?
	for(i = 0 ; i < port_size ; i++)
	{
		// if source port of this packet is in the black list with flag F,
		// drop this packet before forwarding
		if((black_list[i].num==sport)&&(black_list[i].type=='F')){
		// logging
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n","DROP(FORWARD)", ih->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
 			return NF_DROP;
		}
	}

	// logging
	printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n","FORWARD", ih->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);

	//  forward this packet
	return NF_ACCEPT;
}

// overload hook functions for forwarding
static struct nf_hook_ops hook_forward_ops = {
	.hook = hook_forward,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FIRST
};


// customized hook : monitor NF_INET_POST_ROUTING
static unsigned int hook_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// get ip header of skb
	struct iphdr *ih = ip_hdr(skb);

	// get tcp header of skb
	struct tcphdr *th = tcp_hdr(skb);

	int sport, dport;               // source port, destination port
	char saddr[16], daddr[16];      // source ip address, destination ip address
	bool syn,fin,ack,rst;           // tcp flags

	int i;                          // iterator to manage black list

	snprintf(saddr, 16, "%pI4", &ih->saddr);    // formatted print as IP
	snprintf(daddr, 16, "%pI4", &ih->daddr);    // formatted print as IP
	sport = ntohs(th->source);                  // format source port info in tcp header
	dport = ntohs(th->dest);                    // format destination port info in tcp header

	//  get tcp flags from tcp header
	syn = th->syn;
	fin = th->fin;
	ack = th->ack;
	rst = th->rst;

    	// filtering : whether this packet must be filterted or not : safe destination?
	for(i = 0 ; i < port_size ; i++)
	{
		// if destination port of this packet is in the black list with flag O,
		// drop this packet as destination may not be safe
		if((black_list[i].num==dport)&&(black_list[i].type=='O')){
		// logging
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n","DROP(OUTBOUND)", ih->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
			return NF_DROP;
		}
	}

	// logging
	printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n","OUTBOUND", ih->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
	return NF_ACCEPT;
}

// overload hook functions for post routing
static struct nf_hook_ops hook_post_routing_ops = {
	.hook = hook_post_routing,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST
};


// customized open : to manage the black list
static int as_open(struct inode *inode, struct file *file)
{
    // action : show? add? delete? the black list
	char const* const str = file->f_path.dentry->d_name.name;
	printk(KERN_INFO "proc file open : %s.\n",str);
	
	return 0;
}

// customized read : to check black list information
static ssize_t as_show(struct file *file, char __user *ubuf, size_t size, loff_t *ppos)
{
	int len = 0;                    // legth of black list info : rules
	char buf[SHOW_BUFSIZE];         // temp buffer for deliver rules to user

	int i;                          // iterator to manage the rules

	// to finish "cat"
	if(!finish_cat){
		finish_cat = true;
	}
	else{
		finish_cat = false;
		return 0;
	}

	// print all the rules to temp buffer
	for(i = 0 ; i < port_size ; i++)
	{
		char port_info[20]; // info of one rule
		int port_info_len;  // length of info of one rule
		sprintf(port_info, "%d(%c) %d\n", i, black_list[i].type, black_list[i].num);

		// concate one rule to temp buffer
        	sprintf(buf+len, "%s", port_info);

		port_info_len = strlen(port_info);

		len += port_info_len;
   
	}

	// print temp buffer to user space
	if(copy_to_user(ubuf, buf, len))
	{
		char* err_msg = "fail to copy to user\n";
        	printk(KERN_INFO "          %s", err_msg);
		return 0;
	}

	// move file pointer
	*ppos = len;    

	return len;
}

// overloading : show as read operation as it reads the black list
static const struct file_operations show_fops = {
	.owner = THIS_MODULE,
	.open = &as_open,
	.read = &as_show,
};

// customized write : to add filtering ports
static ssize_t as_add(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
	int len = 0;            // length of command

	char buf[WRITE_BUFSIZE];

	char add_port_type;		// filtering type
	int add_port_num;       // port to be filterted

	// copy commands from user space to kernel
	if(copy_from_user(buf, ubuf, size))
	{
		char* err_msg = "fail to copy from user";
		printk(KERN_INFO "      %s\n",err_msg);
		return 0;
	}

	// analyze the command, and get a rule
	sscanf(buf, "%c %d", &add_port_type, &add_port_num);

	// add the rule to black list
	black_list[port_size].type = add_port_type;
	black_list[port_size].num = add_port_num;


	// increase length of the black list
	port_size++;

	len = strlen(buf);
	*ppos = len;

	return len;
}

// overloading : add as write operation as it modifies the black list
static const struct file_operations add_fops = {
	.owner = THIS_MODULE,
	.open = &as_open,
	.write = &as_add,
};

// customized write : to delete filtering ports
static ssize_t as_del(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
	int len = 0;            // length of command

	char buf[WRITE_BUFSIZE];

	int del_port_idx;		// filtering ports to be deleted

	int i;                  // iterator to manage the rules

	// copy commands from user space to kernel
	if(copy_from_user(buf, ubuf, size))
	{
		char* err_msg = "fail to copy from user";
		printk(KERN_INFO "      %s\n",err_msg);
		return 0;
	}

	// analyze the command, and get a rule : get index of rule to be deleted
	sscanf(buf, "%d", &del_port_idx);

	// decrease size of the black list
	port_size--;

	// erase the rule with the index
	for(i = del_port_idx ; i < port_size ; i++)
	{
		black_list[i] = black_list[i+1];
	}

	len = strlen(buf);
	*ppos = len;

	return len;
}

// overloading : del as write operation as it modifies the black list
static const struct file_operations del_fops = {
	.owner = THIS_MODULE,
	.open = &as_open,
	.write = &as_del,
};


// initialize : make proc file
static int __init simple_init(void)
{
	printk(KERN_INFO "Simple Module Init!!\n");

	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	add_file = proc_create(FILENAME_ADD, 0777, proc_dir, &add_fops);
	show_file = proc_create(FILENAME_SHOW, 0777, proc_dir, &show_fops);
	del_file = proc_create(FILENAME_DEL, 0777, proc_dir, &del_fops);

	nf_register_hook(&hook_pre_routing_ops);
	nf_register_hook(&hook_forward_ops);
	nf_register_hook(&hook_post_routing_ops);

	return 0;
}

// When dispatching this module, remove all this module made
static void __exit simple_exit(void)
{
	printk(KERN_INFO "Simple Module Exit!!\n");

	remove_proc_entry(FILENAME_ADD, proc_dir);
	remove_proc_entry(FILENAME_SHOW, proc_dir);
	remove_proc_entry(FILENAME_DEL, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);

	nf_unregister_hook(&hook_pre_routing_ops);
	nf_unregister_hook(&hook_forward_ops);
	nf_unregister_hook(&hook_post_routing_ops);

	return;
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("YUNYURIM");
MODULE_DESCRIPTION("It's Simple!!");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");









