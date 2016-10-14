#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/vmalloc.h>

//#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
//#define __KERNEL__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gerard");
MODULE_DESCRIPTION("Network packet filter");

static struct nf_hook_ops nfho;   //net filter hook option struct

unsigned int my_hook(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))  {
    struct sock *sk = skb->sk;
    printk(KERN_INFO "[GS] => packet detected\n");
    return NF_ACCEPT;
}

static int init_filter_if(void)
{
  nfho.hook = my_hook;
  nfho.hooknum = 0 ; //NF_IP_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&nfho);

  return 0;
}

int __init netfilter_init(void)
{
    printk(KERN_INFO "Hello world!\n");
    init_filter_if();
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

void __exit netfilter_cleanup(void)
{
  nf_unregister_hook(&nfho);
  printk(KERN_INFO "[GS] Cleaning up netfilter module.\n");
}

module_init(netfilter_init);
module_exit(netfilter_cleanup);