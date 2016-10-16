#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/vmalloc.h>
#include <linux/skbuff.h> 
#include <linux/ip.h> 
#include <linux/tcp.h>

//#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
//#define __KERNEL__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gerard");
MODULE_DESCRIPTION("Network packet filter");

/* hook fn structs defined by netfilter.h */
static struct nf_hook_ops nfho_rcv;   /* hook for received packets */
static struct nf_hook_ops nfho_trm;    /* hook for transmitted packets */

/* hook fn for received packets as defined by netfilter.h */
static unsigned int nf_rcv_hook_fn(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;          /* IPv4 header */
    struct tcphdr *tcph;        /* TCP header */
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    unsigned char *user_data;   /* TCP data begin pointer */
    unsigned char *tail;        /* TCP data end pointer */
    unsigned char *it;          /* TCP data iterator */

  /* Network packet is empty, seems like some problem occurred. Skip it */
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);          /* get IP header */

    tcph = tcp_hdr(skb);        /* get TCP header */

    /* Convert network endianness to host endiannes */
    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    printk(KERN_INFO "[GS] received packet info: %pI4h:%d -> %pI4h:%d\n", &saddr, sport, &daddr, dport);

    return NF_ACCEPT;
}

/* Hook fn for transmitted packets as defined by netfilter.h */
static unsigned int nf_trm_hook_fn(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;          /* IPv4 header */
    struct tcphdr *tcph;        /* TCP header */
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    unsigned char *user_data;   /* TCP data begin pointer */
    unsigned char *tail;        /* TCP data end pointer */
    unsigned char *it;          /* TCP data iterator */

  /* Network packet is empty, seems like some problem occurred. Skip it */
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);          /* get IP header */

    tcph = tcp_hdr(skb);        /* get TCP header */

    /* Convert network endianness to host endiannes */
    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    printk(KERN_INFO "[GS] transmitted packet info: %pI4h:%d -> %pI4h:%d\n", &saddr, sport, &daddr, dport);

    return NF_ACCEPT;

}

static int init_rcv_filter(void)
{
  nfho_rcv.hook = nf_rcv_hook_fn; /* Assign defined hook for received packets */
  nfho_rcv.hooknum = NF_INET_PRE_ROUTING; /* Received packets */
  nfho_rcv.pf = PF_INET; /* Hook only IPv4 packets */
  nfho_rcv.priority = NF_IP_PRI_FIRST; /* Max priority hook */

  int hook_result;
  hook_result = nf_register_hook(&nfho_rcv);
  if (hook_result < 0) {
    printk(KERN_ERR "[GS] cannot register hook for received packets");
  }
  return hook_result;
}

static int init_trm_filter(void)
{
  nfho_trm.hook = nf_trm_hook_fn; /* Assign defined hook for tramsitted packets */
  nfho_trm.hooknum = NF_INET_POST_ROUTING; /* Transmitted packets */
  nfho_trm.pf = PF_INET; /* Hook only IPv4 packets */
  nfho_trm.priority = NF_IP_PRI_FIRST; /* Max priority hook */

  int hook_result;
  hook_result = nf_register_hook(&nfho_trm);
  if (hook_result < 0) {
    printk(KERN_ERR "[GS] cannot register hook for transmitted packets");
  }
  return hook_result;
}

/* Module init and cleanup */
int __init netfilter_init(void)
{
    printk(KERN_INFO "[GS] network filter module startup.\n");
    init_rcv_filter();
    init_trm_filter();
    printk(KERN_INFO "[GS] rcv and trm hooks registered, startup completed");
    return 0;    /* Non-zero return for unsuccessfully module startup */ 
}

void __exit netfilter_cleanup(void)
{
  printk(KERN_INFO "[GS] finishing netfilter module, starting cleanup");
  nf_unregister_hook(&nfho_rcv);
  //nf_unregister_hook(&nfho_trm);
  printk(KERN_INFO "[GS] hooks unregistered, cleanup completed.\n");
}

module_init(netfilter_init);
module_exit(netfilter_cleanup);