#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gerard");
MODULE_DESCRIPTION("Hello world");

void hide_module(void) 
{
	list_del(&THIS_MODULE->list);
}

int init_module(void)
{
	//hide_module();
	printk(KERN_INFO "[GS] hello world!");
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "[GS] bye hello world!");
}