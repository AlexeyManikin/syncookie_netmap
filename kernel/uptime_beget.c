#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/cryptohash.h>
#include <net/tcp.h>

static u32 (*syncookie_secret_ptr)[2][16-4+SHA_DIGEST_WORDS];

static int uptime_proc_show_beget(struct seq_file *m, void *v)
{
	int i, j;
	seq_printf(m, "%lu %lu\n", (unsigned long) jiffies, (unsigned long)tcp_cookie_time());
	for(i = 0; i < 2; i++) {
		for(j = 0; j < 16-4+SHA_DIGEST_WORDS; j++) {
			seq_printf(m, "%.8x.", (*syncookie_secret_ptr)[i][j]); 
		}
	}
	seq_printf(m, "\n");
	return 0;
}

static int uptime_proc_open_beget(struct inode *inode, struct file *file)
{
	return single_open(file, uptime_proc_show_beget, NULL);
}

static const struct file_operations uptime_proc_fops_beget = {
	.open		= uptime_proc_open_beget,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int symbol_walk_callback(void *data, const char *name,
				struct module *mod, unsigned long addr) {
	if (mod)
		return 0;

	if (strcmp(name, "syncookie_secret") == 0) {
		syncookie_secret_ptr = (void *)addr;
	}
	return 0;
}

static int __init beget_uptime_init(void)
{
	int rc = kallsyms_on_each_symbol(symbol_walk_callback, NULL);
	if (rc)
		return rc;
	return proc_create("beget_uptime", 0, NULL, &uptime_proc_fops_beget) == NULL;
}

module_init(beget_uptime_init);

static void __exit beget_uptime_exit(void)
{
	remove_proc_entry("beget_uptime", 0);
}

module_exit(beget_uptime_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Polyakov <apolyakov@beget.ru>");
MODULE_DESCRIPTION("Show kernel variable to syncookie_netmap");
MODULE_VERSION("1.0");
