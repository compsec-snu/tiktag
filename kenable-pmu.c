#include <linux/types.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>


/* PMU related */
#define ARMV8_PMCR_E            (1 << 0) /* Enable all counters */
#define ARMV8_PMCR_P            (1 << 1) /* Reset all counters */
#define ARMV8_PMCR_C            (1 << 2) /* Cycle counter reset */
#define ARMV8_PMCNTENSET_EL0_EN (1 << 31) /* Performance Monitors Count Enable Set register */
#define ARMV8_PMUUSERNR_EN      (1 << 0)

void pmu_test_init(void);

static int kpmu_proc_show(struct seq_file *m, void *v) {
	return 0;
}

static int kpmu_proc_open(struct inode *inode, struct file *file) {
	pmu_test_init();
	return single_open(file, kpmu_proc_show, NULL);
}

static ssize_t kpmu_write(struct file *file, const char __user *buf,
                                  size_t count, loff_t *ppos)
{
  return count;
}

static const struct proc_ops kpmu_proc_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_open = kpmu_proc_open,
	.proc_write = kpmu_write,
	.proc_release = single_release,
};

int __init kpmu_init(void)
{
	printk("Enable user PMU init\n");

	proc_create("enable-pmu", 0, NULL, &kpmu_proc_fops);

	return 0;
}

fs_initcall(kpmu_init);

static void init_pmu(void) {
     unsigned long value = 0;
     asm volatile("MRS %0, PMCR_EL0" : "=r" (value));
     value |= ARMV8_PMCR_E;
     value |= ARMV8_PMCR_C;
     value |= ARMV8_PMCR_P;
     asm volatile("MSR PMCR_EL0, %0" : : "r" (value));
     asm volatile("MRS %0, PMCNTENSET_EL0" : "=r" (value));
     value |= ARMV8_PMCNTENSET_EL0_EN;
     asm volatile("MSR PMCNTENSET_EL0, %0" : : "r" (value));
 
     /* user enable */
     asm volatile("MRS %0, PMUSERENR_EL0" : "=r" (value));
     value |= ARMV8_PMUUSERNR_EN;
     asm volatile("MSR PMUSERENR_EL0, %0" :: "r" (value));
}

void pmu_test_init(void)
{
    init_pmu();
}

