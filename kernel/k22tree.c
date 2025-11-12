// SPDX-License-Identifier: GPL-2.0

#include <linux/k22info.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/types.h>

struct queue_node {
	struct task_struct *task;
	struct list_head node;
};

// https://manpages.debian.org/testing/linux-manual-4.11/
// https://docs.kernel.org/core-api/list.html

static int traverse(struct k22info *buf, int limit)
{
	int count = 0;

	struct k22info *kbuf = kmalloc_array(limit, sizeof(struct k22info), GFP_KERNEL);

	if (!kbuf)
		return -ENOMEM;

	struct queue_node *start_node = kmalloc(sizeof(struct queue_node), GFP_KERNEL);

	if (!start_node) {
		kfree(kbuf);
		return -ENOMEM;
	}
	start_node->task = &init_task;

	struct list_head queue;

	INIT_LIST_HEAD(&queue);

	list_add(&start_node->node, &queue);

	read_lock(&tasklist_lock);

	// Stack is not empty
	while (!list_empty(&queue)) {
		// Get first entry of stack
		struct queue_node *current_node = list_first_entry(&queue, struct queue_node, node);
		struct task_struct *curr = current_node->task;

		// Pop from stack & free
		list_del(&current_node->node);
		kfree(current_node);

		// Check if read items exceed limit given by user
		if (count < limit) {
			struct k22info n;

			get_task_comm(n.comm, curr);
			n.pid = curr->pid;
			n.parent_pid = task_pid_vnr(curr->real_parent);
			n.nvcsw = curr->nvcsw;
			n.nivcsw = curr->nivcsw;
			n.start_time = curr->start_time;

			struct task_struct *first_child = NULL;

			list_for_each_entry(first_child, &curr->children, sibling) {
				// Ensure child is a process and current is not last
				if (first_child == NULL ||
					task_pid_vnr(first_child) == curr->pid ||
					thread_group_leader(first_child))
					break;
			}
			n.first_child_pid = first_child == NULL ? 0 : task_pid_vnr(first_child);

			struct task_struct *next_sibling = NULL;

			list_for_each_entry(next_sibling, &curr->sibling, sibling) {
				// Ensure sibling is a process and current is not last
				if (next_sibling == NULL ||
					task_pid_vnr(next_sibling) == curr->pid ||
					thread_group_leader(next_sibling))
					break;
			}
			n.next_sibling_pid = next_sibling == NULL ? 0 : task_pid_vnr(next_sibling);

			// Copy struct to temp buffer
			kbuf[count] = n;
		}
		count++;

		// For each child of current process
		struct task_struct *child;

		list_for_each_entry_reverse(child, &curr->children, sibling) {
			if (thread_group_leader(child)) {
				// Child is process, push to stack
				struct queue_node *child_node =
					kmalloc(sizeof(struct queue_node), GFP_KERNEL);

				if (!child_node) {
					kfree(kbuf);
					return -ENOMEM;
				}
				child_node->task = child;
				list_add(&child_node->node, &queue);
			}
		}
	}

	read_unlock(&tasklist_lock);

	unsigned long err = copy_to_user(buf, kbuf, (size_t) limit * sizeof(struct k22info));

	kfree(kbuf);

	return err ? -EFAULT : count;
}

static int k22tree(struct k22info *buf, int *ne)
{
	if (!buf || !ne)
		return -EINVAL;

	if (!access_ok(ne, sizeof(int)))
		return -EFAULT;

	int size;

	if (copy_from_user(&size, ne, sizeof(int)))
		return -EFAULT;

	if (size < 1)
		return -EINVAL;

	return traverse(buf, size);
}

SYSCALL_DEFINE2(k22_tree, struct k22info __user *, buf, int __user *, ne)
{
	return k22tree(buf, ne);
}
