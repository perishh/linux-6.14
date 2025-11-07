#include <linux/k22info.h>

struct queue_node {
	struct task_struct* task;
	struct list_head node;
};

// https://manpages.debian.org/testing/linux-manual-4.11/
// https://docs.kernel.org/core-api/list.html
int traverse(struct task_struct *start, struct k22info *buf, int limit) {
	int count = 0;

	struct queue_node *start_node = kmalloc(sizeof(struct queue_node), GFP_KERNEL);
	start_node->task = start;

	struct list_head queue;
	INIT_LIST_HEAD(&queue);

	list_add(&start_node->node, &queue);

	// Stack is not empty
	while(!list_empty(&queue)) {
		// Get first entry of stack
		struct queue_node *parent_node = list_first_entry(&queue, struct queue_node, node);
		struct task_struct *parent = parent_node->task;

		// Pop from stack & free
		list_del(&parent_node->node);
		kfree(parent_node);

		if(count < limit) {
			struct k22info n;
			// Copy name
			if(TASK_COMM_LEN >= 64) {
				memcpy(&n.comm, &parent->comm, 64);
				n.comm[63] = '\0'; // Ensure string ends;
			}else {
				memcpy(&n.comm, &parent->comm, TASK_COMM_LEN);
				n.comm[TASK_COMM_LEN] = '\0'; // Ensure string ends;
			}
			n.pid = parent->pid;
			n.parent_pid = task_pid_vnr(parent->real_parent);
			struct task_struct *first_sibling = list_entry(&parent->sibling, struct task_struct, sibling);
			n.next_sibling_pid = first_sibling->pid;
			struct task_struct *first_child = list_entry(&parent->children, struct task_struct, children);
			n.first_child_pid = first_child->pid;
	
			// Copy struct to user space on buffer
			copy_to_user(buf + count, &n, sizeof(struct k22info));
		}
		count++;
		
		// For each child of current process
		struct task_struct *child;
		list_for_each_entry(child, &parent->children, sibling) {
			// Push child processes to stack
			struct queue_node *child_node = kmalloc(sizeof(struct queue_node), GFP_KERNEL);
			child_node->task = child;
			list_add(&child_node->node, &queue);

			pr_info("[K22] Adding %d\n", child->pid);
		}
	}

	return count;
}

int k22tree(struct k22info *buf, int *ne) {
	int size;
	copy_from_user(&size, ne, sizeof(int));

	struct pid* pid_struct = find_get_pid(1);
	struct task_struct *parent = pid_task(pid_struct, PIDTYPE_PID);

	int count = traverse(parent, buf, size);

	put_pid(pid_struct);
	return count;
}

SYSCALL_DEFINE2(k22_tree, struct k22info __user *, buf, int __user *, ne)
{
	return k22tree(buf, ne);
}