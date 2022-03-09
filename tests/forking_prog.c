#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>

pid_t child_pid;

int main(int argc, char const *argv[])
{
	const int num_children = 5;
	pid_t children[num_children];

	printf("Hello from parent!\n");
	for (int i = 0; i < num_children; i++) {
		pid_t pid = fork();
		if (pid) {
			children[i] = pid;
			printf("[Parent] Created child pid=%d\n", pid);
			child_pid = pid;
		} else {
			asm volatile ("child_path:\n");
			child_pid = getpid();
			printf("[Child] Hello from child pid=%d\n", getpid());
			sleep(1+i);
			exit(0);
		}
	}

	int wstatus;
	for (int i = 0; i < num_children; i++) {
		printf("[Parent] Child %d exited\n", waitpid(-1, &wstatus, 0));
	}

	return 0;
}
