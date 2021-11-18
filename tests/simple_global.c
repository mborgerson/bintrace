#include <stdint.h>
#include <stdio.h>

int global_value = 0;

int main(int argc, char const *argv[])
{
	printf("Startup!\n");
	for (int i = 0; i < 10; i++) {
		printf("Enter a number: ");
		scanf("%d", &global_value);
		printf("You said: %d\n", global_value);

		asm volatile ("loop_bottom:\n");
	}

	return 0;
}
