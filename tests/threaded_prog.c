#define _GNU_SOURCE

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#define NUM_THREADS 5
pthread_t threads[NUM_THREADS];

pthread_mutex_t sync_lock;
pthread_cond_t sync_cond;
int sync_num;

int thread_mark[NUM_THREADS];

void thread_exit(int tnum)
{
	pthread_mutex_lock(&sync_lock);
	sync_num = tnum;
	pthread_cond_signal(&sync_cond);
	pthread_mutex_unlock(&sync_lock);
}

void *thread_routine(void *opaque)
{
	int tnum = (int)(ptrdiff_t)opaque;
	printf("[Thread] Hello from thread %d, pid=%d, tid=%d, pthread=%lx\n",
		   tnum, getpid(), gettid(), threads[tnum]);
	sleep(1+tnum);
	thread_mark[tnum] = 100 + tnum;
	thread_exit(tnum);
	return NULL;
}

void create_thread(int i)
{
	assert(!pthread_create(&threads[i], NULL, thread_routine, (void*)(ptrdiff_t)i));
	printf("[Parent] Created thread %d, pthread=%lx\n", i, threads[i]);
}

void wait_for_thread(void)
{
	pthread_cond_wait(&sync_cond, &sync_lock);
	pthread_join(threads[sync_num], NULL);
	printf("[Parent] Thread %d exited\n", sync_num);
}

int main(int argc, char const *argv[])
{
	assert(!pthread_mutex_init(&sync_lock, NULL));
	assert(!pthread_cond_init(&sync_cond, NULL));
	pthread_mutex_lock(&sync_lock);

	printf("[Parent] Hello from parent!\n");
	for (int i = 0; i < NUM_THREADS; i++) {
		create_thread(i);
	}
	for (int i = 0; i < NUM_THREADS; i++) {
		wait_for_thread();
	}

	return 0;
}
