# Android-NDK-Examples

ashmem: (Android Shared Memory)
-------------------------------

Reference Linux Driver Implementation: (Kernel Space)
	https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/drivers/staging/android/ashmem.c?h=v4.9.90

Reference Android Implementation: (User Space)
	https://android.googlesource.com/platform/system/core/+/android-cts-8.1_r3/libcutils/include/cutils/ashmem.h
	https://android.googlesource.com/platform/system/core/+/android-cts-8.1_r3/libcutils/ashmem-dev.c

Story:
-----

The ashmem subsystem is a new shared memory allocator, similar to POSIX SHM but with different behavior and sporting a simpler file-based API
Apparently it better-supports for low memory devices, because it can discard shared memory units under memory pressure
ashmem allows processes which are not related by ancestry to share memory maps by name, which are cleaned up automatically
Plain old anonymous mmaps and System V shared memory lack some of these requirements
System V shared memory segments stick around when no longer referenced by running programs (which is sometimes a feature, sometimes a nuisance)
Anonymous shared mmaps can be passed from a parent to child processes, which is inflexible since sometimes you want processes not related that way to share memory

System V Shared memory is not best suited for Android
All System V IPCs have been removed for cupcake. See bionic/libc/docs/SYSV-IPC.TXT for details.

In brief, System V IPCs are leaky by design and do not play well in Android's runtime environment where
killing processes to make room for other ones is just normal and very common. The end result is that any
code that relies on these IPCs could end up filling up the kernel's internal table of SysV IPC keys, something
that can only safely be resolved by a reboot.

We want to provide alternative mechanism in the future that don't have the same problems. One thing
we provide at the moment is ashmem, which was designed specifically for Android to avoid that kind of
problem (though it's not as well documented as it should). We probably need something similar for
semaphores and/or message queues.

Note that PTHREAD_SHARED Posix mutexes don't have this problem, because they are cleaned up
automatically when a process is killed by the kernel. However, we do not support them yet in our
Pthread implementation.


shmem(Linux) vs ashmem(Android)
	1/ Ashmem classifies shared memory pages into two types.
	2/ One is pinned pages. another one is unpinned pages.
	3/ In low memory situations kernel can evict unpinned pages.
	4/ Pinned pages sholud be removed only after unpinned pages.
	
We can Create shared memory region using ashmem:
    fd = ashmem_create_region("my_shm_region", size); 
    if(fd < 0) 
        return -1; 
    data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); 
    if(data == MAP_FAILED) 
        goto out;
	
IMPORTANT NOTE:
---------------
If another processes wants to access shared memory, it does not access through file name. Because of security issues
Process share the fd of shared memory through IPC binder

Example Application on opening "shared file" from second process:
-----------------------------------------------------------------
if we want to share data between two (ndk-)processes. For this we use ashmem using this source.
One process is continuously reading (read_mem) and one process is writing one time (write_mem).

Problem: The read process is not getting the values of the writer

// read_mem.c
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include "ashmem.h"

#define SHM_NAME "test_mem"
int main(int argc, char **argv) {
    int shID = ashmem_create_region(SHM_NAME, 2);
    if (shID < 0)
    {
        perror("ashmem_create_region failed\n");
        return 1;
    }
    // right here /dev/ashmem/test_mem is deleted
    printf("ashmem_create_region: %d\n", shID);
    char *sh_buffer = (char*)mmap(NULL, 2, PROT_READ | PROT_WRITE, MAP_SHARED, shID, 0);
    if (sh_buffer == (char*)-1)
    {
        perror("mmap failed");
        return 1;
    }
    printf("PID=%d", getpid());
    do
    {
        printf("VALUE = 0x%x\n", sh_buffer[0]);
    }
    while (getchar());
    return 0;
}

// write_mem.c
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include "ashmem.h"

#define SHM_NAME "test_mem"
int main(int argc, char **argv) {
    int shID = ashmem_create_region(SHM_NAME, 2);
    if (shID < 0)
    {
        perror("ashmem_create_region failed\n");
        return 1;
    }
    printf("ashmem_create_region: %d\n", shID);
    char *sh_buffer = (char*)mmap(NULL, 2, PROT_READ | PROT_WRITE, MAP_SHARED, shID, 0);
    if (sh_buffer == (char*)-1)
    {
        perror("mmap failed");
        return 1;
    }
    printf("PID=%d\n", getpid());
    int ch = getchar();
    sh_buffer[0] = ch;
    printf("Written 0x%x\n", ch);
    munmap(sh_buffer, 2);
    close(shID);
    return 0;
}

Results:
-------
This is the output:
Reading

$ ./read_mem
ashmem_create_region: 3
PID=29655
VALUE = 0x0
Writing

$ ./write_mem
ashmem_create_region: 3
PID=29691
A
Written 0x41
Reading again VALUE = 0x0 (by pressing return)

Watching the maps of the reader:
$ cat /proc/29655/maps | grep test_mem
b6ef5000-b6ef6000 rw-s 00000000 00:04 116213     /dev/ashmem/test_mem (deleted)

as you can see test_mem is deleted WHILE read_mem is still alive.

Answer:
-------
Ashmem doesn't work like regular shared memory on Linux, and there is a good reason for it.
First, let's try to explain the "(deleted)" part, this is an implementation detail of how ashmem is implemented in the kernel. What it really means is that a file entry was created in the /dev/ashmem/ directory, then later removed, but that the corresponding i-node still exists because there is at least one open file-descriptor for it.
You could actually create several ashmem regions with the same name, and they would all appear as "/dev/ashmem/<name> (deleted)", but each one of them would correspond to a different i-node, and thus a different memory region. And if you look under /dev/ashmem/ you would see that the directory is still empty.
That's why the name of an ashmem region is really only used for debugging. There is no way to 'open' an existing region by name.
An ashmem i-node, and corresponding memory, is automatically reclaimed when the last file descriptor to it is closed. This is useful because it means that if your process dies due to a crash, the memory will be reclaimed by the kernel automatically. This is not the case with regular SysV shared memory (a crashing process just leaks the memory! Something unacceptable on an embedded system like Android).
Your test programs create two distinct ashmem regions with the same name, that's why they dont work as you think they should. What you need instead is:

1) Create a single ashmem region in one of the process
2) Pass a new file descriptor to the region from the first process to the second one

One way to do that is to fork the first process to create the second (this will automatically duplicate the file descriptors), but this is generally not a good idea under Android.
A better alternative is to use sendmsg() and recvmsg() to send the file descriptor through a Unix-domain socket between the two processes. This is generally tricky, but as an example, have a look at the SendFd() and ReceiveFd() functions in the following source file was written for the NDK:
