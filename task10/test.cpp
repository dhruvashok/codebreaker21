#include <sys/mman.h>
#include <cstdio>
#include <cstddef>
#include <stdlib.h>
#include <unistd.h>
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include<netdb.h> //hostent

int main() {
//    void *ptr = mmap(NULL, 0x320, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
//    int a = mprotect(ptr, 0x320, 7);
//    _dl_make_stack_executable(__libc_stack_end);
	int a;
	int* b = &a;
	write(1, b, 8);
	return 0;
}
