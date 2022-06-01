#include <syscall.h>

int main (int, char *[]);
void _start (int argc, char *argv[]);

void
_start (int argc, char *argv[]) { // argc : argument counts , argv : arguments vector
	exit (main (argc, argv));
}
