#include <csignal>
#include <stacktrace.hxx>

static void MemoryAccessViolation(int sig)
{
	std::cout << "\u001b[41m\n                              memory access violation\n";
	std::cout << "signal: " << sig << "\n";
    printStacktrace(50);
	std::cout << "\u001b[0m" << std::endl;
	exit(1);
}

static void AbnormalTermination(int sig) 
{
	std::cout << "\u001b[41m\n                              abnormal termination\n";
	std::cout << "signal: " << sig << "\n";
    printStacktrace(50);
	std::cout << "\u001b[0m" << std::endl;
	exit(1);
}

static void InvalidInstruction(int sig) 
{
	std::cout << "\u001b[41m\n                              invalid instruction\n";
	std::cout << "signal: " << sig << "\n";
    printStacktrace(50);
	std::cout << "\u001b[0m" << std::endl;
	exit(1);
}

void install_crash_handlers()
{
	signal(SIGSEGV, MemoryAccessViolation);
    signal(SIGABRT, AbnormalTermination);
    signal(SIGILL, InvalidInstruction);
}
