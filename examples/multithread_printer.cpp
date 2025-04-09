#include <thread>
#include <string>
#include <iostream>
#include <vector>
#include <mutex>

void printer(std::string message, std::mutex &mutex)
{
    std::lock_guard lock{mutex};
    std::cout << "Tracee: Hello, I am thread #" << message << std::endl;
}

static constexpr int numThreads = 5;

int main()
{
    std::mutex stdoutMutex;

    std::vector<std::thread> threads;
    for(int i = 0; i < numThreads; ++i)
    {
        threads.push_back(std::thread(printer, std::to_string(i), std::ref(stdoutMutex)));
    }

    for(auto &thread: threads)
    {
        thread.join();
    }

    return 0;
}
