#include <iostream>
#include <sys/utsname.h>
#include <unistd.h>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <csignal>

#define password_size 32

char* calc_addr(char* p_addr){
    return p_addr + 0x400000;
}

void __attribute__ ((optimize("O1")))generateKey(const std::string &login, const std::string &password, std::string &key){
#ifdef __unix__
    char* label_address = 0;
    asm volatile(
        "jmp unaligned\n"
        ".short 0xe8\n"
        "unaligned:");
    label_address = calc_addr(((char*)&&return_here) - 0x400000);
    asm volatile(
        "push %0\n"
        "ret\n"
        ".string \"\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\""
        :
        : "g"(label_address));
    return_here:
#endif
    uint32_t tmp1,tmp2;
    struct utsname buffer;
    if (uname(&buffer) < 0) {
        perror("uname");
        exit(EXIT_FAILURE);
    }
    for(size_t i = 0; i < std::max(login.size(),password.size()); i++) {
        if(login.size() > i){
            key.push_back(login[i]);
        }
        if(password.size() > i){
            key.push_back(password[i]);
        }
    }
    while(key.size() < password_size){
        key+=key;
    }
    key.erase(key.begin()+32,key.end());

    for(size_t i = 0; i < key.size()/2; i++){
        key[i] ^=  buffer.sysname[i % strlen(buffer.sysname)];
    }
    for(size_t i = key.size(); i < key.size(); i++){
        key[i] ^=  buffer.nodename[i % strlen(buffer.nodename)];
    }
    for(size_t i = 0; i < key.size(); i++){
        tmp1 = key[i] << std::stoi(&buffer.release[0])%key.size();
        tmp2 = key[i] >> (key.size() -  std::stoi(&buffer.release[0]) % key.size());
        key[i] = 33 + (tmp1 | tmp2) % 94;
    }
}

void isDebuggerAttached() {
    FILE* proc_status = fopen("/proc/self/status", "r");
    if (proc_status == NULL){
        return;
    }
    char line[1024] = { };
    char *fgets(char *s, int size, FILE *stream);
    while (fgets(line, sizeof(line), proc_status) != NULL) {
        const char traceString[] = "TracerPid:";
        char* tracer = strstr(line, traceString);
        if (tracer != NULL)
        {
            int pid = atoi(tracer + sizeof(traceString) - 1);
            if (pid != 0){
                fclose(proc_status);
                kill(getppid(), SIGKILL);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(proc_status);
}
int main() {
    std::string login, password, key, checkKey;
    std::cout<<"Enter login\n";
    std::cin>>login;
    std::cout<<"Enter password\n";
    std::cin>>password;
#ifdef __unix__
    int fork_pid = fork();
    if (fork_pid == 0){
        if (ptrace(PTRACE_ATTACH, getppid(), NULL, NULL) != 0){
            exit(EXIT_FAILURE);
        }
        ptrace(PTRACE_SETOPTIONS, getppid(), NULL, PTRACE_O_TRACEFORK);// PTRACE_O_EXITKILL
        // restart the parent so it can keep processing like normal
        int status = 0;
        wait(&status);
        ptrace(PTRACE_CONT, getppid(), NULL, NULL);
        // handle any signals that may come in from tracees
        while (true)
        {
            isDebuggerAttached();
            int pid = waitpid(-1, &status, WNOHANG);
            if (pid == 0)
            {
                sleep(1);
                continue;
            }
            if (status >> 16 == PTRACE_EVENT_FORK)
            {
                // follow the fork
                long newpid = 0;
                ptrace(PTRACE_GETEVENTMSG, pid, NULL, &newpid);
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_CONT, newpid, NULL, NULL);
            }
            ptrace(PTRACE_CONT, pid, NULL, NULL);
        }

    }
#endif
    generateKey(login, password,key);
    std::cout<<"your key is \n"<<key<<"\n"<<"Enter key\n";
    std::cin>>checkKey;
    if(!strcmp(key.c_str(),checkKey.c_str())){
        std::cout<<"congratulation\n";
    }
    return 0;
}

void __attribute__((constructor)) before_main()
{
    isDebuggerAttached();
}

