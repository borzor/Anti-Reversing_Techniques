#include <iostream>
#include <sys/utsname.h>
#include <unistd.h>
#include <csignal>

std::string generateKey(const std::string &login, const std::string &password) {
    std::string key;
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
    std::cout<<key<<'\n';
    for(size_t i = 0; i < key.size()/2; i++){
        key[i] ^=  buffer.sysname[i % strlen(buffer.sysname)];
    }
    for(size_t i = key.size(); i < key.size(); i++){
        key[i] ^=  buffer.nodename[i % strlen(buffer.nodename)];
    }
    for(size_t i = 0; i < key.size(); i++){
        tmp1 = key[i] << std::stoi(&buffer.release[0])%key.size();
        tmp2 = key[i] >> (key.size() -  std::stoi(&buffer.release[0]) % key.size());
        key[i] = 31 + (tmp1 | tmp2) % 95;
    }
    std::cout<<key<<'\n';
    return key;
}

int main() {
    std::string login="login", password="password", key, checkKey;
    key = generateKey(login, password);
    //std::cin>>checkKey;
    if(!strcmp(key.c_str(),checkKey.c_str())){
        std::cout<<"congratulation\n";
    }

    return 0;
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
