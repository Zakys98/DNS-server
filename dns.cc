#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <fstream>
#include <iostream>
#include <vector>

#define BUFFER_SIZE 512
#define T_A 1

typedef struct args {
    char *server;
    int port;
    char *filter;
} Args;

struct DNS_HEADER {
    unsigned short id;  // identification number

    unsigned char rd : 1;      // recursion desired
    unsigned char tc : 1;      // truncated message
    unsigned char aa : 1;      // authoritive answer
    unsigned char opcode : 4;  // purpose of message
    unsigned char qr : 1;      // query/response flag

    unsigned char rcode : 4;  // response code
    unsigned char cd : 1;     // checking disabled
    unsigned char ad : 1;     // authenticated data
    unsigned char z : 1;      // its z! reserved
    unsigned char ra : 1;     // recursion available

    unsigned short q_count;     // number of question entries
    unsigned short ans_count;   // number of answer entries
    unsigned short auth_count;  // number of authority entries
    unsigned short add_count;   // number of resource entries
};

struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

// Global variables
Args *arguments;

// Prototypes
void parsePacket(int, struct sockaddr_in, unsigned char *, unsigned long,
                 std::vector<std::string>);
void loadFile(std::vector<std::string> &);
int parseArguments(int, char **);
bool checkResolverName();
unsigned char *translateName(unsigned char *, unsigned char *);
int filterFile(std::vector<std::string> &, std::string &);
void sendToResolver(unsigned char *, int, struct sockaddr_in, int);
void changeToDnsNameFormat(unsigned char *, unsigned char *);
void sigintHandler(int);
bool is_ipv6();

int main(int argc, char **argv) {
    signal(SIGINT, sigintHandler);
    if (parseArguments(argc, argv) == 1) {
        if (arguments != NULL) {
            if (arguments->filter != NULL) free(arguments->filter);
            if (arguments->server != NULL) free(arguments->server);
            free(arguments);
        }
        exit(1);
    }

    if (!is_ipv6()) {
        if (!checkResolverName()) sigintHandler(1);
    }

    std::vector<std::string> filteredDomains;
    loadFile(filteredDomains);

    int server_fd;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    unsigned long recvMessageSize;
    unsigned char buffer[BUFFER_SIZE];

    if ((server_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        sigintHandler(1);
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(arguments->port);

    if (bind(server_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) <
        0) {
        sigintHandler(1);
    }

    for (;;) {
        unsigned int clientLen = sizeof(clientAddr);

        recvMessageSize = recvfrom(server_fd, buffer, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&clientAddr, &clientLen);

        if (recvMessageSize > 0) {
            parsePacket(server_fd, clientAddr, buffer, recvMessageSize,
                        filteredDomains);
        }
    }

    return 0;
}

void parsePacket(int socket, struct sockaddr_in clientAddr,
                 unsigned char *buffer, unsigned long bufferSize,
                 std::vector<std::string> filteredDomains) {
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    unsigned char *qname;

    dns = (struct DNS_HEADER *)buffer;
    qname = (unsigned char *)&buffer[sizeof(struct DNS_HEADER)];

    qinfo = (struct QUESTION *)&buffer[sizeof(struct DNS_HEADER) +
                                       (strlen((const char *)qname) + 1)];

    // osetrit kdyz prijde odpoved a ne query (pridat else if)
    if (htons(qinfo->qtype) == 1 && htons(dns->qr) == 0 && htons(dns->z) == 0) {
        unsigned char *name_with_sub = translateName(qname, buffer);
        std::cout << "name with sub " << name_with_sub << std::endl;
        std::string s(reinterpret_cast<char *>(name_with_sub));
        s = s.substr(0, s.find("/"));
        if (filterFile(filteredDomains, s) == 0) {
            // adress is not filtered
            unsigned char name[128];
            std::copy(s.begin(), s.end(), name);
            name[s.length()] = 0;
            sendToResolver(name, socket, clientAddr, htons(dns->id));
        } else {
            // adress is filtered
            dns->qr = dns->ra = dns->rd = 1;
            dns->ad = 0;
            dns->rcode = 5;
            sendto(socket, buffer, bufferSize, 0,
                   (struct sockaddr *)&clientAddr, sizeof(clientAddr));
        }
        free(name_with_sub);
    } else {
        // send not implemented
        dns->qr = dns->rd = dns->ra = 1;
        dns->rcode = 4;
        dns->ad = 0;

        sendto(socket, buffer, bufferSize, 0, (struct sockaddr *)&clientAddr,
               sizeof(clientAddr));
    }
}

void sendToResolver(unsigned char *resolverName, int serverSocket,
                      struct sockaddr_in clientAddr, int id) {
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    struct sockaddr_in dest;
    int resolver_fd;
    unsigned char buffer[BUFFER_SIZE], *qname;

    resolver_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(arguments->server);

    dns = (struct DNS_HEADER *)&buffer;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    qname = (unsigned char *)&buffer[sizeof(struct DNS_HEADER)];

    changeToDnsNameFormat(qname, resolverName);
    
    qinfo = (struct QUESTION *)&buffer[sizeof(struct DNS_HEADER) +
                                       (strlen((const char *)qname) + 1)];

    qinfo->qtype = htons(T_A);
    qinfo->qclass = htons(1);

    if (sendto(resolver_fd, (char *)buffer,
               sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) +
                   sizeof(struct QUESTION),
               0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "sendto failed" << std::endl;
    }

    unsigned int i = sizeof(dest);
    unsigned long recvMsgResolverSize;

    recvMsgResolverSize = recvfrom(resolver_fd, (char *)buffer, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&dest, &i);

    dns = (struct DNS_HEADER *)&buffer;
    dns->id = htons(id);

    if (recvMsgResolverSize > 0) {
        sendto(serverSocket, (char *)buffer, recvMsgResolverSize, 0,
               (struct sockaddr *)&clientAddr, sizeof(clientAddr));
    }
}

void changeToDnsNameFormat(unsigned char *dns, unsigned char *host) {
    unsigned int lock = 0;
    strcat((char *)host, ".");

    for (unsigned int i = 0; i < strlen((char *)host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int filterFile(std::vector<std::string> &vc, std::string &s) {
    std::vector<std::string>::iterator it = find(vc.begin(), vc.end(), s);
    if (it != vc.end()) return 1;
    return 0;
}

unsigned char *translateName(unsigned char *reader, unsigned char *buffer) {
    unsigned char *name;
    unsigned int p = 0, offset;

    name = (unsigned char *)malloc(256);

    name[0] = '\0';
    while (*reader != 0) {
        if (*reader >= 192) {
            offset = (*reader) * 256 + *(reader + 1) - 49152;
            reader = buffer + offset - 1;
        } else {
            name[p++] = *reader;
        }
        reader = reader + 1;
    }

    name[p] = '\0';

    int i;
    for (i = 0; i < (int)strlen((const char *)name); i++) {
        p = name[i];
        for (int j = 0; j < (int)p; j++) {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0';
    return name;
}

bool checkResolverName() {
    struct hostent *he = NULL;
    struct in_addr a;
    he = gethostbyname(arguments->server);
    if (he) {
        while (*he->h_addr_list) {
            bcopy(*he->h_addr_list++, (char *)&a, sizeof(a));
            arguments->server =
                (char *)realloc(arguments->server, strlen(inet_ntoa(a)) + 1);
            if (arguments->server == NULL) sigintHandler(1);
            strcpy(arguments->server, inet_ntoa(a));
            return true;
        }
    }
    return false;
}

// check if resolver server is IPV6
bool is_ipv6() {
    struct sockaddr_in6 ipv6;
    return inet_pton(AF_INET6, arguments->server, &(ipv6.sin6_addr)) != 0;
}

void loadFile(std::vector<std::string> &vc) {
    std::ifstream f;
    f.open(arguments->filter);
    if (f.is_open()) {
        std::string line;
        while (std::getline(f, line)) {
            if (line[0] != '#' && !line.empty()) vc.push_back(line);
        }
    }
    f.close();
    sort(vc.begin(), vc.end());
}

// function for parsing arguments
int parseArguments(int argc, char **argv) {
    arguments = (Args *)malloc(sizeof(Args));
    if (arguments == NULL) return 1;
    arguments->port = 53;
    arguments->filter = arguments->server = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            if (argv[i + 1] != NULL) {
                arguments->server =
                    (char *)malloc(sizeof(char) * (strlen(argv[i + 1]) + 1));
                strcpy(arguments->server, argv[i + 1]);
            }
        }
        if (strcmp(argv[i], "-f") == 0) {
            if (argv[i + 1] != NULL) {
                arguments->filter =
                    (char *)malloc(sizeof(char) * (strlen(argv[i + 1]) + 1));
                strcpy(arguments->filter, argv[i + 1]);
            }
        }
        if (strcmp(argv[i], "-p") == 0)
            if (argv[i + 1] != NULL)
                arguments->port = (int)strtol(argv[i + 1], NULL, 10);
    }
    if (arguments->filter == NULL || arguments->server == NULL) return 1;
    return 0;
}

// function to clean memory after CTRL + C
void sigintHandler(int number) {
    free(arguments->filter);
    free(arguments->server);
    free(arguments);
    exit(number);
}