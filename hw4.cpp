#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>
#include "hw4.h"
using namespace std;

state st = ANY;
program prog;
string flags;

pid_t pid = 0;
char *code = NULL;
int bi = 0;
int dislen = 10;
int isbp = -1;

ll disaddr = -1;
ll dumpaddr = -1;
ll bpaddr = -1;

struct user_regs_struct regs = {0};

vector<breakpoint> bps;

string exec(const char* cmd) {
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

ll* reg(string name) {
    if (name == "rax"  ) return (ll*) &regs.rax;
    if (name == "rbx"  ) return (ll*) &regs.rbx;
    if (name == "rcx"  ) return (ll*) &regs.rcx;
    if (name == "rdx"  ) return (ll*) &regs.rdx;
    if (name == "rsp"  ) return (ll*) &regs.rsp;
    if (name == "rbp"  ) return (ll*) &regs.rbp;
    if (name == "rsi"  ) return (ll*) &regs.rsi;
    if (name == "rdi"  ) return (ll*) &regs.rdi;
    if (name == "rip"  ) return (ll*) &regs.rip;
    if (name == "r8"   ) return (ll*) &regs.r8;
    if (name == "r9"   ) return (ll*) &regs.r9;
    if (name == "r10"  ) return (ll*) &regs.r10;
    if (name == "r11"  ) return (ll*) &regs.r11;
    if (name == "r12"  ) return (ll*) &regs.r12;
    if (name == "r13"  ) return (ll*) &regs.r13;
    if (name == "r14"  ) return (ll*) &regs.r14;
    if (name == "r15"  ) return (ll*) &regs.r15;
    if (name == "flags") return (ll*) &regs.eflags;
    return NULL;
}

void pt_code() {
    ifstream f(prog.path.c_str(), ios::in | ios::binary | ios::ate);
    streampos size = f.tellg();
    code = new char [size + 1L];
    f.seekg(0, ios::beg);
    f.read(code, size);
    code[size] = 0;
    f.close();
}

string pt_mem(const ll addr) {
    string s = "";
    for (int i = 0; i < MAX / 8; i++) {
        auto out = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
        s += string((char*) &out, 8);
    }
    return s;
}

void pt_regs() {
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
}

void print_reg(const string &name) {
    for (auto &x : REGS) {
        if (x == name) {
            ll val = *reg(name);
            cerr << name << " = " << val << " (" << hex << "0x" << val << dec << ")" << endl;
            return;
        }
    }
    cerr << "** '" << name << "' does not exist." << endl;
}

string dasm(unsigned char *pos, ll &addr) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        cerr << "** cs open error." << endl;
        return "";
    }
    cs_insn *insn;
    size_t count = cs_disasm(handle, pos, MAX, addr, 0, &insn);
    string out = "";
    if (count > 0) {
        stringstream ss;
        ss << hex << setfill(' ') << setw(12) << insn[0].address << ": "
            << left << setfill(' ') << setw(31) << get_bytes(insn[0].bytes, insn[0].size)
            << left << setfill(' ') << setw(7) << insn[0].mnemonic
            << right << insn[0].op_str << endl << dec;
        addr += insn[0].size;
        out = ss.str();
        cs_free(insn, count);
    }
    else {
        cerr << "** disassemble failed." << endl;
    }
    cs_close(&handle);
    return out;
}

unsigned char cbyte(const ll addr, unsigned char c) {
    auto code = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    ptrace(PTRACE_POKETEXT, pid, addr, (code & 0xffffffffffffff00) | (c & 0xff));
    return code & 0xff;
}

bool isintext(const ll addr) {
    return prog.addr <= addr && addr <= (prog.addr + prog.size);
}

bool vargs(vector<string> &x, unsigned int at, bool p) {
    if (x.size() > at) return true;
    if (p) cerr << "** missing argument(s)." << endl;
    return false;
}

int check() {
    int status;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) != SIGTRAP) {
            cerr << "** child process " << pid << " stopped by signal (code " << WSTOPSIG(status) << ")" << endl;
            return -1;
        }
        if (isbp != -1) return 0;
        pt_regs();
        for (auto &x : bps) {
            ll tmpaddr = x.addr;
            if (tmpaddr == (*reg("rip") - 1)) {
                isbp = x.id;
                bpaddr = tmpaddr;
				
                dislen = 1;
                ll addrbak = disaddr;
                cerr << "** breakpoint @ ";
                disaddr = tmpaddr;
                disasm();
                disaddr = addrbak;
                dislen = 10;

                cbyte(tmpaddr, x.ori);
                (*reg("rip"))--;
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                return 1;
            }
        }
        return -1;
    }
    if (WIFEXITED(status)) {
        if (WIFSIGNALED(status))
            cerr << "** child process " << pid << " terminiated by signal (code " << WTERMSIG(status) << ")" << endl;
        else
            cerr << "** child process " << pid << " terminiated normally (code " << status << ")" << endl;
        pid = 0;
        st = LOADED;
        return -1;
    }
    return -1;
}

void bp(const ll addr) {
    if (st == LOADED) {
        if (!isintext(addr)) {
            cerr << "** address must be in the text segment. (LOADED state)" << endl;
            return;
        }
        bps.push_back({bi++, addr, 0, false});
    }
    else if (st == RUNNING) {
        unsigned char tmp = cbyte(addr, 0xcc);
        bps.push_back({bi++, addr, tmp, true});
    }
    else {
        cerr << "** state must be LOADED or RUNNING." << endl;
    }
}

void cont() {
    if (st != RUNNING) {
        cerr << "** state must be RUNNING." << endl;
        return;
    }
    if (isbp != -1) si();
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    check();
}

void del(int id) {
    bool good = false;
    for (auto itr = bps.begin(); itr != bps.end(); itr++) {
        if (id == (*itr).id) {
            cbyte((*itr).addr, (*itr).ori);
            bps.erase(itr);
            good = true;
            break;
        }
    }
    if (good) cerr << "** breakpoint " << id << " deleted." << endl;
    else cerr << "** no breakpoint number " << id << "." << endl;
}

void disasm() {
    if (st != LOADED && st != RUNNING) {
        cerr << "** state must be LOADED or RUNNING." << endl;
        return;
    }
    if (disaddr == -1) {
        cerr << "** no addr is given." << endl;
        return;
    }
    if (code == NULL) pt_code();
    if (st == LOADED) {
        for (int i = 0; i < dislen; i++) {
            auto pos = (unsigned char*) code + prog.offset + (disaddr - prog.addr);
            ll tmpaddr = disaddr;
            string out = dasm(pos, tmpaddr);
            if (out == "" || tmpaddr > prog.addr + prog.size) break;
            else {
                disaddr = tmpaddr;
                cerr << out;
            }
        }
        return;
    }
    if (st == RUNNING) {
        for (int i = 0; i < dislen; i++) {
            if (isintext(disaddr)) {
                ll offset;
                offset = prog.offset + (disaddr - prog.addr);
                auto pos = (unsigned char*) code + offset;
                string out = dasm(pos, disaddr);
                cerr << out;
            }
            else {
                string s = pt_mem(disaddr);
                auto pos = (unsigned char*) s.c_str();
                string out = dasm(pos, disaddr);
                cerr << out;
            }
        }
    }
}

void dump(int sz) {
    if (st != RUNNING) {
        cerr << "** state must be RUNNING." << endl;
        return;
    }
    if (dumpaddr == -1) {
        cerr << "** no addr is given." << endl;
        return;
    }
    int nline = sz / 16, nbytes = sz % 16;
    int n = nline + (nbytes != 0);
    for (int i = 0; i < n; i++) {
        string hexout = "";
        for (int j = 0; j < 2; j++) {
            auto out = ptrace(PTRACE_PEEKTEXT, pid, dumpaddr, NULL);
            hexout += string((char*) &out, 8);
            dumpaddr += 8;
        }
        cerr << hex << setfill(' ') << setw(12) << dumpaddr - 16 << ": "
            << left << setfill(' ') << setw(49) << get_bytes((unsigned char*) hexout.c_str(), 16)
            << right << get_printable(hexout) << endl << dec;
    }
}

void exit() {
    if (code) {
        delete [] code;
        code = NULL;
    }
    if (pid) kill(pid, SIGTERM);
}

void getreg(const string &reg) {
    if (st != RUNNING) {
        cerr << "** state must be RUNNING." << endl;
        return;
    }
    pt_regs();
    print_reg(reg);
}

void getregs() {
    if (st != RUNNING) {
        cerr << "** state must be RUNNING." << endl;
        return;
    }
    pt_regs();
    for (auto &x : REGS) {
        print_reg(x);
    }
}

void help() {
    cerr << "- break {instruction-address}: add a break point" << endl;
    cerr << "- cont: continue execution" << endl;
    cerr << "- delete {break-point-id}: remove a break point" << endl;
    cerr << "- disasm addr: disassemble instructions in a file or a memory region" << endl;
    cerr << "- dump addr [length]: dump memory content" << endl;
    cerr << "- exit: terminate the debugger" << endl;
    cerr << "- get reg: get a single value from a register" << endl;
    cerr << "- getregs: show registers" << endl;
    cerr << "- help: show this message" << endl;
    cerr << "- list: list break points" << endl;
    cerr << "- load {path/to/a/program}: load a program" << endl;
    cerr << "- run: run the program" << endl;
    cerr << "- vmmap: show memory layout" << endl;
    cerr << "- set reg val: get a single value to a register" << endl;
    cerr << "- si: step into instruction" << endl;
    cerr << "- start: start the program and stop at the first instruction" << endl;
}

void list() {
    for (auto &x : bps) {
        cerr << setfill(' ') << setw(3) << x.id << ":" << setfill(' ') << setw(8) << hex << x.addr << endl << dec;
    }
}

void load() {
	if (st != ANY) {
        cerr << "** state must be ANY." << endl;
        return;
    }
	stringstream s1(exec(("readelf -S " + prog.path + " | grep -A1 .text | sed -n 1p | awk '{ print $5 }'").c_str()));
	s1 >> hex >> prog.addr;
	stringstream s2(exec(("readelf -S " + prog.path + " | grep -A1 .text | sed -n 1p | awk '{ print $6 }'").c_str()));
	s2 >> hex >> prog.offset;
	stringstream s3(exec(("readelf -S " + prog.path + " | grep -A1 .text | sed -n 2p | awk '{ print $1 }'").c_str()));
	s3 >> hex >> prog.size;
	stringstream s4(exec(("readelf -S " + prog.path + " | grep -A1 .text | sed -n 2p | awk '{ print $3 }'").c_str()));
	s4 >> flags;

	cerr << "** program '" << prog.path << "' loaded. " << hex
		<< ", vaddr 0x" << prog.addr
		<< ", offset 0x" << prog.offset
		<< ", size 0x" << prog.size << endl << dec;
	st = LOADED;
}

void run() {
    if (st == RUNNING) {
        cerr << "** program '" << prog.path << "' is already running." << endl;
        cont();
    }
    else if (st == LOADED) {
        start();
        cont();
    }
    else {
        cerr << "** state must be LOADED or RUNNING." << endl;
    }
}

void vmmap() {
    if (st == LOADED) {
        cerr << hex << setfill('0') << setw(16) << prog.addr << "-"
            << setfill('0') << setw(16) << prog.addr + prog.size << " "
            << flags << " "
            << setfill('0') << setw(8) << prog.offset << " "
            << prog.path << endl << dec;
    }
    else if (st == RUNNING) {
        ifstream f("/proc/" + to_string(pid) + "/maps");
        string s;
        while (getline(f, s)) {
            vector<string> item = split(s);
            vector<string> addr = split(item[0], '-');
            cerr << setfill('0') << setw(16) << addr[0] << "-"
                << setfill('0') << setw(16) << addr[1] << " "
                << item[1].substr(0, 3) << " "
                << item[2];
            if (item.size() > 5) cerr << " " << item[5];
            cerr << endl;
        }
        f.close();
    }
    else {
        cerr << "** state must be LOADED or RUNNING." << endl;
        return;
    }
}

void set(const string &name, ll val) {
    if (st != RUNNING) {
        cerr << "** state must be RUNNING." << endl;
        return;
    }
    pt_regs();
    *reg(name) = val;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

void si() {
    if (st != RUNNING) {
        cerr << "** state must be RUNNING." << endl;
        return;
    }
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (check() == 0 && isbp != -1) {
        for (auto &x : bps) {
            if (x.id == isbp) {
                unsigned char tmp = cbyte(bpaddr, 0xcc);
                x.ori = tmp;
                isbp = -1;
                break;
            }
        }
    }
}

void start() {
    if (st != LOADED) {
        cerr << "** state must be LOADED." << endl;
        return;
    }
    if (pid) {
        cerr << "** program '" << prog.path << "' is already running." << endl;
        return;
    }
    pid = fork();
    if (pid < 0) {
        cerr << "** fork error." << endl;
        return;
    }
    else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            cerr << "** ptrace error." << endl;
        }
        char **argv = { NULL };
        execvp(prog.path.c_str(), argv);
    }
    else {
        int status;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
        ifstream f("/proc/" + to_string(pid) + "/stat");
        string s;
        getline(f, s);
        vector<string> out = split(s);
        for (auto &x : bps) {
            if (!x.isfix) {
                ll tmpaddr = x.addr;
                unsigned char tmp = cbyte(tmpaddr, 0xcc);
                x.ori = tmp;
            }
        }
        cerr << "** pid " << pid << endl;
        st = RUNNING;
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        prog.path = argv[1];
        load();
    }
    while (true) {
        cerr << "sdb> ";
        string s;
        getline(cin, s);
        vector<string> line = split(s);
        if (line.empty()) continue;
        string cmd = line[0];
        if (cmd == "break" || cmd == "b") {
            if (vargs(line, 1, true)) bp(str2ll(line[1]));
        }
        else if (cmd == "cont" || cmd == "c") {
            cont();
        }
        else if (cmd == "delete") {
            if (vargs(line, 1, true)) del(stoi(line[1]));
        }
        else if (cmd == "disasm" || cmd == "d") {
            if (vargs(line, 1, false)) disaddr = str2ll(line[1]);
            disasm();
        }
        else if (cmd == "dump" || cmd == "x") {
            if (vargs(line, 1, false)) dumpaddr = str2ll(line[1]);
            if (vargs(line, 2, false)) dump(str2ll(line[2]));
            else dump();
        }
        else if (cmd == "exit" || cmd == "q") {
            exit();
            break;
        }
        else if (cmd == "get" || cmd == "g") {
            if (vargs(line, 1, true)) getreg(line[1]);
        }
        else if (cmd == "getregs") {
            getregs();
        }
        else if (cmd == "help" || cmd == "h") {
            help();
        }
        else if (cmd == "list" || cmd == "l") {
            list();
        }
        else if (cmd == "load") {
            if (vargs(line, 1, true)) prog.path = line[1];
            load();
        }
        else if (cmd == "run" || cmd == "r") {
            run();
        }
        else if (cmd == "vmmap" || cmd == "m") {
            vmmap();
        }
        else if (cmd == "set" || cmd == "s") {
            if (vargs(line, 2, true)) set(line[1], str2ll(line[2]));
        }
        else if (cmd == "si") {
            si();
        }
        else if (cmd == "start") {
            start();
        }
        else {
            cerr << "Undefined command: \"" << cmd << "\".  Try \"help\"." << endl;
        }
    }
    return 0;
}
