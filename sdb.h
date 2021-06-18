#ifndef __SDB_H__
#define __SDB_H__

#include <vector>
#include <string>
#include <sstream>

using namespace std;

typedef long long ll;
const int MAX = 0x100;
vector<string> REGS = {
    "rax", "rbx", "rcx", "rdx",
    "r8" , "r9" , "r10", "r11", 
    "r12", "r13", "r14", "r15",
    "rdi", "rsi", "rbp", "rsp", 
    "rip", "flags"};

enum state {
	ANY,
	LOADED,
	RUNNING
};

struct program {
	string path;
	ll addr;
	ll offset;
	ll size;
};

struct breakpoint {
    int id;
    ll addr;
    unsigned char ori;
    bool isfix;
    breakpoint(int _i = -1, ll _a = 0, unsigned char _o = '\0', bool _f = false)
        : id(_i), addr(_a), ori(_o), isfix(_f) {
        }
};


vector<string> split(const string &s, const char d = '\0') {
    vector<string> res;
    stringstream ss(s);
    string item;
    if (d)
        while (getline(ss, item, d)) res.push_back(item);
    else
        while (ss >> item) res.push_back(item);
    return res;
}

string get_byte(const unsigned char *byte) {
    stringstream ss;
    ss << hex << setfill('0') << setw(2) << (int) *byte;
    string tmp;
    ss >> tmp;
    return tmp;
}

string get_bytes(const unsigned char *bytes, int n) {
    string out = "";
    bool fir = true;
    for (int i = 0; i < n; i++) {
        if (!fir) out += " ";
        fir = false;
        out += get_byte(bytes + i);
    }
    return out;
}

string get_printable(const string &s) {
    string out = "|";
    for (auto &x : s) {
        int tmp = x;
        if (tmp < 32 || tmp > 126) out += ".";
        else out += x;
    }
    out += "|";
    return out;
}

string flags2rwx(const ll flags) {
    string per = "xwr", tmp = "";
    for (int i = 2; i >= 0; i--) {
        if (flags & (1 << i)) tmp += per[i];
        else tmp += "-";
    }
    return tmp;
}

ll str2ll(const string &s) {
    if (s.find("0x") == 0 || s.find("0X") == 0) {
        return stoll(s, NULL, 16);
    }
    else if (s.find("0") == 0) {
        return stoll(s, NULL, 8);
    }
    else {
        return stoll(s);
    }
}

void pt_code();
void pt_regs();
string pt_mem(const ll addr);
void print_reg(const string &name);
unsigned char patch_byte(const ll addr, unsigned char c);
bool isintext(const ll addr);
bool vargs(vector<string> &x, unsigned int at, bool p);
int check();
string dasm(unsigned char *pos, ll &addr);

void bp(const ll addr);
void cont();
void del(int id);
void disasm();
void dump(int sz = 80);
void exit();
void getreg(const string &reg);
void getregs();
void help();
void list();
void load();
void run();
void vmmap();
void set(const string &reg, ll val);
void si();
void start();

#endif
