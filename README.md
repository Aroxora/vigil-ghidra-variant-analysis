# Vigil Ghidra Variant Analysis

Binary vulnerability discovery via Vigil + Ghidra headless — cross-OS (ELF/PE/Mach-O) reverse engineering with function-level variant analysis and risky-import surface detection.

## Analysis Results

| Binary | Format | Functions | Symbols | Strings | Risky Functions |
|--------|--------|-----------|---------|---------|-----------------|
| bash | Executable and Linking Format (ELF) | 2881 | 35678 | 4081 | 20 |
| curl | Executable and Linking Format (ELF) | 583 | 6614 | 1570 | 8 |
| hydra | Executable and Linking Format (ELF) | 1027 | 9316 | 1591 | 20 |
| ls | Executable and Linking Format (ELF) | 577 | 4964 | 537 | 10 |
| nc | Executable and Linking Format (ELF) | 160 | 829 | 181 | 20 |
| ssh | Executable and Linking Format (ELF) | 2101 | 20033 | 3477 | 20 |
| wget | Executable and Linking Format (ELF) | 1138 | 11145 | 1673 | 18 |

**Total across 6 binaries:** 8467 functions, 116 with risky imports (execve, system, popen, strcpy, memcpy, etc.)

## Risky Import Surface

### bash (20 risky)
```
{"name":"getservent","entry":"001310a0","bodyBytes":6,"signature":"servent * getservent(void)","callingConvention":"unknown","external":false}
{"name":"strncpy","entry":"00131160","bodyBytes":6,"signature":"char * strncpy(char * __dest, char * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"strcpy","entry":"00131190","bodyBytes":6,"signature":"char * strcpy(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"reallocarray","entry":"00131240","bodyBytes":6,"signature":"undefined reallocarray(void)","callingConvention":"unknown","external":false}
{"name":"execve","entry":"001316a0","bodyBytes":6,"signature":"int execve(char * __path, char * * __argv, char * * __envp)","callingConvention":"unknown","external":false}
{"name":"__memcpy_chk","entry":"00131720","bodyBytes":6,"signature":"undefined __memcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"00131770","bodyBytes":6,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"fgets_unlocked","entry":"00131850","bodyBytes":6,"signature":"char * fgets_unlocked(char * __s, int __n, FILE * __stream)","callingConvention":"unknown","external":false}
{"name":"tgetstr","entry":"00131960","bodyBytes":6,"signature":"undefined tgetstr(void)","callingConvention":"unknown","external":false}
{"name":"__strncpy_chk","entry":"00131990","bodyBytes":6,"signature":"undefined __strncpy_chk(void)","callingConvention":"unknown","external":false}
```

### curl (8 risky)
```
{"name":"memcpy","entry":"0010a300","bodyBytes":6,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"getsockname","entry":"0010a380","bodyBytes":6,"signature":"int getsockname(int __fd, sockaddr * __addr, socklen_t * __len)","callingConvention":"unknown","external":false}
{"name":"fgets","entry":"0010a6e0","bodyBytes":6,"signature":"char * fgets(char * __s, int __n, FILE * __stream)","callingConvention":"unknown","external":false}
{"name":"__memcpy_chk","entry":"0010a770","bodyBytes":6,"signature":"undefined __memcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"00152170","bodyBytes":1,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"getsockname","entry":"001521b0","bodyBytes":1,"signature":"int getsockname(int __fd, sockaddr * __addr, socklen_t * __len)","callingConvention":"unknown","external":false}
{"name":"fgets","entry":"00152360","bodyBytes":1,"signature":"char * fgets(char * __s, int __n, FILE * __stream)","callingConvention":"unknown","external":false}
{"name":"__memcpy_chk","entry":"001523a8","bodyBytes":1,"signature":"undefined __memcpy_chk(void)","callingConvention":"unknown","external":false}
```

### hydra (20 risky)
```
{"name":"gzgets","entry":"001071b0","bodyBytes":6,"signature":"undefined gzgets(void)","callingConvention":"unknown","external":false}
{"name":"__memcpy_chk","entry":"00107240","bodyBytes":6,"signature":"undefined __memcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"strcat","entry":"00107280","bodyBytes":6,"signature":"char * strcat(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"__strcat_chk","entry":"001072b0","bodyBytes":6,"signature":"undefined __strcat_chk(void)","callingConvention":"unknown","external":false}
{"name":"sprintf","entry":"00107390","bodyBytes":6,"signature":"int sprintf(char * __s, char * __format, ...)","callingConvention":"unknown","external":false}
{"name":"__strncpy_chk","entry":"001075d0","bodyBytes":6,"signature":"undefined __strncpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"strcpy","entry":"00107600","bodyBytes":6,"signature":"char * strcpy(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"strncpy","entry":"001079a0","bodyBytes":6,"signature":"char * strncpy(char * __dest, char * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"getsockname","entry":"00107cf0","bodyBytes":6,"signature":"int getsockname(int __fd, sockaddr * __addr, socklen_t * __len)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"00107d20","bodyBytes":6,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
```

### ls (10 risky)
```
{"name":"strcpy","entry":"00104100","bodyBytes":6,"signature":"char * strcpy(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"__memcpy_chk","entry":"00104410","bodyBytes":6,"signature":"undefined __memcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"00104450","bodyBytes":6,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"__strcpy_chk","entry":"00104550","bodyBytes":6,"signature":"undefined __strcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"__sprintf_chk","entry":"001046d0","bodyBytes":6,"signature":"undefined __sprintf_chk(void)","callingConvention":"unknown","external":false}
{"name":"strcpy","entry":"0012b078","bodyBytes":1,"signature":"char * strcpy(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"__memcpy_chk","entry":"0012b218","bodyBytes":1,"signature":"undefined __memcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"0012b240","bodyBytes":1,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"__strcpy_chk","entry":"0012b2c0","bodyBytes":1,"signature":"undefined __strcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"__sprintf_chk","entry":"0012b390","bodyBytes":1,"signature":"undefined __sprintf_chk(void)","callingConvention":"unknown","external":false}
```

### nc (20 risky)
```
{"name":"strncpy","entry":"00102060","bodyBytes":6,"signature":"char * strncpy(char * __dest, char * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"strcpy","entry":"00102080","bodyBytes":6,"signature":"char * strcpy(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"getservbyname","entry":"00102150","bodyBytes":6,"signature":"servent * getservbyname(char * __name, char * __proto)","callingConvention":"unknown","external":false}
{"name":"getsockopt","entry":"001021a0","bodyBytes":6,"signature":"int getsockopt(int __fd, int __level, int __optname, void * __optval, socklen_t * __optlen)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"001021f0","bodyBytes":6,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"__strcpy_chk","entry":"00102290","bodyBytes":6,"signature":"undefined __strcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"getsockname","entry":"00102310","bodyBytes":6,"signature":"int getsockname(int __fd, sockaddr * __addr, socklen_t * __len)","callingConvention":"unknown","external":false}
{"name":"strcat","entry":"00102320","bodyBytes":6,"signature":"char * strcat(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"getservbyport","entry":"00102380","bodyBytes":6,"signature":"servent * getservbyport(int __port, char * __proto)","callingConvention":"unknown","external":false}
{"name":"__sprintf_chk","entry":"001023d0","bodyBytes":6,"signature":"undefined __sprintf_chk(void)","callingConvention":"unknown","external":false}
```

### ssh (20 risky)
```
{"name":"getservbyname","entry":"0010b0f0","bodyBytes":6,"signature":"servent * getservbyname(char * __name, char * __proto)","callingConvention":"unknown","external":false}
{"name":"getseuserbyname","entry":"0010b1c0","bodyBytes":6,"signature":"undefined getseuserbyname(void)","callingConvention":"unknown","external":false}
{"name":"popen","entry":"0010b340","bodyBytes":6,"signature":"FILE * popen(char * __command, char * __modes)","callingConvention":"unknown","external":false}
{"name":"strncpy","entry":"0010b5b0","bodyBytes":6,"signature":"char * strncpy(char * __dest, char * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"getsid","entry":"0010b640","bodyBytes":6,"signature":"__pid_t getsid(__pid_t __pid)","callingConvention":"unknown","external":false}
{"name":"getsockopt","entry":"0010b8d0","bodyBytes":6,"signature":"int getsockopt(int __fd, int __level, int __optname, void * __optval, socklen_t * __optlen)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"0010b9c0","bodyBytes":6,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"system","entry":"0010ba00","bodyBytes":6,"signature":"int system(char * __command)","callingConvention":"unknown","external":false}
{"name":"getsockname","entry":"0010bb40","bodyBytes":6,"signature":"int getsockname(int __fd, sockaddr * __addr, socklen_t * __len)","callingConvention":"unknown","external":false}
{"name":"__asprintf_chk","entry":"0010c040","bodyBytes":6,"signature":"undefined __asprintf_chk(void)","callingConvention":"unknown","external":false}
```

### wget (18 risky)
```
{"name":"gnutls_certificate_set_x509_system_trust","entry":"0010b090","bodyBytes":6,"signature":"undefined gnutls_certificate_set_x509_system_trust(void)","callingConvention":"unknown","external":false}
{"name":"__memcpy_chk","entry":"0010b3b0","bodyBytes":6,"signature":"undefined __memcpy_chk(void)","callingConvention":"unknown","external":false}
{"name":"sprintf","entry":"0010b650","bodyBytes":6,"signature":"int sprintf(char * __s, char * __format, ...)","callingConvention":"unknown","external":false}
{"name":"gnutls_certificate_allocate_credentials","entry":"0010b660","bodyBytes":6,"signature":"undefined gnutls_certificate_allocate_credentials(void)","callingConvention":"unknown","external":false}
{"name":"getsockname","entry":"0010b800","bodyBytes":6,"signature":"int getsockname(int __fd, sockaddr * __addr, socklen_t * __len)","callingConvention":"unknown","external":false}
{"name":"strcpy","entry":"0010bab0","bodyBytes":6,"signature":"char * strcpy(char * __dest, char * __src)","callingConvention":"unknown","external":false}
{"name":"__sprintf_chk","entry":"0010bbd0","bodyBytes":6,"signature":"undefined __sprintf_chk(void)","callingConvention":"unknown","external":false}
{"name":"memcpy","entry":"0010bdd0","bodyBytes":6,"signature":"void * memcpy(void * __dest, void * __src, size_t __n)","callingConvention":"unknown","external":false}
{"name":"__vasprintf_chk","entry":"0010be10","bodyBytes":6,"signature":"undefined __vasprintf_chk(void)","callingConvention":"unknown","external":false}
{"name":"gnutls_certificate_set_x509_system_trust","entry":"0017e030","bodyBytes":1,"signature":"undefined gnutls_certificate_set_x509_system_trust(void)","callingConvention":"unknown","external":false}
```

## CVE Matches (searchsploit)

```
--- bash ---
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Advantech Switch - 'Shellshock' [01;31m[KBash[m[K Environm | cgi/remote/38849.rb
[01;31m[KBash[m[K - 'Shellshock' Environment Variables Com | linux/remote/34766.php
--- curl ---
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
[01;31m[KcURL[m[K - Buffer Overflow (PoC)                  | linux/dos/24487.py
[01;31m[KcURL[m[K 6.1 < 7.4 - Remote Buffer Overflow (1)   | freebsd/remote/20292.pl
--- hydra ---
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
[01;31m[KHydra[m[KIrc 0.3.164 - Remote Denial of Service   | windows/dos/6201.html
---------------------------------------------- ---------------------------------
--- ls ---
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
15 TOTOLINK Router Mode[01;31m[Kls[m[K - Multiple Remote C | hardware/webapps/37623.txt
2DayBiz Real Estate Portal - 'viewpropertydet | php/webapps/14019.txt
--- nc ---
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
1024 CMS 1.1.0 Beta - 'force_download.php' Lo | php/webapps/18000.txt
1024 CMS 1.3.1 - Local File I[01;31m[Knc[m[Klusion / SQL I | php/webapps/4765.txt
--- ssh ---
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
([01;31m[KSSH[m[K.com Communications) [01;31m[KSSH[m[K Tectia ([01;31m[KSSH[m[K < 2. | linux/remote/23082.txt
([01;31m[KSSH[m[K.com Communications) [01;31m[KSSH[m[K Tectia - USERAUT | unix/remote/23156.rb
--- wget ---
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
feh 1.7 - '--[01;31m[Kwget[m[K-Timestamp' Remote Code Exec | linux/remote/34201.txt
GNU [01;31m[Kwget[m[K - Cookie Injection                   | linux/local/44601.txt
```

## Methodology

1. **Binary Import** — Ghidra headless imports ELF/PE/Mach-O binaries with full auto-analysis
2. **Function Extraction** — `VigilExportSummary.java` exports all functions with signatures, entry points, and calling conventions
3. **Symbol Enumeration** — All imported and exported symbols with addresses and types
4. **String Extraction** — All printable strings with addresses and data types
5. **Risky Surface Detection** — Pattern matching on known-dangerous C functions: `execve`, `system`, `popen`, `sprintf`, `strcpy`, `strcat`, `gets`, `memcpy`, `strncpy`
6. **CVE Cross-Reference** — searchsploit/ExploitDB lookup for known vulnerabilities in each binary

## Usage

```bash
# Analyze any binary (ELF, PE, Mach-O)
/usr/share/ghidra/support/analyzeHeadless <projectDir> <projectName> \
  -import <binary> \
  -scriptPath scripts \
  -postScript VigilExportSummary.java <outputDir>
```

## Via Vigil MCP

When Vigil is running with the Ghidra MCP server connected:
```
ghidra_export_summary(target="/path/to/binary.exe")
```

Works cross-OS — ELF (Linux), PE (Windows), Mach-O (macOS) all supported.

---
Sun Jul  5 07:21:03 PM UTC 2026
