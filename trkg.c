#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <cjson/cJSON.h>
#include <limits.h>
#include <errno.h>
#include <sys/wait.h>

#define REPO_URL "https://repopisipkg.pythonanywhere.com/packages.json"
#define MAX_PATH_LEN 4096
#define MAX_NAME_LEN 256
#define MAX_CMD_LEN 1024

struct Memory { char *data; size_t size; };

int safe_strcpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) return -1;
    size_t src_len = strlen(src);
    if (src_len >= dest_size) return -1;
    strcpy(dest, src);
    return 0;
}

int validate_name(const char *name) {
    if (!name || strlen(name) == 0 || strlen(name) > MAX_NAME_LEN) return 0;
    
    for (int i = 0; name[i]; i++) {
        char c = name[i];
        if (!(c >= 'a' && c <= 'z') && 
            !(c >= 'A' && c <= 'Z') && 
            !(c >= '0' && c <= '9') && 
            c != '-' && c != '_' && c != '.') {
            return 0;
        }
    }
    
    if (strcmp(name, "..") == 0 || strcmp(name, ".") == 0) return 0;
    if (strstr(name, "..") != NULL) return 0;
    
    return 1;
}

int validate_url(const char *url) {
    if (!url) return 0;
    return (strncmp(url, "https://", 8) == 0);
}

int validate_filename(const char *filename) {
    if (!filename) return 0;
    

    if (strstr(filename, "..") || strstr(filename, "/") || strstr(filename, "\\")) {
        return 0;
    }
    
    for (int i = 0; filename[i]; i++) {
        char c = filename[i];
        if (!(c >= 'a' && c <= 'z') && 
            !(c >= 'A' && c <= 'Z') && 
            !(c >= '0' && c <= '9') && 
            c != '-' && c != '_' && c != '.') {
            return 0;
        }
    }
    
    return 1;
}

static size_t cb_write(void *ptr, size_t size, size_t nmemb, void *user) {
    size_t total = size * nmemb;
    struct Memory *m = user;
    
    if (m->size + total > 100 * 1024 * 1024) {
        return 0;
    }
    
    char *new_data = realloc(m->data, m->size + total + 1);
    if (!new_data) {
        return 0;
    }
    
    m->data = new_data;
    memcpy(m->data + m->size, ptr, total);
    m->size += total;
    m->data[m->size] = 0;
    return total;
}

char *sha256sum(const char *file) {
    if (!validate_filename(file)) return NULL;
    
    FILE *f = fopen(file, "rb");
    if (!f) return NULL;
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    unsigned char buf[32768], h[SHA256_DIGEST_LENGTH];
    int n;
    
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    
    SHA256_Final(h, &ctx);
    fclose(f);
    
    static char out[65];
    for (int i = 0; i < 32; i++) {
        sprintf(out + 2 * i, "%02x", h[i]);
    }
    out[64] = 0;
    return out;
}

int download_url(const char *url, const char *out) {
    if (!validate_url(url) || !validate_filename(out)) {
        fprintf(stderr, "[!] Geçersiz URL veya dosya adı\n");
        return 1;
    }
    
    CURL *c = curl_easy_init();
    if (!c) return 1;
    
    struct Memory m = {.data = malloc(1), .size = 0};
    if (!m.data) {
        curl_easy_cleanup(c);
        return 1;
    }
    
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, cb_write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    
    CURLcode res = curl_easy_perform(c);
    curl_easy_cleanup(c);
    
    if (res != CURLE_OK) {
        free(m.data);
        return 1;
    }
    
    FILE *f = fopen(out, "wb");
    if (!f) {
        free(m.data);
        return 1;
    }
    
    fwrite(m.data, 1, m.size, f);
    fclose(f);
    free(m.data);
    return 0;
}

int safe_system(const char *cmd) {
    if (!cmd) return -1;
    
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    }
    
    return -1;
}

int safe_mkdir_recursive(const char *path) {
    if (!path || strlen(path) > MAX_PATH_LEN) return -1;
    
    char temp[MAX_PATH_LEN];
    if (safe_strcpy(temp, path, sizeof(temp)) != 0) return -1;
    
    for (char *p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    
    if (mkdir(temp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    
    return 0;
}

void add_path_to_bashrc() {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "[!] HOME environment variable not set\n");
        return;
    }

    char full_path[MAX_PATH_LEN];
    if (snprintf(full_path, sizeof(full_path), "%s/.bashrc", home) >= sizeof(full_path)) {
        fprintf(stderr, "[!] Path too long\n");
        return;
    }

    const char *path_line = "export PATH=\"$HOME/.local/data/usr/local/bin:$PATH\"";

    FILE *f = fopen(full_path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            if (strcmp(line, path_line) == 0) {
                fclose(f);
                printf("[*] PATH zaten .bashrc içinde.\n");
                return;
            }
        }
        fclose(f);
    }

    f = fopen(full_path, "a");
    if (!f) {
        fprintf(stderr, "[!] .bashrc dosyasına yazılamıyor.\n");
        return;
    }
    fprintf(f, "\n# Added by TRKG package manager\n%s\n", path_line);
    fclose(f);
    printf("[+] PATH ~/.bashrc dosyasına eklendi. Lütfen terminali yeniden başlatın veya 'source ~/.bashrc' çalıştırın.\n");
}

void print_banner_wout_usage() {
    printf(" /\\_/\\  TRKG Package Manager\n");
    printf("( o.o )  dreamtech.dev & FreeC-14\n");
    printf(" > ^ <  Tarafından Sevgiyle Yapıldı :)\n\n");
}

void cmd_init(const char *name) {
    if (!validate_name(name)) {
        fprintf(stderr, "[!] Geçersiz paket adı: %s\n", name);
        exit(1);
    }
    
    if (access(name, F_OK) == 0) {
        fprintf(stderr, "[!] %s already exists\n", name);
        exit(1);
    }
    
    char path1[MAX_PATH_LEN], path2[MAX_PATH_LEN];
    if (snprintf(path1, sizeof(path1), "%s/data/usr/local/bin", name) >= sizeof(path1) ||
        snprintf(path2, sizeof(path2), "%s/data/etc", name) >= sizeof(path2)) {
        fprintf(stderr, "[!] Path too long\n");
        exit(1);
    }
    
    if (safe_mkdir_recursive(path1) != 0 || safe_mkdir_recursive(path2) != 0) {
        fprintf(stderr, "[!] Failed to create directories\n");
        exit(1);
    }
    
    char control_file[MAX_PATH_LEN];
    if (snprintf(control_file, sizeof(control_file), "%s/control.trkg", name) >= sizeof(control_file)) {
        fprintf(stderr, "[!] Path too long\n");
        exit(1);
    }
    
    FILE *f = fopen(control_file, "w");
    if (!f) {
        fprintf(stderr, "[!] Failed to create control file\n");
        exit(1);
    }
    
    fprintf(f, "Name: %s\nVersion: 0.0.0\nDescription: Açıklama\nAuthor: Siz\n", name);
    fclose(f);
    printf("[+] '%s/' created.\n", name);
}

void cmd_build() {
    char cwd[MAX_PATH_LEN];
    if (!getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "[!] Çalışma dizini alınamadı\n");
        return;
    }

    char control_file[MAX_PATH_LEN];
    snprintf(control_file, sizeof(control_file), "%s/control.trkg", cwd);

    FILE *f = fopen(control_file, "r");
    if (!f) {
        fprintf(stderr, "[!] control.trkg dosyası bulunamadı\n");
        return;
    }

    char name[128] = {0}, version[64] = {0};
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line + 5, "%127s", name);
        } else if (strncmp(line, "Version:", 8) == 0) {
            sscanf(line + 8, "%63s", version);
        }
    }

    fclose(f);

    if (!validate_name(name) || strlen(version) == 0) {
        fprintf(stderr, "[!] control.trkg içinde geçersiz Name veya Version\n");
        return;
    }

    char output_file[MAX_PATH_LEN];
    snprintf(output_file, sizeof(output_file), "%s-%s.trkg", name, version);

    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "tar -czf %s data control.trkg", output_file);

    int ret = safe_system(cmd);
    if (ret == 0) {
        printf("[+] Paket oluşturuldu: %s\n", output_file);
    } else {
        fprintf(stderr, "[!] Paket oluşturulamadı\n");
    }
}


void cmd_list() {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    char path[MAX_PATH_LEN];
    if (snprintf(path, sizeof(path), "%s/.local/data/usr/local/bin", home) >= sizeof(path)) {
        fprintf(stderr, "[!] Path too long\n");
        return;
    }

    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "[!] Paket dizini bulunamadı: %s\n", path);
        return;
    }

    struct dirent *entry;
    printf("[*] Yüklü paketler:\n");
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        printf(" - %s\n", entry->d_name);
    }
    closedir(d);
}

void cmd_info(const char *pkg) {
    if (!validate_name(pkg)) {
        fprintf(stderr, "[!] Geçersiz paket adı: %s\n", pkg);
        return;
    }
    
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    char path[MAX_PATH_LEN];
    if (snprintf(path, sizeof(path), "%s/.local/data/%s/control.trkg", home, pkg) >= sizeof(path)) {
        fprintf(stderr, "[!] Path too long\n");
        return;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[!] Paket bulunamadı veya kontrol dosyası eksik: %s\n", pkg);
        return;
    }

    printf("[*] %s paket bilgileri:\n\n", pkg);

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
    }

    fclose(f);
}

void cmd_clean() {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    printf("[*] Temizlik başlıyor...\n");

    if (remove("tmp_repo.json") == 0)
        printf("[+] tmp_repo.json silindi.\n");

    char cmd[MAX_CMD_LEN];
    if (snprintf(cmd, sizeof(cmd), "find %s/.local/data -name '*.trkg' -type f -delete", home) >= sizeof(cmd)) {
        fprintf(stderr, "[!] Command too long\n");
        return;
    }
    
    int ret = safe_system(cmd);
    if (ret == 0)
        printf("[+] Geçici paket dosyaları silindi.\n");
    else
        printf("[!] Geçici paket dosyaları silinemedi veya bulunamadı.\n");
}

void cmd_install(const char *pkg) {
    if (!validate_filename(pkg)) {
        fprintf(stderr, "[!] Geçersiz paket dosya adı: %s\n", pkg);
        return;
    }
    
    printf("[+] Installing %s...\n", pkg);
    
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    
    char data_dir[MAX_PATH_LEN];
    if (snprintf(data_dir, sizeof(data_dir), "%s/.local/data", home) >= sizeof(data_dir)) {
        fprintf(stderr, "[!] Path too long\n");
        return;
    }
    
    if (safe_mkdir_recursive(data_dir) != 0) {
        fprintf(stderr, "[!] Failed to create data directory\n");
        return;
    }
    
    char cmd[MAX_CMD_LEN];
    if (snprintf(cmd, sizeof(cmd), "tar -xzf %s -C %s --strip-components=1", pkg, data_dir) >= sizeof(cmd)) {
        fprintf(stderr, "[!] Command too long\n");
        return;
    }
    
    if (safe_system(cmd) == 0) {
        char chmod_cmd[MAX_CMD_LEN];
        if (snprintf(chmod_cmd, sizeof(chmod_cmd), "chmod +x %s/usr/local/bin/*", data_dir) < sizeof(chmod_cmd)) {
            safe_system(chmod_cmd);
        }
        printf("[+] Installed %s\n", pkg);
    } else {
        fprintf(stderr, "[!] Install failed: %s\n", pkg);
    }
}

void cmd_remove(const char *name) {
    if (!validate_name(name)) {
        fprintf(stderr, "[!] Geçersiz paket adı: %s\n", name);
        return;
    }
    
    printf("[+] Removing %s...\n", name);
    
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "[!] HOME environment variable not set\n");
        return;
    }
    
    char cmd[MAX_CMD_LEN];
    if (snprintf(cmd, sizeof(cmd), "rm -rf %s/.local/data/usr/local/bin/%s", home, name) >= sizeof(cmd)) {
        fprintf(stderr, "[!] Command too long\n");
        return;
    }
    
    if (safe_system(cmd) == 0) {
        printf("[+] Removed %s\n", name);
    } else {
        fprintf(stderr, "[!] Remove failed: %s\n", name);
    }
}

void print_help() {
    printf("TRKG Paket Yöneticisi Komutları:\n");
    printf("  init <name>       : Yeni paket dizini oluşturur\n");
    printf("  build             : Paketi derler\n");
    printf("  install <file>    : Paketi kurar\n");
    printf("  remove <name>     : Paketi kaldırır\n");
    printf("  search <query>    : Paketlerde arama yapar\n");
    printf("  upgrade           : Reposundaki paketleri günceller\n");
    printf("  help              : Bu yardım mesajını gösterir\n");
}

void cmd_search(const char *query) {
    if (!validate_name(query)) {
        fprintf(stderr, "[!] Geçersiz arama sorgusu: %s\n", query);
        return;
    }
    
    curl_global_init(CURL_GLOBAL_ALL);
    
    char tmp[] = "tmp_repo.json";
    if (download_url(REPO_URL, tmp)) {
        fprintf(stderr, "[!] Repo indirilemedi.\n");
        curl_global_cleanup();
        return;
    }
    
    FILE *f = fopen(tmp, "rb");
    if (!f) {
        fprintf(stderr, "[!] Temporary file could not be opened\n");
        curl_global_cleanup();
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    
    if (sz <= 0 || sz > 10 * 1024 * 1024) {
        fprintf(stderr, "[!] Invalid file size\n");
        fclose(f);
        remove(tmp);
        curl_global_cleanup();
        return;
    }
    
    char *d = malloc(sz + 1);
    if (!d) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        fclose(f);
        remove(tmp);
        curl_global_cleanup();
        return;
    }
    
    fread(d, 1, sz, f);
    d[sz] = 0;
    fclose(f);
    
    cJSON *j = cJSON_Parse(d);
    free(d);
    remove(tmp);
    
    if (!j) {
        fprintf(stderr, "[!] JSON parse error\n");
        curl_global_cleanup();
        return;
    }
    
    int n = cJSON_GetArraySize(j);
    for (int i = 0; i < n; i++) {
        cJSON *pkg = cJSON_GetArrayItem(j, i);
        if (!pkg) continue;
        
        cJSON *name_item = cJSON_GetObjectItem(pkg, "name");
        cJSON *desc_item = cJSON_GetObjectItem(pkg, "description");
        
        if (!name_item || !cJSON_IsString(name_item)) continue;
        
        const char *name = name_item->valuestring;
        const char *desc = desc_item && cJSON_IsString(desc_item) ? desc_item->valuestring : "";
        
        if (strstr(name, query) || (desc && strstr(desc, query))) {
            printf(" * %s: %s\n", name, desc);
        }
    }
    
    cJSON_Delete(j);
    curl_global_cleanup();
}

void cmd_upgrade() {
    curl_global_init(CURL_GLOBAL_ALL);
    
    char tmp[] = "tmp_repo.json";
    if (download_url(REPO_URL, tmp)) {
        fprintf(stderr, "[!] Repo hata\n");
        curl_global_cleanup();
        return;
    }
    
    FILE *f = fopen(tmp, "rb");
    if (!f) {
        fprintf(stderr, "[!] Temporary file could not be opened\n");
        curl_global_cleanup();
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    
    if (sz <= 0 || sz > 10 * 1024 * 1024) {
        fprintf(stderr, "[!] Invalid file size\n");
        fclose(f);
        remove(tmp);
        curl_global_cleanup();
        return;
    }
    
    char *d = malloc(sz + 1);
    if (!d) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        fclose(f);
        remove(tmp);
        curl_global_cleanup();
        return;
    }
    
    fread(d, 1, sz, f);
    d[sz] = 0;
    fclose(f);
    
    cJSON *j = cJSON_Parse(d);
    free(d);
    remove(tmp);
    
    if (!j) {
        fprintf(stderr, "[!] JSON parse error\n");
        curl_global_cleanup();
        return;
    }
    
    int n = cJSON_GetArraySize(j);
    for (int i = 0; i < n; i++) {
        cJSON *pkg = cJSON_GetArrayItem(j, i);
        if (!pkg) continue;
        
        cJSON *name_item = cJSON_GetObjectItem(pkg, "name");
        cJSON *ver_item = cJSON_GetObjectItem(pkg, "version");
        cJSON *url_item = cJSON_GetObjectItem(pkg, "url");
        cJSON *sha_item = cJSON_GetObjectItem(pkg, "sha256");
        
        if (!name_item || !cJSON_IsString(name_item) ||
            !ver_item || !cJSON_IsString(ver_item) ||
            !url_item || !cJSON_IsString(url_item) ||
            !sha_item || !cJSON_IsString(sha_item)) {
            continue;
        }
        
        const char *name = name_item->valuestring;
        const char *ver = ver_item->valuestring;
        const char *url = url_item->valuestring;
        const char *sha = sha_item->valuestring;
        
        if (!validate_name(name) || !validate_url(url)) {
            fprintf(stderr, "[!] Invalid package data: %s\n", name);
            continue;
        }
        
        const char *fn = strrchr(url, '/');
        if (!fn) {
            fprintf(stderr, "[!] Invalid URL format: %s\n", url);
            continue;
        }
        fn++;
        
        if (!validate_filename(fn)) {
            fprintf(stderr, "[!] Invalid filename: %s\n", fn);
            continue;
        }
        
        printf("[+] %s (%s) downloading...\n", name, ver);
        
        if (download_url(url, fn)) {
            fprintf(stderr, "[!] Download failed: %s\n", name);
            continue;
        }
        
        char *act = sha256sum(fn);
        if (!act || strcmp(act, sha) != 0) {
            fprintf(stderr, "[!] SHA mismatch: %s\n", name);
            remove(fn);
            continue;
        }
        
        printf("[✓] %s verified\n", name);
        cmd_install(fn);
        remove(fn);
    }
    
    cJSON_Delete(j);
    curl_global_cleanup();
}

void print_banner() {
    printf(" /\\_/\\  TRKG Package Manager\n");
    printf("( o.o )  dreamtech.dev & FreeC-14\n");
    printf(" > ^ <  Kullanım: trkg <cmd> [arg]\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_banner_wout_usage();
        fprintf(stderr, "Unknown or missing command\n");
        return 1;
    }

    const char *c = argv[1];

    if (strcmp(c, "help") == 0) {
        print_banner();
        print_help();
        return 0;
    }

    print_banner_wout_usage();

    if (strcmp(c, "init") == 0 && argc == 3) {
        cmd_init(argv[2]);
    }
    else if (strcmp(c, "build") == 0) {
        cmd_build();
    }
    else if (strcmp(c, "install") == 0 && argc == 3) {
        cmd_install(argv[2]);
    }
    else if (strcmp(c, "remove") == 0 && argc == 3) {
        cmd_remove(argv[2]);
    }
    else if (strcmp(c, "search") == 0 && argc == 3) {
        cmd_search(argv[2]);
    }
    else if (strcmp(c, "upgrade") == 0) {
        cmd_upgrade();
    }
    else if (strcmp(c, "path") == 0) {
        add_path_to_bashrc();
        return 0;
    }
    else if (strcmp(c, "list") == 0) {
        cmd_list();
    }
    else if (strcmp(c, "info") == 0 && argc == 3) {
        cmd_info(argv[2]);
    }
    else if (strcmp(c, "clean") == 0) {
        cmd_clean();
    }
    else {
        fprintf(stderr, "Unknown or missing command\n");
        return 1;
    }

    return 0;
}
