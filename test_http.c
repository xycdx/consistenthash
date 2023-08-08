#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

struct progress
{
    char *private;
    size_t size;
};

static size_t progress_callback(void *clientp,
                                double dltotal,
                                double dlnow,
                                double ultotal,
                                double ulnow)
{
    printf("downloading: %.0f / %.0f \n", dlnow, dltotal);
    return 0;
}

int main()
{
    CURL *curl;
    CURLcode res;
    const char *referer = "Referer: http://www.tangdou.com/";
    const char *origin = "Origin: http://www.tangdou.com/";
    const char *range = "Range: bytes=0-1";
    const char *host = "Host: aqiniushare.tangdou.com";
    const char *url = "http://175.152.138.36:2280/aqiniushare.tangdou.com/202307/20000005637578_H540P.mp4?sign=3e6c2749c453aa3c6c70ff9999054fa6&t=64c8eefe";
    int retryTimes = 0;
    int internalRequest = 1;

    FILE *fp;
    fp = fopen("example.mp4", "wb");

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    struct curl_slist *headers = NULL;
    struct progress data;
    // headers = curl_slist_append(headers, range);
    headers = curl_slist_append(headers, origin);
    headers = curl_slist_append(headers, referer);
    // headers = curl_slist_append(headers, host);
    // headers = curl_slist_append(headers, "X-Miku-Agent: miku-delivery-android/1.1.2");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    // curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

    // curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    // curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &data);
    // curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);

    printf("start download\n");
    res = curl_easy_perform(curl);
    printf("finish download\n");
    if (res == CURLE_OK) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        char *response_message = NULL;
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &response_message);
        printf("code: %d, message: %s \n", response_code, response_message);
        if (response_code >= 300 && response_code < 400) {
            char *location;
            curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &location);
            if (location) {
                printf("redirect to: %s \n", location);
                curl_slist_free_all(headers);
                headers = NULL;

                curl = curl_easy_init();
                curl_easy_setopt(curl, CURLOPT_URL, location);
                // headers = curl_slist_append(headers, range);
                // headers = curl_slist_append(headers, "X-Miku-Agent: miku-delivery-android/1.1.2");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

                printf("start download\n");
                res = curl_easy_perform(curl);
                printf("finish download\n");

                if (res == CURLE_OK) {
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &response_message);
                    printf("code: %d, message: %s\n", response_code, response_message);
                } else {
                    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                }
            }
        } else {
            
        }
    } else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    fclose(fp);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    return 0;
}
