
typedef struct PureFTPd_SiteCallback_ {
    int return_code;
    char *response;
} PureFTPd_SiteCallback;

void pureftpd_register_login_callback(void (*callback)(void *user_data),
                                      void *user_data);

void pureftpd_register_logout_callback(void (*callback)(void *user_data),
                                       void *user_data);

void pureftpd_register_log_callback(void (*callback)(int crit,
                                                     const char *message,
                                                     void *user_data),
                                    void *user_data);

void pureftpd_register_simple_auth_callback(int (*callback)(const char *account,
                                                            const char *password,
                                                            void *user_data),
                                            void *user_data);

int pureftpd_start(int argc, char *argv[], const char *home_directory);

int pureftpd_shutdown(void);
int pureftpd_enable(void);
int pureftpd_disable(void);

void pureftpd_register_site_callback
    (const char *site_command,
     PureFTPd_SiteCallback *(*callback)(const char *arg, void *user_data),
     void (*free_callback)(PureFTPd_SiteCallback *site_callback,
                           void *user_data),
     void *user_data);
