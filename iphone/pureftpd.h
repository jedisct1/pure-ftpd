
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
