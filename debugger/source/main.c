// SPDX-License-Identifier: GPL-3.0-only

#include <ps4.h>
#include "ptrace.h"
#include "server.h"
#include "debug.h"
#include "protocol.h"
#include "net.h"

extern void run_init_array(void);

static int ps4debug_already_running(void) {
    int fd = sceNetSocket("guard", AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 0;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_len         = sizeof(sa);
    sa.sin_family      = AF_INET;
    sa.sin_port        = sceNetHtons(SERVER_PORT);
    sa.sin_addr.s_addr = 0x0100007Fu;

    int rc = sceNetConnect(fd, (struct sockaddr *)&sa, sizeof(sa));
    sceNetSocketClose(fd);
    return (rc == 0);
}

int _main(void) {

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    run_init_array();

    sceKernelSleep(2);

    if (ps4debug_already_running()) {
        sceSysUtilSendSystemNotificationWithText(222, "ps4debug is already running!");
        return 0;
    }

    sys_console_cmd(SYS_CONSOLE_CMD_JAILBREAK, NULL);

    mkdir("/update/PS4UPDATE.PUP", 0777);
    mkdir("/update/PS4UPDATE.PUP.net.temp", 0777);

    turboscan_startup_cleanup();

    // 1. Get the local IP address to display in the notification
    char ip_buf[16];
    memset(ip_buf, 0, sizeof(ip_buf));
    net_get_ip_address(ip_buf);

    // 2. Format and send the "Loaded/Ready" notification
    char notification_msg[256];
    snprintf(notification_msg, sizeof(notification_msg), "RIKU IS SNIFFING SOCKS");
    sceSysUtilSendSystemNotificationWithText(222, notification_msg);

    // 3. Initialize debugger components and start the server thread/loop
    ptrace_init();
    
    // This starts the listening server on SERVER_PORT and handles incoming connections
    server_init(); 

    return 0;
}
