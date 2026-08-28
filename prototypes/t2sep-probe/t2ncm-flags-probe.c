// SPDX-License-Identifier: MIT
/* Fail-closed probe for AppleUSBNCM's device-to-host interface-flags read. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define LIVE_T2_NCM_FLAGS_READ_ENABLED 0
#define T2_INTERFACE "/sys/bus/usb/devices/7-1:1.0"
#define CONFIRMATION "I_UNDERSTAND_THIS_ONLY_READS_FOUR_T2_NCM_FLAG_BYTES"

static int read_number(const char *directory, const char *name,
                       unsigned int *value, int base)
{
    char path[PATH_MAX];
    char text[32];
    char *end = NULL;
    int fd;
    ssize_t count;
    unsigned long parsed;

    if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    count = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (count <= 0 || count >= (ssize_t)sizeof(text))
        return -1;
    text[count] = '\0';
    errno = 0;
    parsed = strtoul(text, &end, base);
    if (errno || end == text || (*end != '\n' && *end != '\0') || parsed > UINT_MAX)
        return -1;
    *value = (unsigned int)parsed;
    return 0;
}

static int exact_device_path(char device[PATH_MAX], unsigned int *interface_number,
                             unsigned int *bus, unsigned int *dev)
{
    char resolved[PATH_MAX];
    char usb[PATH_MAX];
    char *interface_name;
    unsigned int vendor, product;

    if (!realpath(T2_INTERFACE, resolved))
        return -1;
    if (!strstr(resolved, "/0000:04:00.1/") || !strstr(resolved, "/t2bce_vhci/usb"))
        return -1;
    if (strlen(resolved) >= sizeof(usb))
        return -1;
    strcpy(usb, resolved);
    interface_name = strrchr(usb, '/');
    if (!interface_name || !strchr(interface_name + 1, ':') ||
        strcmp(strchr(interface_name + 1, ':'), ":1.0") != 0)
        return -1;
    *interface_name = '\0';
    if (read_number(usb, "idVendor", &vendor, 16) || vendor != 0x05ac ||
        read_number(usb, "idProduct", &product, 16) || product != 0x8233 ||
        read_number(resolved, "bInterfaceNumber", interface_number, 16) ||
        *interface_number != 0 || read_number(usb, "busnum", bus, 10) ||
        read_number(usb, "devnum", dev, 10) || *bus > 999 || *dev > 999)
        return -1;
    if (snprintf(device, PATH_MAX, "/dev/bus/usb/%03u/%03u", *bus, *dev) >= PATH_MAX)
        return -1;
    return 0;
}

static int control_read(int fd, uint8_t request_type, uint8_t request,
                        uint16_t value, uint16_t index, void *data, uint16_t length)
{
    struct usbdevfs_ctrltransfer transfer = {
        .bRequestType = request_type,
        .bRequest = request,
        .wValue = value,
        .wIndex = index,
        .wLength = length,
        .timeout = 1000,
        .data = data,
    };
    return ioctl(fd, USBDEVFS_CONTROL, &transfer);
}

int main(int argc, char **argv)
{
    const char *output = NULL;
    const char *confirmation = NULL;
    bool live = false;
    char device[PATH_MAX];
    unsigned int interface_number, bus, dev;
    uint8_t descriptor[18] = {0};
    uint8_t flags[4] = {0};
    int fd = -1, out = -1, result = EXIT_FAILURE;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--live"))
            live = true;
        else if (!strcmp(argv[i], "--confirm") && ++i < argc)
            confirmation = argv[i];
        else if (!strcmp(argv[i], "--output") && ++i < argc)
            output = argv[i];
        else {
            fprintf(stderr, "invalid arguments\n");
            return EXIT_FAILURE;
        }
    }
    if (!live) {
        puts("offline only: request-type=0xa1 request=0xa0 value=0 index=0 length=4");
        return EXIT_SUCCESS;
    }
#if !LIVE_T2_NCM_FLAGS_READ_ENABLED
    fprintf(stderr, "live T2 NCM flags read disabled in source\n");
    return EXIT_FAILURE;
#endif
    if (!confirmation || strcmp(confirmation, CONFIRMATION) || !output || output[0] != '/' ||
        strstr(output, "..")) {
        fprintf(stderr, "live mode requires the exact confirmation and an absolute output path\n");
        return EXIT_FAILURE;
    }
    if (exact_device_path(device, &interface_number, &bus, &dev)) {
        fprintf(stderr, "refusing device whose T2 USB/PCI identity is not exact\n");
        return EXIT_FAILURE;
    }
    fd = open(device, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        perror("open usbfs device");
        goto done;
    }
    if (control_read(fd, 0x80, 0x06, 0x0100, 0, descriptor, sizeof(descriptor)) !=
            (int)sizeof(descriptor) || descriptor[0] != sizeof(descriptor) ||
        descriptor[1] != 0x01 || descriptor[8] != 0xac || descriptor[9] != 0x05 ||
        descriptor[10] != 0x33 || descriptor[11] != 0x82) {
        fprintf(stderr, "usbfs descriptor identity did not match 05ac:8233\n");
        goto done;
    }
    if (control_read(fd, 0xa1, 0xa0, 0, (uint16_t)interface_number,
                     flags, sizeof(flags)) != (int)sizeof(flags)) {
        perror("Apple NCM flags read");
        goto done;
    }
    out = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0 || write(out, flags, sizeof(flags)) != (ssize_t)sizeof(flags)) {
        perror("create private evidence");
        goto done;
    }
    printf("read four Apple NCM flag bytes from verified 05ac:8233 on bus %u device %u\n",
           bus, dev);
    result = EXIT_SUCCESS;
done:
    if (out >= 0)
        close(out);
    if (fd >= 0)
        close(fd);
    return result;
}
