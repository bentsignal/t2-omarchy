// SPDX-License-Identifier: GPL-2.0-only
/*
 * Read-only enumeration probe for the T2 SEP PCI function.
 *
 * This intentionally does not enable the PCI function, request regions,
 * map a BAR, register an interrupt, perform DMA, or write PCI/MMIO state.
 */

#include <linux/dmi.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <crypto/algapi.h>
#include <crypto/sha2.h>

#define PCI_VENDOR_ID_APPLE_LOCAL 0x106b
#define PCI_DEVICE_ID_APPLE_T2_SEP 0x1802

/* T8012 32-bit ASC mailbox layout from checkra1n/PongoOS. */
#define T2SEP_MAILBOX_BAR 4
#define T2SEP_MAILBOX_BASE 0x4000
#define T2SEP_ALT_MAILBOX_BASE 0x0000
#define T2SEP_SEND_STATUS (T2SEP_MAILBOX_BASE + 0x08)
#define T2SEP_RECV_STATUS (T2SEP_MAILBOX_BASE + 0x20)
#define T2SEP_RECV0 (T2SEP_MAILBOX_BASE + 0x34)
#define T2SEP_RECV1 (T2SEP_MAILBOX_BASE + 0x38)
#define T2SEP_RECV_EMPTY BIT(17)

/* Recovered from AppleSEPIntelIOP in Apple's macOS 14.5 KDK. */
#define T2SEP_INTEL_INBOX_STATUS 0x0108
#define T2SEP_INTEL_OUTBOX_STATUS 0x010c
#define T2SEP_INTEL_INBOX_EMPTY BIT(17)
#define T2SEP_INTEL_OUTBOX_FULL BIT(16)
#define T2SEP_INTEL_MSG_ERROR BIT(18)
#define T2SEP_INTEL_MSG_FATAL BIT(19)
#define T2SEP_INTEL_CPU_CONTROL 0x8028
#define T2SEP_INTEL_CPU_STOP 0x8024
#define T2SEP_INTEL_CPU_RESET 0x8040
#define T2SEP_INTEL_CPU_START 0x8048

static bool allow_unsupported_model;
module_param(allow_unsupported_model, bool, 0400);
MODULE_PARM_DESC(allow_unsupported_model,
	"Permit read-only enumeration on models other than MacBookPro16,1");

static bool read_mailbox_status;
module_param(read_mailbox_status, bool, 0400);
MODULE_PARM_DESC(read_mailbox_status,
	"Map BAR4 and read only the hypothesized T8012 mailbox status registers");

static bool read_one_message;
module_param(read_one_message, bool, 0400);
MODULE_PARM_DESC(read_one_message,
	"Consume and decode at most one waiting T8012 SEP-to-host mailbox message");

static bool scan_apertures;
module_param(scan_apertures, bool, 0400);
MODULE_PARM_DESC(scan_apertures,
	"Read status candidates at T8012 offsets in BAR0, BAR2, and BAR4");

static bool temporarily_enable_device;
module_param(temporarily_enable_device, bool, 0400);
MODULE_PARM_DESC(temporarily_enable_device,
	"Temporarily call pci_enable_device_mem() during the probe, then disable it");

static bool read_apple_layout;
module_param(read_apple_layout, bool, 0400);
MODULE_PARM_DESC(read_apple_layout,
	"Read only AppleSEPIntelIOP BAR4 status and CPU-control registers");

static bool apple_start_cpu_probe;
module_param(apple_start_cpu_probe, bool, 0400);
MODULE_PARM_DESC(apple_start_cpu_probe,
	"Reproduce Apple's CPU-start writes, poll status, then issue Apple's stop write");

static bool apple_start_with_msi;
module_param(apple_start_with_msi, bool, 0400);
MODULE_PARM_DESC(apple_start_with_msi,
	"Allocate Apple's two MSI vectors around the bounded CPU-start probe");

static bool apple_send_control_nop;
module_param(apple_send_control_nop, bool, 0400);
MODULE_PARM_DESC(apple_send_control_nop,
	"Send one non-mutating Apple control-endpoint NOP and read its response");

static bool apple_collect_discovery;
module_param(apple_collect_discovery, bool, 0400);
MODULE_PARM_DESC(apple_collect_discovery,
	"After a validated NOP, collect a bounded stream of passive endpoint 0xfd advertisements");

static bool apple_capture_ool_acks;
module_param(apple_capture_ool_acks, bool, 0400);
MODULE_PARM_DESC(apple_capture_ool_acks,
	"After validated sbio discovery, register bounded coherent OOL buffers and capture acknowledgements");

static ulong ool_ack_confirmation;
module_param(ool_ack_confirmation, ulong, 0400);
MODULE_PARM_DESC(ool_ack_confirmation,
	"Required explicit confirmation value 0x5345504f4f4c4143 for OOL acknowledgement capture");

static bool apple_capture_credential_ool_acks;
module_param(apple_capture_credential_ool_acks, bool, 0400);
MODULE_PARM_DESC(apple_capture_credential_ool_acks,
	"Capture only fixed ACM/AKS 16 KiB OOL acknowledgements; sends no service request");

static uint credential_endpoint;
module_param(credential_endpoint, uint, 0400);
MODULE_PARM_DESC(credential_endpoint,
	"Fixed credential service endpoint: 7 for AKS or 10 for ACM");

static ulong credential_ool_confirmation;
module_param(credential_ool_confirmation, ulong, 0400);
MODULE_PARM_DESC(credential_ool_confirmation,
	"Required explicit confirmation value 0x435245444f4f4c41 for credential OOL capture");

static bool apple_capture_dual_credential_ool_acks;
module_param(apple_capture_dual_credential_ool_acks, bool, 0400);
MODULE_PARM_DESC(apple_capture_dual_credential_ool_acks,
	"Register both fixed AKS and ACM OOL pairs; sends no service request");

static ulong dual_credential_ool_confirmation;
module_param(dual_credential_ool_confirmation, ulong, 0400);
MODULE_PARM_DESC(dual_credential_ool_confirmation,
	"Required explicit confirmation value 0x4455414c4f4f4c41 for dual credential OOL capture");

static bool apple_probe_aks_capabilities;
module_param(apple_probe_aks_capabilities, bool, 0400);
MODULE_PARM_DESC(apple_probe_aks_capabilities,
	"Send one non-mutating AKS operation-0x4d capabilities request after fixed OOL registration");

static ulong aks_capabilities_confirmation;
module_param(aks_capabilities_confirmation, ulong, 0400);
MODULE_PARM_DESC(aks_capabilities_confirmation,
	"Required explicit confirmation value 0x414b534341504142 for the AKS capabilities probe");

static bool apple_probe_aks_startup_environment;
module_param(apple_probe_aks_startup_environment, bool, 0400);
MODULE_PARM_DESC(apple_probe_aks_startup_environment,
	"Negotiate AKS capabilities and send normal-boot operation-0x2a environment setup");

static ulong aks_startup_environment_confirmation;
module_param(aks_startup_environment_confirmation, ulong, 0400);
MODULE_PARM_DESC(aks_startup_environment_confirmation,
	"Required explicit confirmation value 0x414b53454e565052 for the AKS startup-environment probe");

static bool apple_probe_acm_context_lifecycle;
module_param(apple_probe_acm_context_lifecycle, bool, 0400);
MODULE_PARM_DESC(apple_probe_acm_context_lifecycle,
	"Initialize ACM and create then delete one ephemeral context");

static ulong acm_context_confirmation;
module_param(acm_context_confirmation, ulong, 0400);
MODULE_PARM_DESC(acm_context_confirmation,
	"Required explicit confirmation value 0x41434d4354584c46 for the ACM context lifecycle probe");

struct t2sep_irq_probe {
	atomic_t count[2];
};

#define T2SEP_DISCOVERY_ENDPOINT 0xfd
#define T2SEP_DISCOVERY_MAX_RECORDS 64
#define T2SEP_SBIO_ENDPOINT 0x08
#define T2SEP_SBIO_NAME 0x6f696273
#define T2SEP_SBIO_IN_PAGES 4
#define T2SEP_SBIO_OUT_PAGES 75
#define T2SEP_OOL_CONFIRMATION 0x5345504f4f4c4143UL
#define T2SEP_CREDENTIAL_OOL_CONFIRMATION 0x435245444f4f4c41UL
#define T2SEP_DUAL_CREDENTIAL_OOL_CONFIRMATION 0x4455414c4f4f4c41UL
#define T2SEP_AKS_CAPABILITIES_CONFIRMATION 0x414b534341504142UL
#define T2SEP_AKS_STARTUP_ENV_CONFIRMATION 0x414b53454e565052UL
#define T2SEP_ACM_CONTEXT_CONFIRMATION 0x41434d4354584c46UL
#define T2SEP_AKS_ENDPOINT 0x07
#define T2SEP_ACM_ENDPOINT 0x0a
#define T2SEP_CREDENTIAL_OOL_SIZE (4 * PAGE_SIZE)
#define T2SEP_AKS_CAPABILITIES_SIZE 100
#define T2SEP_AKS_STARTUP_ENV_REQUEST_SIZE 0x470
#define T2SEP_AKS_STARTUP_ENV_REPLY_SIZE 0x58
#define T2SEP_AKS_STARTUP_ENV_BLOB_SIZE 0x40c
#define T2SEP_AKS_HEADER_SIZE 0x50
#define T2SEP_AKS_SERIALIZED_HEADER_SIZE 0x54
#define T2SEP_ACM_CONTEXT_RESPONSE_SIZE 17
#define T2SEP_ACM_CURRENT_CONTEXT_RESPONSE_SIZE 21
#define T2SEP_ACM_CONTEXT_SIZE 16
#define T2SEP_SBIO_IN_SIZE (T2SEP_SBIO_IN_PAGES * PAGE_SIZE)
#define T2SEP_SBIO_OUT_SIZE (T2SEP_SBIO_OUT_PAGES * PAGE_SIZE)

struct t2sep_discovery_entry {
	bool identity;
	bool limits;
	u32 name;
	u8 in_min;
	u8 in_max;
	u8 out_min;
	u8 out_max;
};

static irqreturn_t t2sep_probe_irq(int irq, void *data)
{
	atomic_inc(data);
	return IRQ_HANDLED;
}

static int t2sep_setup_msi(struct pci_dev *pdev, struct t2sep_irq_probe *probe)
{
	int ret;

	atomic_set(&probe->count[0], 0);
	atomic_set(&probe->count[1], 0);
	ret = pci_alloc_irq_vectors(pdev, 2, 2, PCI_IRQ_MSI);
	if (ret < 0)
		return ret;
	if (ret != 2) {
		pci_free_irq_vectors(pdev);
		return -ENOSPC;
	}

	ret = request_irq(pci_irq_vector(pdev, 0), t2sep_probe_irq, 0,
			  "t2sep-inbox", &probe->count[0]);
	if (ret)
		goto out_vectors;
	ret = request_irq(pci_irq_vector(pdev, 1), t2sep_probe_irq, 0,
			  "t2sep-outbox", &probe->count[1]);
	if (ret)
		goto out_irq0;

	dev_info(&pdev->dev, "allocated MSI vectors %d and %d\n",
		 pci_irq_vector(pdev, 0), pci_irq_vector(pdev, 1));
	return 0;

out_irq0:
	free_irq(pci_irq_vector(pdev, 0), &probe->count[0]);
out_vectors:
	pci_free_irq_vectors(pdev);
	return ret;
}

static void t2sep_teardown_msi(struct pci_dev *pdev,
			       struct t2sep_irq_probe *probe)
{
	dev_info(&pdev->dev, "MSI observations: vector0=%d vector1=%d\n",
		 atomic_read(&probe->count[0]), atomic_read(&probe->count[1]));
	free_irq(pci_irq_vector(pdev, 1), &probe->count[1]);
	free_irq(pci_irq_vector(pdev, 0), &probe->count[0]);
	pci_free_irq_vectors(pdev);
}

static int t2sep_read_intel_message(void __iomem *bar4, u32 words[4])
{
	u32 inbox = ioread32(bar4 + T2SEP_INTEL_INBOX_STATUS);

	if (inbox & T2SEP_INTEL_INBOX_EMPTY)
		return -EAGAIN;

	/* Apple reads all four words in order; the final word commits the pop. */
	words[0] = ioread32(bar4 + 0x810);
	words[1] = ioread32(bar4 + 0x814);
	words[2] = ioread32(bar4 + 0x818);
	words[3] = ioread32(bar4 + 0x81c);
	if (words[3] & (T2SEP_INTEL_MSG_ERROR | T2SEP_INTEL_MSG_FATAL))
		return -EIO;
	return 0;
}

static int t2sep_collect_discovery(struct pci_dev *pdev, void __iomem *bar4)
{
	struct t2sep_discovery_entry *entries;
	u32 records = 0;
	u32 identities = 0;
	u32 idle_ms = 0;
	u32 elapsed_ms;
	int awaiting_limits = -1;
	bool saw_message = false;
	int ret = 0;

	entries = kcalloc(256, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	for (elapsed_ms = 0; elapsed_ms < 1000; elapsed_ms += 10) {
		u32 words[4];
		u8 endpoint;
		u8 tag;
		u8 opcode;
		u8 endpoint_id;
		u32 i;

		ret = t2sep_read_intel_message(bar4, words);
		if (ret == -EAGAIN) {
			if (saw_message && (idle_ms += 10) >= 100) {
				ret = 0;
				break;
			}
			msleep(10);
			continue;
		}
		if (ret) {
			dev_err(&pdev->dev,
				"discovery transport error after %u records\n", records);
			break;
		}

		saw_message = true;
		idle_ms = 0;
		endpoint = words[0] & 0xff;
		tag = (words[0] >> 8) & 0xff;
		opcode = (words[0] >> 16) & 0xff;
		endpoint_id = (words[0] >> 24) & 0xff;
		dev_info(&pdev->dev,
			 "discovery candidate %u: %08x %08x %08x %08x\n",
			 records, words[0], words[1], words[2], words[3]);

		if (endpoint != T2SEP_DISCOVERY_ENDPOINT || tag || words[2] != 0) {
			dev_err(&pdev->dev,
				"bounded discovery stopped on non-discovery message\n");
			ret = -EPROTO;
			break;
		}
		if (++records > T2SEP_DISCOVERY_MAX_RECORDS) {
			dev_err(&pdev->dev, "bounded discovery record cap exceeded\n");
			ret = -E2BIG;
			break;
		}
		if (endpoint_id < 1 || endpoint_id > 0xfc) {
			dev_err(&pdev->dev,
				"discovery endpoint ID %#02x is outside service range\n",
				endpoint_id);
			ret = -EPROTO;
			break;
		}

		if (opcode == 0) {
			u8 name_byte;

			if (awaiting_limits >= 0) {
				dev_err(&pdev->dev,
					"identity %#02x was not followed by OOL limits\n",
					awaiting_limits);
				ret = -EPROTO;
				break;
			}
			if (entries[endpoint_id].identity) {
				dev_err(&pdev->dev,
					"duplicate discovery endpoint ID %#02x\n",
					endpoint_id);
				ret = -EEXIST;
				break;
			}
			for (i = 0; i < 256; i++) {
				if (entries[i].identity && entries[i].name == words[1]) {
					dev_err(&pdev->dev,
						"duplicate discovery endpoint name %08x\n",
						words[1]);
					ret = -EEXIST;
					break;
				}
			}
			if (ret)
				break;
			for (i = 0; i < 4; i++) {
				name_byte = (words[1] >> (i * 8)) & 0xff;
				if (name_byte < 0x20 || name_byte > 0x7e) {
					dev_err(&pdev->dev,
						"endpoint %#02x has non-printable name %08x\n",
						endpoint_id, words[1]);
					ret = -EPROTO;
					break;
				}
			}
			if (ret)
				break;
			entries[endpoint_id].identity = true;
			entries[endpoint_id].name = words[1];
			awaiting_limits = endpoint_id;
			identities++;
			dev_info(&pdev->dev,
				 "discovery identity: id=%#02x name=%08x\n",
				 endpoint_id, words[1]);
		} else if (opcode == 1) {
			if (!entries[endpoint_id].identity ||
			    entries[endpoint_id].limits ||
			    awaiting_limits != endpoint_id) {
				dev_err(&pdev->dev,
					"invalid OOL ordering for endpoint ID %#02x\n",
					endpoint_id);
				ret = -EPROTO;
				break;
			}
			entries[endpoint_id].limits = true;
			entries[endpoint_id].in_min = words[1] & 0xff;
			entries[endpoint_id].in_max = (words[1] >> 8) & 0xff;
			entries[endpoint_id].out_min = (words[1] >> 16) & 0xff;
			entries[endpoint_id].out_max = (words[1] >> 24) & 0xff;
			if (entries[endpoint_id].in_min > entries[endpoint_id].in_max ||
			    entries[endpoint_id].out_min > entries[endpoint_id].out_max) {
				dev_err(&pdev->dev,
					"inverted OOL range for endpoint ID %#02x\n",
					endpoint_id);
				ret = -EPROTO;
				break;
			}
			awaiting_limits = -1;
			dev_info(&pdev->dev,
				 "discovery OOL: id=%#02x in=%u..%u pages out=%u..%u pages\n",
				 endpoint_id, entries[endpoint_id].in_min,
				 entries[endpoint_id].in_max,
				 entries[endpoint_id].out_min,
				 entries[endpoint_id].out_max);
		} else {
			dev_err(&pdev->dev,
				"unknown discovery opcode %#02x\n", opcode);
			ret = -EPROTO;
			break;
		}
	}
	if (!ret && awaiting_limits >= 0) {
		dev_err(&pdev->dev,
			"discovery ended before OOL limits for endpoint %#02x\n",
			awaiting_limits);
		ret = -EPROTO;
	}
	if (!ret && (!entries[T2SEP_SBIO_ENDPOINT].identity ||
		     entries[T2SEP_SBIO_ENDPOINT].name != T2SEP_SBIO_NAME ||
		     !entries[T2SEP_SBIO_ENDPOINT].limits ||
		     entries[T2SEP_SBIO_ENDPOINT].in_min > T2SEP_SBIO_IN_PAGES ||
		     entries[T2SEP_SBIO_ENDPOINT].in_max < T2SEP_SBIO_IN_PAGES ||
		     entries[T2SEP_SBIO_ENDPOINT].out_min > T2SEP_SBIO_OUT_PAGES ||
		     entries[T2SEP_SBIO_ENDPOINT].out_max < T2SEP_SBIO_OUT_PAGES)) {
		dev_err(&pdev->dev,
			"discovery lacks usable sbio endpoint 0x08 OOL limits\n");
		ret = -ENODEV;
	}

	dev_info(&pdev->dev,
		 "bounded discovery complete: records=%u identities=%u sbio=%s limits=%s result=%d\n",
		 records, identities,
		 entries[T2SEP_SBIO_ENDPOINT].identity &&
		 entries[T2SEP_SBIO_ENDPOINT].name == T2SEP_SBIO_NAME ? "yes" : "no",
		 entries[T2SEP_SBIO_ENDPOINT].limits ? "yes" : "no", ret);
	kfree(entries);
	return ret;
}

static int t2sep_send_intel_message(void __iomem *bar4, const u32 words[3])
{
	u32 outbox = ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);

	if (outbox & T2SEP_INTEL_OUTBOX_FULL)
		return -EBUSY;
	iowrite32(words[0], bar4 + 0x820);
	iowrite32(words[1], bar4 + 0x824);
	iowrite32(words[2], bar4 + 0x828);
	iowrite32(0, bar4 + 0x82c);
	ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);
	return 0;
}

static int t2sep_wait_intel_message(void __iomem *bar4, u32 words[4])
{
	int i;

	for (i = 0; i < 500; i++) {
		int ret = t2sep_read_intel_message(bar4, words);

		if (ret != -EAGAIN)
			return ret;
		msleep(10);
	}
	return -ETIMEDOUT;
}

static int t2sep_capture_one_ool_ack(struct pci_dev *pdev,
				      void __iomem *bar4, u8 target, u8 opcode,
				      u8 tag, dma_addr_t dma, size_t size,
				      int expected_ack_opcode, int expected_ack_target)
{
	u32 request[3] = {
		target << 24 | opcode << 16 | tag << 8,
		lower_32_bits(dma >> PAGE_SHIFT),
		size,
	};
	u32 response[4];
	int ret;

	ret = t2sep_send_intel_message(bar4, request);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "OOL registration request: opcode=%u tag=%u words=%08x %08x %08x 00000000\n",
		 opcode, tag, request[0], request[1], request[2]);
	ret = t2sep_wait_intel_message(bar4, response);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "OOL acknowledgement: request_opcode=%u tag=%u raw=%08x %08x %08x %08x decoded_endpoint=%u decoded_tag=%u decoded_opcode=%u decoded_target=%u\n",
		 opcode, tag, response[0], response[1], response[2], response[3],
		 response[0] & 0xff, (response[0] >> 8) & 0xff,
		 (response[0] >> 16) & 0xff, (response[0] >> 24) & 0xff);
	if ((response[0] & 0xff) != 0 || ((response[0] >> 8) & 0xff) != tag ||
	    response[1] != 0 || response[2] != 0 ||
	    (response[3] & (T2SEP_INTEL_MSG_ERROR | T2SEP_INTEL_MSG_FATAL)))
		return -EPROTO;
	if (expected_ack_opcode >= 0 &&
	    (((response[0] >> 16) & 0xff) != expected_ack_opcode ||
	     ((response[0] >> 24) & 0xff) != expected_ack_target))
		return -EPROTO;
	return 0;
}

static int t2sep_aks_protect(u8 *wire, size_t wire_size, u32 version,
			     u8 digest[SHA256_DIGEST_SIZE])
{
	struct sha256_ctx context;
	size_t header_tail = version == 1 ? 0x38 : 0x40;

	if ((version != 1 && version != 2) ||
	    wire_size < T2SEP_AKS_SERIALIZED_HEADER_SIZE)
		return -EINVAL;
	sha256_init(&context);
	sha256_update(&context, wire + 4 + 0x10, header_tail);
	sha256_update(&context, wire + T2SEP_AKS_SERIALIZED_HEADER_SIZE,
		      wire_size - T2SEP_AKS_SERIALIZED_HEADER_SIZE);
	sha256_final(&context, digest);
	memcpy(wire + 4, digest, 16);
	return 0;
}

static int t2sep_aks_validate_reply(u8 *wire, size_t wire_size, u32 version,
				    u8 digest[SHA256_DIGEST_SIZE])
{
	u8 received_digest[16];
	int ret;

	if (get_unaligned_le32(wire) != T2SEP_AKS_HEADER_SIZE ||
	    get_unaligned_le32(wire + 4 + 0x10) != version ||
	    get_unaligned_le32(wire + 4 + 0x1c) != 0)
		return -EPROTO;
	memcpy(received_digest, wire + 4, sizeof(received_digest));
	memset(wire + 4, 0, sizeof(received_digest));
	ret = t2sep_aks_protect(wire, wire_size, version, digest);
	if (!ret && crypto_memneq(received_digest, digest,
				  sizeof(received_digest)))
		ret = -EBADMSG;
	memzero_explicit(received_digest, sizeof(received_digest));
	return ret;
}

static int t2sep_probe_aks_capabilities(struct pci_dev *pdev,
					void __iomem *bar4,
					void *send_buffer, void *receive_buffer,
					u32 *negotiated_version)
{
	u8 digest[SHA256_DIGEST_SIZE];
	u8 *send = send_buffer;
	u8 *receive = receive_buffer;
	u32 request[3] = { 0x00044d07, 0x00640000, 0 };
	u32 response[4];
	/* mach_continuous_time includes suspend; Linux boottime is its analogue. */
	u64 continuous_usec = ktime_get_boottime_ns() / NSEC_PER_USEC;
	u32 status;
	u64 remote_version;
	int ret;

	/*
	 * Exact version-1 empty operation-0x4d body. The identity fields mirror
	 * XNU kernproc: unique ID 0, default audit session 0, and no cdhash.
	 * This probe remains separately gated because that execution context is
	 * source-derived but has not yet been accepted by this T2.
	 */
	memset(send, 0, T2SEP_AKS_CAPABILITIES_SIZE);
	put_unaligned_le32(T2SEP_AKS_HEADER_SIZE, send);
	put_unaligned_le32(1, send + 4 + 0x10);
	put_unaligned_le64(continuous_usec, send + 4 + 0x14);
	put_unaligned_le64(1, send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 4);
	ret = t2sep_aks_protect(send, T2SEP_AKS_CAPABILITIES_SIZE, 1, digest);
	if (ret)
		goto out_scrub;
	dma_wmb();

	ret = t2sep_send_intel_message(bar4, request);
	if (ret)
		goto out_scrub;
	dev_info(&pdev->dev,
		 "AKS capabilities request: endpoint=7 selector=0x4d tag=4 length=100 header_version=1\n");
	ret = t2sep_wait_intel_message(bar4, response);
	if (ret)
		goto out_scrub;
	dev_info(&pdev->dev,
		 "AKS capabilities envelope: raw=%08x %08x %08x %08x\n",
		 response[0], response[1], response[2], response[3]);
	if (response[0] != 0x0004cd07 || response[1] != 0x00640000 ||
	    response[2] != 0 ||
	    (response[3] & (T2SEP_INTEL_MSG_ERROR | T2SEP_INTEL_MSG_FATAL))) {
		ret = -EPROTO;
		goto out_scrub;
	}

	dma_rmb();
	if (get_unaligned_le32(receive) != T2SEP_AKS_HEADER_SIZE ||
	    get_unaligned_le32(receive + 4 + 0x10) != 1 ||
	    get_unaligned_le32(receive + 4 + 0x1c) != 0 ||
	    get_unaligned_le32(receive + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 12) != 0) {
		ret = -EPROTO;
		goto out_scrub;
	}
	ret = t2sep_aks_validate_reply(receive,
				       T2SEP_AKS_CAPABILITIES_SIZE, 1, digest);
	if (ret)
		goto out_scrub;
	status = get_unaligned_le32(receive + T2SEP_AKS_SERIALIZED_HEADER_SIZE);
	remote_version = get_unaligned_le64(receive + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 4);
	if (status || remote_version < 1) {
		ret = status ? -EREMOTEIO : -EPROTONOSUPPORT;
		goto out_scrub;
	}
	dev_info(&pdev->dev,
		 "AKS capabilities reply passed strict validation: status=%d remote_header_version=%llu\n",
		 (s32)status, remote_version);
	if (negotiated_version)
		*negotiated_version = min_t(u64, remote_version, 2);
	ret = 0;

out_scrub:
	memzero_explicit(digest, sizeof(digest));
	return ret;
}

static int t2sep_probe_aks_startup_environment(struct pci_dev *pdev,
					       void __iomem *bar4,
					       void *send_buffer,
					       void *receive_buffer)
{
	u8 digest[SHA256_DIGEST_SIZE];
	u8 *send = send_buffer;
	u8 *receive = receive_buffer;
	u32 request[3] = { 0x00052a07, 0x04700000, 0 };
	u32 response[4];
	u32 version;
	u32 status;
	int ret;

	ret = t2sep_probe_aks_capabilities(pdev, bar4, send, receive, &version);
	if (ret)
		goto out_scrub;

	memset(send, 0, T2SEP_CREDENTIAL_OOL_SIZE);
	memset(receive, 0, T2SEP_CREDENTIAL_OOL_SIZE);
	put_unaligned_le32(T2SEP_AKS_HEADER_SIZE, send);
	put_unaligned_le32(version, send + 4 + 0x10);
	put_unaligned_le64(ktime_get_boottime_ns() / NSEC_PER_USEC,
			   send + 4 + 0x14);
	if (version == 2)
		put_unaligned_le64(ktime_get_real_seconds(), send + 4 + 0x48);
	put_unaligned_le64(1, send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 4);
	put_unaligned_le32(T2SEP_AKS_STARTUP_ENV_BLOB_SIZE,
			   send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 12);
	put_unaligned_le32(1, send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 16);
	/* no-effaceable-storage is absent on the supported machine: explicit 0. */
	put_unaligned_le32(0, send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 20);
	put_unaligned_le32(4, send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 24);
	ret = t2sep_aks_protect(send, T2SEP_AKS_STARTUP_ENV_REQUEST_SIZE,
				version, digest);
	if (ret)
		goto out_scrub;
	dma_wmb();

	ret = t2sep_send_intel_message(bar4, request);
	if (ret)
		goto out_scrub;
	dev_info(&pdev->dev,
		 "AKS startup environment request: endpoint=7 selector=0x2a tag=5 length=1136 header_version=%u no_effaceable_storage=0 mode=4\n",
		 version);
	ret = t2sep_wait_intel_message(bar4, response);
	if (ret)
		goto out_scrub;
	dev_info(&pdev->dev,
		 "AKS startup environment envelope: raw=%08x %08x %08x %08x\n",
		 response[0], response[1], response[2], response[3]);
	if (response[0] != 0x0005aa07 || response[1] != 0x00580000 ||
	    response[2] != 0 ||
	    (response[3] & (T2SEP_INTEL_MSG_ERROR | T2SEP_INTEL_MSG_FATAL))) {
		ret = -EPROTO;
		goto out_scrub;
	}
	dma_rmb();
	ret = t2sep_aks_validate_reply(receive,
				       T2SEP_AKS_STARTUP_ENV_REPLY_SIZE,
				       version, digest);
	if (ret)
		goto out_scrub;
	status = get_unaligned_le32(receive + T2SEP_AKS_SERIALIZED_HEADER_SIZE);
	if (status) {
		ret = -EREMOTEIO;
		goto out_scrub;
	}
	dev_info(&pdev->dev,
		 "AKS startup environment reply passed strict validation: status=%d header_version=%u\n",
		 (s32)status, version);
	ret = 0;

out_scrub:
	memzero_explicit(digest, sizeof(digest));
	return ret;
}

static int t2sep_acm_exchange(struct pci_dev *pdev, void __iomem *bar4,
			      const char *phase, u16 request_length,
			      u16 expected_reply_length)
{
	u32 request[3] = {
		T2SEP_ACM_ENDPOINT | 1 << 8 | request_length << 16,
		0,
		0,
	};
	u32 response[4];
	u16 reply_length;
	int ret;

	ret = t2sep_send_intel_message(bar4, request);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "ACM %s envelope request: raw=%08x %08x %08x 00000000\n",
		 phase, request[0], request[1], request[2]);
	ret = t2sep_wait_intel_message(bar4, response);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "ACM %s envelope reply: raw=%08x %08x %08x %08x\n",
		 phase, response[0], response[1], response[2], response[3]);
	reply_length = response[0] >> 16;
	if ((response[0] & 0xff) != T2SEP_ACM_ENDPOINT ||
	    ((response[0] >> 8) & 0xff) != 1 ||
	    reply_length != expected_reply_length || response[1] != 0 ||
	    response[2] != 0 ||
	    (response[3] & (T2SEP_INTEL_MSG_ERROR | T2SEP_INTEL_MSG_FATAL)))
		return -EPROTO;
	return 0;
}

static int t2sep_acm_create_exchange(struct pci_dev *pdev, void __iomem *bar4,
				     u8 selector, u16 expected_reply_length,
				     bool allow_minus_three_fallback)
{
	u32 request[3] = {
		T2SEP_ACM_ENDPOINT | 1 << 8 | 8 << 16,
		0,
		0,
	};
	u32 response[4];
	u16 reply_length;
	int ret;

	ret = t2sep_send_intel_message(bar4, request);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "ACM context-create-%02x envelope request: raw=%08x %08x %08x 00000000\n",
		 selector, request[0], request[1], request[2]);
	ret = t2sep_wait_intel_message(bar4, response);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "ACM context-create-%02x envelope reply: raw=%08x %08x %08x %08x\n",
		 selector, response[0], response[1], response[2], response[3]);
	reply_length = response[0] >> 16;
	if ((response[0] & 0xff) != T2SEP_ACM_ENDPOINT ||
	    ((response[0] >> 8) & 0xff) != 1 || response[2] != 0 ||
	    (response[3] & (T2SEP_INTEL_MSG_ERROR | T2SEP_INTEL_MSG_FATAL)))
		return -EPROTO;
	if (allow_minus_three_fallback && response[1] == 0xfffffffd) {
		if (reply_length != 0)
			return -EPROTO;
		return 1;
	}
	if (response[1] != 0 || reply_length != expected_reply_length)
		return -EPROTO;
	return 0;
}

static int t2sep_probe_acm_context_lifecycle(struct pci_dev *pdev,
					      void __iomem *bar4,
					      void *send_buffer,
					      void *receive_buffer)
{
	u8 *send = send_buffer;
	u8 *receive = receive_buffer;
	u16 context_response_size;
	int ret;

	memset(send, 0, 8);
	memcpy(send, "DRCS\n", 5);
	send[5] = 0x28;
	dma_wmb();
	dev_info(&pdev->dev,
		 "ACM SCRD initialization request: endpoint=10 message_type=1 length=8 version=0x28\n");
	ret = t2sep_acm_exchange(pdev, bar4, "SCRD-initialization", 8, 0);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "ACM SCRD initialization reply passed strict validation: status=0 length=0\n");

	/* Apple calls this selector through LibCall_ACMPing before privileged work. */
	memset(send, 0, 8);
	memcpy(send, "DRCS", 4);
	send[4] = 0x1d;
	send[7] = 1;
	dma_wmb();
	dev_info(&pdev->dev,
		 "ACM ping request: endpoint=10 message_type=1 selector=29 length=8 expected_reply=0\n");
	ret = t2sep_acm_exchange(pdev, bar4, "ping-1d", 8, 0);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "ACM ping reply passed strict validation: status=0 length=0\n");

	memset(receive, 0, T2SEP_ACM_CURRENT_CONTEXT_RESPONSE_SIZE);
	memcpy(send, "DRCS", 4);
	send[4] = 0x24;
	send[5] = 0;
	send[6] = 0;
	send[7] = 1;
	dma_wmb();
	dev_info(&pdev->dev,
		 "ACM context-create request: endpoint=10 message_type=1 selector=36 length=8 expected_reply=21\n");
	ret = t2sep_acm_create_exchange(
		pdev, bar4, 0x24, T2SEP_ACM_CURRENT_CONTEXT_RESPONSE_SIZE, true);
	if (ret < 0)
		return ret;
	if (ret == 1) {
		dev_info(&pdev->dev,
			 "ACM current context-create returned -3; applying Apple legacy fallback\n");
		memset(receive, 0, T2SEP_ACM_CONTEXT_RESPONSE_SIZE);
		send[4] = 1;
		dma_wmb();
		dev_info(&pdev->dev,
			 "ACM context-create fallback request: endpoint=10 message_type=1 selector=1 length=8 expected_reply=17\n");
		ret = t2sep_acm_create_exchange(
			pdev, bar4, 1, T2SEP_ACM_CONTEXT_RESPONSE_SIZE, false);
		if (ret)
			return ret;
		context_response_size = T2SEP_ACM_CONTEXT_RESPONSE_SIZE;
	} else {
		context_response_size = T2SEP_ACM_CURRENT_CONTEXT_RESPONSE_SIZE;
	}
	dma_rmb();
	dev_info(&pdev->dev,
		 "ACM context-create reply passed strict validation: status=0 length=%u context_bytes=not-logged\n",
		 context_response_size);

	memcpy(send, "DRCS", 4);
	send[4] = 2;
	send[5] = 0;
	send[6] = T2SEP_ACM_CONTEXT_SIZE;
	send[7] = 1;
	memcpy(send + 8, receive, T2SEP_ACM_CONTEXT_SIZE);
	dma_wmb();
	dev_info(&pdev->dev,
		 "ACM context-delete request: endpoint=10 message_type=1 selector=2 length=24 context_length=16 context_bytes=not-logged\n");
	ret = t2sep_acm_exchange(pdev, bar4, "context-delete", 24, 0);
	if (ret)
		return ret;
	dev_info(&pdev->dev,
		 "ACM context-delete reply passed strict validation: status=0 length=0\n");
	return 0;
}

static int t2sep_apple_start_cpu_probe(struct pci_dev *pdev, void __iomem *bar4)
{
	u32 inbox_before = ioread32(bar4 + T2SEP_INTEL_INBOX_STATUS);
	u32 outbox_before = ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);
	u32 inbox = inbox_before;
	u32 outbox = outbox_before;
	bool nop_valid = false;
	void *in_buffer = NULL;
	void *out_buffer = NULL;
	void *second_in_buffer = NULL;
	void *second_out_buffer = NULL;
	dma_addr_t in_dma = 0;
	dma_addr_t out_dma = 0;
	dma_addr_t second_in_dma = 0;
	dma_addr_t second_out_dma = 0;
	size_t in_size = T2SEP_SBIO_IN_SIZE;
	size_t out_size = T2SEP_SBIO_OUT_SIZE;
	u8 ool_target = T2SEP_SBIO_ENDPOINT;
	bool credential_ool = apple_capture_credential_ool_acks ||
			      apple_capture_dual_credential_ool_acks ||
			      apple_probe_aks_capabilities ||
			      apple_probe_aks_startup_environment ||
			      apple_probe_acm_context_lifecycle;
	int ret = 0;
	int i;

	/* Exact ordering from AppleSEPIntelIOP::_startCPUGated(). */
	iowrite32(0, bar4 + T2SEP_INTEL_CPU_RESET);
	iowrite32(1, bar4 + T2SEP_INTEL_CPU_START);
	iowrite32(5, bar4 + T2SEP_INTEL_CPU_CONTROL);
	/* Flush posted PCI writes before polling. */
	ioread32(bar4 + T2SEP_INTEL_CPU_CONTROL);

	for (i = 0; i < 100; i++) {
		inbox = ioread32(bar4 + T2SEP_INTEL_INBOX_STATUS);
		outbox = ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);
		if (inbox != inbox_before || outbox != outbox_before)
			break;
		msleep(10);
	}

	dev_info(&pdev->dev,
		 "Apple CPU-start probe after %d ms: inbox %#010x -> %#010x, outbox %#010x -> %#010x\n",
		 i * 10, inbox_before, inbox, outbox_before, outbox);
	dev_info(&pdev->dev,
		 "post-start controls: +0x8028=%#010x +0x8040=%#010x +0x8048=%#010x\n",
		 ioread32(bar4 + T2SEP_INTEL_CPU_CONTROL),
		 ioread32(bar4 + T2SEP_INTEL_CPU_RESET),
		 ioread32(bar4 + T2SEP_INTEL_CPU_START));

	if (apple_send_control_nop) {
		u32 response[4];
		u32 nop[4] = { 0x00000100, 0, 0, 0 };

		outbox = ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);
		if (outbox & T2SEP_INTEL_OUTBOX_FULL) {
			dev_warn(&pdev->dev,
				 "control NOP skipped: outbound FIFO is full (%#010x)\n",
				 outbox);
		} else {
			/* Apple writes words 0..2 and commits with a zero word 3. */
			iowrite32(nop[0], bar4 + 0x820);
			iowrite32(nop[1], bar4 + 0x824);
			iowrite32(nop[2], bar4 + 0x828);
			iowrite32(0, bar4 + 0x82c);
			ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);

			for (i = 0; i < 500; i++) {
				inbox = ioread32(bar4 + T2SEP_INTEL_INBOX_STATUS);
				if (!(inbox & T2SEP_INTEL_INBOX_EMPTY))
					break;
				msleep(10);
			}

			if (inbox & T2SEP_INTEL_INBOX_EMPTY) {
				dev_warn(&pdev->dev,
					 "control NOP timed out after 5000 ms; inbox=%#010x\n",
					 inbox);
			} else {
				response[0] = ioread32(bar4 + 0x810);
				response[1] = ioread32(bar4 + 0x814);
				response[2] = ioread32(bar4 + 0x818);
				response[3] = ioread32(bar4 + 0x81c);
				dev_info(&pdev->dev,
					 "control NOP response after %d ms: %08x %08x %08x %08x\n",
					 i * 10, response[0], response[1],
					 response[2], response[3]);
				if (response[3] & (T2SEP_INTEL_MSG_ERROR |
						   T2SEP_INTEL_MSG_FATAL)) {
					dev_err(&pdev->dev,
						"control NOP transport error flags: %08x\n",
						response[3]);
				} else if (response[0] != 0x00010100 ||
					   response[1] != 0 || response[2] != 0) {
					dev_err(&pdev->dev,
						"control NOP response failed strict validation\n");
				} else {
					dev_info(&pdev->dev,
						"control NOP response passed strict validation\n");
					nop_valid = true;
				}
			}
		}
	}
	if (apple_collect_discovery) {
		if (nop_valid)
			ret = t2sep_collect_discovery(pdev, bar4);
		else {
			dev_err(&pdev->dev,
				"discovery skipped because NOP did not validate\n");
			ret = -EPROTO;
		}
	}
	if (credential_ool && !nop_valid) {
		dev_err(&pdev->dev,
			"credential OOL capture skipped because NOP did not validate\n");
		ret = -EPROTO;
	}

	if (credential_ool) {
		in_size = T2SEP_CREDENTIAL_OOL_SIZE;
		out_size = T2SEP_CREDENTIAL_OOL_SIZE;
		ool_target = (apple_probe_aks_capabilities ||
			      apple_probe_aks_startup_environment ||
			      apple_capture_dual_credential_ool_acks) ? T2SEP_AKS_ENDPOINT :
			     apple_probe_acm_context_lifecycle ? T2SEP_ACM_ENDPOINT :
			     credential_endpoint;
	}

	if ((apple_capture_ool_acks || credential_ool) && !ret) {
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (ret)
			goto out_stop;
		in_buffer = dma_alloc_coherent(&pdev->dev, in_size,
					       &in_dma, GFP_KERNEL);
		out_buffer = dma_alloc_coherent(&pdev->dev, out_size,
					       &out_dma, GFP_KERNEL);
		if (apple_capture_dual_credential_ool_acks) {
			second_in_buffer = dma_alloc_coherent(
				&pdev->dev, in_size, &second_in_dma, GFP_KERNEL);
			second_out_buffer = dma_alloc_coherent(
				&pdev->dev, out_size, &second_out_dma, GFP_KERNEL);
		}
		if (!in_buffer || !out_buffer ||
		    (apple_capture_dual_credential_ool_acks &&
		     (!second_in_buffer || !second_out_buffer))) {
			ret = -ENOMEM;
			goto out_stop;
		}
		memset(in_buffer, 0, in_size);
		memset(out_buffer, 0, out_size);
		if (second_in_buffer)
			memset(second_in_buffer, 0, in_size);
		if (second_out_buffer)
			memset(second_out_buffer, 0, out_size);
		if (!IS_ALIGNED(in_dma, PAGE_SIZE) || !IS_ALIGNED(out_dma, PAGE_SIZE) ||
		    (apple_capture_dual_credential_ool_acks &&
		     (!IS_ALIGNED(second_in_dma, PAGE_SIZE) ||
		      !IS_ALIGNED(second_out_dma, PAGE_SIZE)))) {
			dev_err(&pdev->dev, "OOL DMA addresses are not page aligned\n");
			ret = -ERANGE;
			goto out_stop;
		}
		dev_info(&pdev->dev,
			 "pinned OOL buffers: target=%u in_dma=%pad in_size=%zu out_dma=%pad out_size=%zu\n",
			 ool_target, &in_dma, in_size, &out_dma, out_size);
		if (apple_capture_dual_credential_ool_acks) {
			dev_info(&pdev->dev,
				 "pinned OOL buffers: target=%u in_dma=%pad in_size=%zu out_dma=%pad out_size=%zu\n",
				 T2SEP_ACM_ENDPOINT, &second_in_dma, in_size,
				 &second_out_dma, out_size);
			ret = t2sep_capture_one_ool_ack(
				pdev, bar4, T2SEP_AKS_ENDPOINT, 2, 2,
				in_dma, in_size, 1, T2SEP_AKS_ENDPOINT);
			if (!ret)
				ret = t2sep_capture_one_ool_ack(
					pdev, bar4, T2SEP_AKS_ENDPOINT, 3, 3,
					out_dma, out_size, 1, T2SEP_AKS_ENDPOINT);
			if (!ret)
				ret = t2sep_capture_one_ool_ack(
					pdev, bar4, T2SEP_ACM_ENDPOINT, 2, 4,
					second_in_dma, in_size, 1, T2SEP_ACM_ENDPOINT);
			if (!ret)
				ret = t2sep_capture_one_ool_ack(
					pdev, bar4, T2SEP_ACM_ENDPOINT, 3, 5,
					second_out_dma, out_size, 1, T2SEP_ACM_ENDPOINT);
		} else {
			ret = t2sep_capture_one_ool_ack(
				pdev, bar4, ool_target, 2, 2, in_dma, in_size,
				apple_probe_aks_capabilities ||
				apple_probe_aks_startup_environment ||
				apple_probe_acm_context_lifecycle ? 1 : -1, ool_target);
			if (!ret)
				ret = t2sep_capture_one_ool_ack(
					pdev, bar4, ool_target, 3, 3, out_dma, out_size,
					apple_probe_aks_capabilities ||
					apple_probe_aks_startup_environment ||
					apple_probe_acm_context_lifecycle ? 1 : -1,
					ool_target);
		}
		if (!ret && apple_probe_aks_capabilities)
			ret = t2sep_probe_aks_capabilities(pdev, bar4,
						   in_buffer, out_buffer, NULL);
		if (!ret && apple_probe_aks_startup_environment)
			ret = t2sep_probe_aks_startup_environment(
				pdev, bar4, in_buffer, out_buffer);
		if (!ret && apple_probe_acm_context_lifecycle)
			ret = t2sep_probe_acm_context_lifecycle(
				pdev, bar4, in_buffer, out_buffer);
	}

out_stop:
	/* Exact CPU-stop write from AppleSEPIntelIOP::_stopCPUGated(). */
	iowrite32(5, bar4 + T2SEP_INTEL_CPU_STOP);
	ioread32(bar4 + T2SEP_INTEL_CPU_STOP);
	dev_info(&pdev->dev,
		 "issued Apple CPU-stop value 5 at +0x8024; payload FIFOs %s\n",
		 apple_send_control_nop ? "accessed only by explicit bounded gates" :
					  "untouched");
	if (in_buffer) {
		memzero_explicit(in_buffer, in_size);
		dma_free_coherent(&pdev->dev, in_size,
				  in_buffer, in_dma);
	}
	if (out_buffer) {
		memzero_explicit(out_buffer, out_size);
		dma_free_coherent(&pdev->dev, out_size,
				  out_buffer, out_dma);
	}
	if (second_in_buffer) {
		memzero_explicit(second_in_buffer, in_size);
		dma_free_coherent(&pdev->dev, in_size,
				  second_in_buffer, second_in_dma);
	}
	if (second_out_buffer) {
		memzero_explicit(second_out_buffer, out_size);
		dma_free_coherent(&pdev->dev, out_size,
				  second_out_buffer, second_out_dma);
	}
	if (apple_capture_ool_acks || credential_ool)
		dev_info(&pdev->dev,
			 "OOL buffers scrubbed and released after CPU stop; result=%d\n",
			 ret);
	return ret;
}

static void t2sep_scan_aperture(struct pci_dev *pdev, int bar)
{
	void __iomem *mapping;
	u32 send_status;
	u32 recv_status;

	if (pci_resource_len(pdev, bar) <= T2SEP_RECV_STATUS + sizeof(u32)) {
		dev_info(&pdev->dev, "BAR%d too small for status candidate\n", bar);
		return;
	}

	mapping = pci_iomap(pdev, bar, 0);
	if (!mapping) {
		dev_warn(&pdev->dev, "could not map BAR%d for status candidate\n", bar);
		return;
	}

	send_status = ioread32(mapping + T2SEP_SEND_STATUS);
	recv_status = ioread32(mapping + T2SEP_RECV_STATUS);
	pci_iounmap(pdev, mapping);

	dev_info(&pdev->dev,
		 "aperture candidate BAR%d base=0x4000: send=%#010x receive=%#010x\n",
		 bar, send_status, recv_status);
}

static bool t2sep_supported_model(void)
{
	return dmi_match(DMI_PRODUCT_NAME, "MacBookPro16,1");
}

static int t2sep_probe(struct pci_dev *pdev,
			const struct pci_device_id *id)
{
	u16 command;
	u16 original_command;
	u16 status;
	bool enabled = false;
	bool msi_ready = false;
	struct t2sep_irq_probe irq_probe;
	int bar;
	int ret;

	if (!t2sep_supported_model() && !allow_unsupported_model) {
		dev_err(&pdev->dev,
			"refusing unsupported model %s (read-only override exists)\n",
			dmi_get_system_info(DMI_PRODUCT_NAME) ?: "unknown");
		return -ENODEV;
	}
	if (apple_collect_discovery &&
	    (!apple_start_cpu_probe || !apple_start_with_msi ||
	     !apple_send_control_nop)) {
		dev_err(&pdev->dev,
			"discovery requires CPU start, two MSI vectors, and validated control NOP\n");
		return -EINVAL;
	}
	if (apple_capture_ool_acks &&
	    (!apple_collect_discovery ||
	     ool_ack_confirmation != T2SEP_OOL_CONFIRMATION)) {
		dev_err(&pdev->dev,
			"OOL capture requires validated discovery and explicit confirmation 0x%lx\n",
			T2SEP_OOL_CONFIRMATION);
		return -EINVAL;
	}
	if (apple_capture_credential_ool_acks &&
	    (!apple_start_cpu_probe || !apple_start_with_msi ||
	     !apple_send_control_nop ||
	     credential_ool_confirmation != T2SEP_CREDENTIAL_OOL_CONFIRMATION ||
	     (credential_endpoint != T2SEP_AKS_ENDPOINT &&
	      credential_endpoint != T2SEP_ACM_ENDPOINT))) {
		dev_err(&pdev->dev,
			"credential OOL capture requires start/MSI/NOP, endpoint 7 or 10, and confirmation 0x%lx\n",
			T2SEP_CREDENTIAL_OOL_CONFIRMATION);
		return -EINVAL;
	}
	if (apple_capture_dual_credential_ool_acks &&
	    (!apple_start_cpu_probe || !apple_start_with_msi ||
	     !apple_send_control_nop ||
	     dual_credential_ool_confirmation !=
		T2SEP_DUAL_CREDENTIAL_OOL_CONFIRMATION)) {
		dev_err(&pdev->dev,
			"dual credential OOL capture requires start/MSI/NOP and confirmation 0x%lx\n",
			T2SEP_DUAL_CREDENTIAL_OOL_CONFIRMATION);
		return -EINVAL;
	}
	if (apple_probe_aks_capabilities &&
	    (!apple_start_cpu_probe || !apple_start_with_msi ||
	     !apple_send_control_nop ||
	     aks_capabilities_confirmation != T2SEP_AKS_CAPABILITIES_CONFIRMATION)) {
		dev_err(&pdev->dev,
			"AKS capabilities probe requires start/MSI/NOP and confirmation 0x%lx\n",
			T2SEP_AKS_CAPABILITIES_CONFIRMATION);
		return -EINVAL;
	}
	if (apple_probe_aks_startup_environment &&
	    (!apple_start_cpu_probe || !apple_start_with_msi ||
	     !apple_send_control_nop ||
	     aks_startup_environment_confirmation !=
		T2SEP_AKS_STARTUP_ENV_CONFIRMATION)) {
		dev_err(&pdev->dev,
			"AKS startup-environment probe requires start/MSI/NOP and confirmation 0x%lx\n",
			T2SEP_AKS_STARTUP_ENV_CONFIRMATION);
		return -EINVAL;
	}
	if (apple_probe_acm_context_lifecycle &&
	    (!apple_start_cpu_probe || !apple_start_with_msi ||
	     !apple_send_control_nop ||
	     acm_context_confirmation != T2SEP_ACM_CONTEXT_CONFIRMATION)) {
		dev_err(&pdev->dev,
			"ACM context lifecycle probe requires start/MSI/NOP and confirmation 0x%lx\n",
			T2SEP_ACM_CONTEXT_CONFIRMATION);
		return -EINVAL;
	}
	if (apple_capture_ool_acks + apple_capture_credential_ool_acks +
	    apple_capture_dual_credential_ool_acks +
	    apple_probe_aks_capabilities + apple_probe_aks_startup_environment +
	    apple_probe_acm_context_lifecycle > 1) {
		dev_err(&pdev->dev,
			"SBIO, single/dual credential OOL, AKS capabilities/startup, and ACM context modes are mutually exclusive\n");
		return -EINVAL;
	}

	ret = pci_read_config_word(pdev, PCI_COMMAND, &command);
	if (ret) {
		ret = pcibios_err_to_errno(ret);
		goto out_disable;
	}
	original_command = command;

	ret = pci_read_config_word(pdev, PCI_STATUS, &status);
	if (ret) {
		ret = pcibios_err_to_errno(ret);
		goto out_disable;
	}

	if (temporarily_enable_device || apple_start_with_msi) {
		ret = pci_enable_device_mem(pdev);
		if (ret) {
			dev_err(&pdev->dev,
				"temporary pci_enable_device_mem failed: %d\n", ret);
			return ret;
		}
		enabled = true;
		dev_info(&pdev->dev,
			 "temporarily enabled PCI memory decoding for this probe\n");
	}

	if (apple_start_with_msi) {
		ret = t2sep_setup_msi(pdev, &irq_probe);
		if (ret) {
			dev_err(&pdev->dev, "could not allocate two MSI vectors: %d\n",
				ret);
			goto out_disable;
		}
		msi_ready = true;
	}

	dev_info(&pdev->dev,
		 "read-only probe: vendor=%04x device=%04x revision=%02x irq=%u command=%04x status=%04x\n",
		 pdev->vendor, pdev->device, pdev->revision, pdev->irq,
		 command, status);

	for (bar = 0; bar < PCI_STD_NUM_BARS; bar++) {
		resource_size_t start = pci_resource_start(pdev, bar);
		resource_size_t length = pci_resource_len(pdev, bar);
		unsigned long flags = pci_resource_flags(pdev, bar);

		if (!length)
			continue;

		dev_info(&pdev->dev,
			 "BAR%d start=%pa length=%pa flags=%#lx (not mapped)\n",
			 bar, &start, &length, flags);
	}

	dev_info(&pdev->dev,
		 "enumeration complete; no PCI config or MMIO writes performed\n");

	if (scan_apertures) {
		t2sep_scan_aperture(pdev, 0);
		t2sep_scan_aperture(pdev, 2);
		t2sep_scan_aperture(pdev, 4);
	}

	if (read_mailbox_status) {
		void __iomem *bar4;
		u32 send_status;
		u32 recv_status;
		u32 alt_send_status;
		u32 alt_recv_status;

		if (pci_resource_len(pdev, T2SEP_MAILBOX_BAR) <=
		    (read_one_message ? T2SEP_RECV1 : T2SEP_RECV_STATUS) +
		    sizeof(u32)) {
			dev_err(&pdev->dev, "BAR4 is too small for mailbox status probe\n");
			ret = -EINVAL;
			goto out_disable;
		}

		bar4 = pci_iomap(pdev, T2SEP_MAILBOX_BAR, 0);
		if (!bar4) {
			ret = -ENOMEM;
			goto out_disable;
		}

		send_status = ioread32(bar4 + T2SEP_SEND_STATUS);
		recv_status = ioread32(bar4 + T2SEP_RECV_STATUS);
		alt_send_status = ioread32(bar4 + T2SEP_ALT_MAILBOX_BASE + 0x08);
		alt_recv_status = ioread32(bar4 + T2SEP_ALT_MAILBOX_BASE + 0x20);

		dev_info(&pdev->dev,
			 "T8012 mailbox status base=0x4000: send=%#010x receive=%#010x\n",
			 send_status, recv_status);
		dev_info(&pdev->dev,
			 "T8012 mailbox status base=0x0000: send=%#010x receive=%#010x\n",
			 alt_send_status, alt_recv_status);
		if (!read_one_message)
			dev_info(&pdev->dev,
				 "mailbox payload and control registers were not accessed\n");

		if (read_one_message) {
			u32 recv0;
			u32 recv1;
			u64 message;

			if (recv_status & T2SEP_RECV_EMPTY) {
				dev_info(&pdev->dev,
					 "receive mailbox reports empty; no payload read\n");
			} else {
				u32 recv_status_after;

				/* PongoOS reads recv0 before recv1 on T8012. */
				recv0 = ioread32(bar4 + T2SEP_RECV0);
				recv1 = ioread32(bar4 + T2SEP_RECV1);
				recv_status_after = ioread32(bar4 + T2SEP_RECV_STATUS);
				message = ((u64)recv1 << 32) | recv0;
				dev_info(&pdev->dev,
					 "consumed one inbound message=%#018llx ep=%#04x tag=%#04x opcode=%#04x param=%#04x data=%#010x\n",
					 message, recv0 & 0xff, (recv0 >> 8) & 0xff,
					 (recv0 >> 16) & 0xff, (recv0 >> 24) & 0xff,
					 recv1);
				dev_info(&pdev->dev,
					 "receive status after payload read=%#010x (before=%#010x)\n",
					 recv_status_after, recv_status);
			}
		}

		pci_iounmap(pdev, bar4);
	}

	if (read_apple_layout || apple_start_cpu_probe) {
		void __iomem *bar4;
		u32 inbox_status;
		u32 outbox_status;
		u32 cpu_control;
		u32 cpu_reset;
		u32 cpu_start;

		if (pci_resource_len(pdev, T2SEP_MAILBOX_BAR) <=
		    T2SEP_INTEL_CPU_START + sizeof(u32)) {
			dev_err(&pdev->dev,
				 "BAR4 is too small for AppleSEPIntelIOP register probe\n");
			ret = -EINVAL;
			goto out_disable;
		}

		bar4 = pci_iomap(pdev, T2SEP_MAILBOX_BAR, 0);
		if (!bar4) {
			ret = -ENOMEM;
			goto out_disable;
		}

		inbox_status = ioread32(bar4 + T2SEP_INTEL_INBOX_STATUS);
		outbox_status = ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);
		cpu_control = ioread32(bar4 + T2SEP_INTEL_CPU_CONTROL);
		cpu_reset = ioread32(bar4 + T2SEP_INTEL_CPU_RESET);
		cpu_start = ioread32(bar4 + T2SEP_INTEL_CPU_START);

		dev_info(&pdev->dev,
			 "Apple layout BAR4: inbox_status=%#010x (%s), outbox_status=%#010x (%s)\n",
			 inbox_status,
			 inbox_status & T2SEP_INTEL_INBOX_EMPTY ? "empty" : "not empty",
			 outbox_status,
			 outbox_status & T2SEP_INTEL_OUTBOX_FULL ? "full" : "not full");
		dev_info(&pdev->dev,
			 "Apple layout CPU registers (read-only): +0x8028=%#010x +0x8040=%#010x +0x8048=%#010x\n",
			 cpu_control, cpu_reset, cpu_start);
		dev_info(&pdev->dev,
			 "Apple layout payload FIFOs were not accessed%s\n",
			 apple_start_cpu_probe ? "" : "; no MMIO writes performed");

		if (apple_start_cpu_probe) {
			ret = t2sep_apple_start_cpu_probe(pdev, bar4);
			if (ret)
				dev_err(&pdev->dev,
					"bounded Apple transport probe failed: %d\n", ret);
		}

		pci_iounmap(pdev, bar4);
		if (ret)
			goto out_disable;
	}

	ret = 0;

out_disable:
	if (msi_ready)
		t2sep_teardown_msi(pdev, &irq_probe);
	if (enabled) {
		u16 command_after_disable;

		pci_disable_device(pdev);
		if (!pci_read_config_word(pdev, PCI_COMMAND, &command_after_disable) &&
		    command_after_disable != original_command) {
			pci_write_config_word(pdev, PCI_COMMAND, original_command);
			dev_info(&pdev->dev,
				 "restored PCI command word from %#06x to original %#06x\n",
				 command_after_disable, original_command);
		}
		dev_info(&pdev->dev,
			 "temporary PCI enable released before probe returned\n");
	}
	return ret;
}

static void t2sep_remove(struct pci_dev *pdev)
{
	dev_info(&pdev->dev, "read-only probe removed\n");
}

static const struct pci_device_id t2sep_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_APPLE_LOCAL, PCI_DEVICE_ID_APPLE_T2_SEP) },
	{ }
};
MODULE_DEVICE_TABLE(pci, t2sep_ids);

static struct pci_driver t2sep_driver = {
	.name = "t2sep_probe",
	.id_table = t2sep_ids,
	.probe = t2sep_probe,
	.remove = t2sep_remove,
};
module_pci_driver(t2sep_driver);

MODULE_AUTHOR("Shawn and Codex");
MODULE_DESCRIPTION("Read-only Apple T2 Secure Enclave PCI enumeration probe");
MODULE_LICENSE("GPL");
