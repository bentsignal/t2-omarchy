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
#include <linux/interrupt.h>
#include <linux/slab.h>

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

struct t2sep_irq_probe {
	atomic_t count[2];
};

#define T2SEP_DISCOVERY_ENDPOINT 0xfd
#define T2SEP_DISCOVERY_MAX_RECORDS 64

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
	bool saw_message = false;
	int ret = 0;

	entries = kcalloc(256, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	for (elapsed_ms = 0; elapsed_ms < 1000; elapsed_ms += 10) {
		u32 words[4];
		u8 endpoint;
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
		opcode = (words[0] >> 16) & 0xff;
		endpoint_id = (words[0] >> 24) & 0xff;
		dev_info(&pdev->dev,
			 "discovery candidate %u: %08x %08x %08x %08x\n",
			 records, words[0], words[1], words[2], words[3]);

		if (endpoint != T2SEP_DISCOVERY_ENDPOINT || words[2] != 0) {
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

		if (opcode == 0) {
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
			entries[endpoint_id].identity = true;
			entries[endpoint_id].name = words[1];
			identities++;
			dev_info(&pdev->dev,
				 "discovery identity: id=%#02x name=%08x\n",
				 endpoint_id, words[1]);
		} else if (opcode == 1) {
			if (!entries[endpoint_id].identity ||
			    entries[endpoint_id].limits) {
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

	dev_info(&pdev->dev,
		 "bounded discovery complete: records=%u identities=%u sbio=%s limits=%s result=%d\n",
		 records, identities, entries[0x08].identity ? "yes" : "no",
		 entries[0x08].limits ? "yes" : "no", ret);
	kfree(entries);
	return ret;
}

static void t2sep_apple_start_cpu_probe(struct pci_dev *pdev, void __iomem *bar4)
{
	u32 inbox_before = ioread32(bar4 + T2SEP_INTEL_INBOX_STATUS);
	u32 outbox_before = ioread32(bar4 + T2SEP_INTEL_OUTBOX_STATUS);
	u32 inbox = inbox_before;
	u32 outbox = outbox_before;
	bool nop_valid = false;
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
			t2sep_collect_discovery(pdev, bar4);
		else
			dev_err(&pdev->dev,
				"discovery skipped because NOP did not validate\n");
	}

	/* Exact CPU-stop write from AppleSEPIntelIOP::_stopCPUGated(). */
	iowrite32(5, bar4 + T2SEP_INTEL_CPU_STOP);
	ioread32(bar4 + T2SEP_INTEL_CPU_STOP);
	dev_info(&pdev->dev,
		 "issued Apple CPU-stop value 5 at +0x8024; payload FIFOs %s\n",
		 apple_send_control_nop ? "accessed only by explicit bounded gates" :
					  "untouched");
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

		if (apple_start_cpu_probe)
			t2sep_apple_start_cpu_probe(pdev, bar4);

		pci_iounmap(pdev, bar4);
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
