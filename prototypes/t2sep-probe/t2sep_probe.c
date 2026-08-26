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
	u16 status;
	int bar;
	int ret;

	if (!t2sep_supported_model() && !allow_unsupported_model) {
		dev_err(&pdev->dev,
			"refusing unsupported model %s (read-only override exists)\n",
			dmi_get_system_info(DMI_PRODUCT_NAME) ?: "unknown");
		return -ENODEV;
	}

	ret = pci_read_config_word(pdev, PCI_COMMAND, &command);
	if (ret)
		return pcibios_err_to_errno(ret);

	ret = pci_read_config_word(pdev, PCI_STATUS, &status);
	if (ret)
		return pcibios_err_to_errno(ret);

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
			return -EINVAL;
		}

		bar4 = pci_iomap(pdev, T2SEP_MAILBOX_BAR, 0);
		if (!bar4)
			return -ENOMEM;

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

	return 0;
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
