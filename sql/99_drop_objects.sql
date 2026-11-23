-- 99: removes the helper functions and procedures. Keeps pci_cleanup.MaskAudit as the record of what was masked.
DROP PROCEDURE IF EXISTS pci_cleanup.Inventory, pci_cleanup.MaskApiLog, pci_cleanup.RetireCardsTable;
DROP FUNCTION IF EXISTS pci_cleanup.ContainsCardData, pci_cleanup.RedactCardData, pci_cleanup.RedactCvv,
                        pci_cleanup.CvvEnd, pci_cleanup.RedactPans, pci_cleanup.TextColumns;
