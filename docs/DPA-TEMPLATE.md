# Data processing agreement template

> This is a template, not legal advice. Complete every bracketed field and have
> counsel review it before use. A self-hosted operator normally acts as the
> controller; a managed-service provider acts as the processor.

## 1. Parties

- Controller: [legal name, address, contact]
- Processor: [legal name, address, contact]
- Effective date: [date]
- Term: [term]

## 2. Subject matter and duration

The processor provides [hosting / managed ZeroTrace / backup / support] for the
duration of the agreement and any documented wind-down period. Processing ends
when the service ends and the return/deletion obligations in section 11 are
complete.

## 3. Nature and purpose

Processing is limited to operating, securing, supporting, and backing up the
ZeroTrace instance for the controller. The processor must not use the data for
its own purposes, advertising, model training, or unrelated analytics.

## 4. Categories of data and data subjects

- Account and authentication data for [operators/administrators].
- Scope, scan, finding, and Guard records for authorized targets.
- Logs, metrics, and backup metadata.
- Data subjects: controller personnel and any individuals referenced in
  authorized assessment data.

Special-category data is not expected. The controller must not instruct the
processor to process it without a documented legal basis and additional
safeguards.

## 5. Controller instructions

The processor processes personal data only on documented instructions from the
controller, including transfers to a third country, unless required by law. If
law requires processing, the processor must notify the controller unless
prohibited by law.

## 6. Confidentiality

The processor ensures that personnel authorized to process the data are bound
by confidentiality, receive role-appropriate training, and have access only on a
need-to-know basis.

## 7. Security measures

At minimum:

- encryption in transit and at rest where supported;
- unique credentials, MFA for administrative access, and least privilege;
- patching, vulnerability management, and secure configuration;
- network isolation of the engine, Guard, database, and management interfaces;
- audit logging, monitoring, and tested backup/restore;
- incident response and breach notification procedures;
- secure deletion and media disposal.

The ZeroTrace deployment guidance requires the engine and Guard to remain
loopback-only and the model-provider key to remain outside the BFF and browser.

## 8. Subprocessors

The controller authorizes the following subprocessors:

| Subprocessor | Service | Region | Transfer mechanism |
|---|---|---|---|
| [name] | [hosting] | [region] | [SCCs/adequacy] |
| [name] | [identity provider] | [region] | [SCCs/adequacy] |
| [name] | [model provider] | [region] | [SCCs/adequacy] |
| [name] | [backup target] | [region] | [SCCs/adequacy] |

The processor must give notice of a new subprocessor and a reasonable
opportunity to object. A subprocessor must be bound by terms no less protective
than this agreement.

## 9. Data-subject rights

The processor assists the controller with access, correction, deletion,
restriction, portability, and objection requests, taking into account the nature
of processing. ZeroTrace administrators can export and erase account data
through the authenticated admin API; operational scan and Guard records require
a controller decision.

## 10. Breach notification

The processor notifies the controller without undue delay, and no later than
[24/48/72] hours after confirming a personal-data breach. The notice includes
the nature of the breach, affected categories and approximate volume, likely
consequences, containment measures, and a contact. The processor must not notify
regulators or data subjects on the controller's behalf without instruction,
unless law requires it.

## 11. Audits, return, and deletion

The processor makes available information necessary to demonstrate compliance
and allows audits on reasonable notice, subject to confidentiality and safety.
On termination, the processor returns or deletes personal data as instructed,
including backups within [30] days, and certifies deletion in writing. The
controller may retain data required by law.

## 12. International transfers

Transfers outside the controller's jurisdiction require a valid mechanism such
as an adequacy decision or standard contractual clauses, plus a transfer-impact
assessment where required.

## 13. Liability and governing law

Liability, indemnity, and governing law: [complete with counsel]. Nothing in
this agreement limits data-subject rights under applicable law.

## 14. Signatures

Controller: ______________________  Date: __________

Processor: ______________________  Date: __________
