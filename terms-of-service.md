# Terms of Service

*Open-Source Software License & Terms of Use*

Last Updated: 5 July 2026

When we say “you” or “your,” we mean you as an individual, the legal entity you represent, and any person who uses the Software on your behalf. When we say “we,” “us,” “our,” or “Umanitek,” we mean UMANITEK AG, the entity that publishes and maintains the Software.

## 1. About the Software

Umanitek Agent Blackbox (the “Software”) is free, open-source security software published by UMANITEK AG. It runs inside an AI agent and checks the agent’s actions - prompts, shell commands, file access, package installs, and skills - against shared threat graphs on the OriginTrail Decentralized Knowledge Graph (“DKG”). By default it flags (“audit” mode); blocking is an opt-in configuration setting. When one agent learns of a threat, every protected agent can pick it up on its next sync. Unlike the hosted Umanitek Agent Blackbox service, the Software is self-hosted: you download, install, and run it yourself on your own machine or infrastructure. There is no account, and these Terms govern the open-source Software only, not any separate paid or hosted Umanitek service.

## 2. Acceptance of These Terms

By downloading, installing, running, copying, modifying, or distributing the Software, you agree to be bound by these Terms and by our Privacy Policy. If you do not agree, you must not use the Software. The Software is licensed, not sold; your rights to use, copy, modify, and redistribute it are granted under the MIT License described in Section 4, which these Terms supplement but do not restrict.

## 3. Eligibility

You must be at least 16 years old, or the age of digital consent in your jurisdiction, and have the legal capacity to enter into binding agreements. If you use the Software on behalf of an organization, you represent that you are authorized to bind that organization to these Terms. You represent and warrant that you comply with all applicable laws and regulations when using the Software. You further represent that you are not (a) a resident or national of, or located in, any country or region subject to comprehensive U.S., EU, or Swiss sanctions or embargoes, or (b) identified on any applicable denied-party, restricted-party, or sanctioned-party list, and that you will not use the Software for any end use prohibited by applicable export-control or sanctions laws, including in connection with nuclear, chemical, biological, or missile-related end uses.

## 4. Licence (MIT) and Attribution Requirement

The Software is made available under the MIT License. The full text is reproduced in Section 4.2 and in the LICENSE file distributed with the Software. In plain terms, you may use, copy, modify, merge, publish, distribute, sublicense, and sell copies of the Software, free of charge, provided that you comply with the attribution condition in Section 4.1.

### 4.1 Attribution when you copy, close-source, reuse, or redistribute

You must keep the copyright notice and the permission notice in all copies or substantial portions of the Software. This is a binding condition of the licence, not a courtesy. If you fork, redistribute, repackage, embed, or build a derivative work from the Software - whether your work is open-source, closed-source, or commercial - you must:

- Retain the original MIT copyright notice of the upstream author (Nous Research) and any UMANITEK AG copyright notice included in the Software.
- Include a copy of the MIT License text with your distribution.
- Credit the creator. Provide clear attribution to Umanitek as the maintainer of Umanitek Agent Blackbox - for example, a line in your README, “About,” or documentation such as: “Built on Umanitek Agent Blackbox by UMANITEK AG (umanitek.ai), a fork of Hermes-Agent by Nous Research, used under the MIT License.”
- Not remove or obscure existing attribution, licence headers, or notices in the source files.
You may add your own copyright notice covering your original contributions, but you may not represent that you are the original author of the Software, nor use Umanitek’s or Nous Research’s names, logos, or trademarks to imply endorsement of your derivative work without prior written permission (see Section 9).

### 4.2 MIT License text

MIT License Copyright (c) 2025 Nous Research Portions Copyright (c) 2025–2026 UMANITEK AG Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### 4.3 Fork lineage

The Software is a fork of NousResearch/hermes-agent (MIT). It is maintained by UMANITEK AG and distributed at github.com/umanitek/agent-blackbox. Nothing in these Terms diminishes the freedoms the MIT License grants you.

## 5. How the Software Works

The Software runs locally and is designed to “fail open”: if a check errors, it degrades to a no-op so as not to break your agent. You are responsible for configuring the Software - including audit/block mode, protected paths, detection categories, and reporting settings - to suit your own risk tolerance. Certain features send limited data off your machine, most notably reporting threats to the shared community graph, optional vulnerability lookups, and the optional AI reviewer. These data flows are described in our Privacy Policy, which forms part of these Terms, and by using those features you consent to them.

## 6. Acceptable Use

You agree to use the Software only for lawful purposes and in accordance with these Terms. You agree not to:

- Use the Software in any way that violates applicable laws or regulations, or infringes the rights of others;
- Submit false, misleading, malicious, or spam reports to the community threat graph, or otherwise attempt to poison, manipulate, or degrade the shared threat intelligence;
- Reverse the Software’s protective purpose - for example, to probe for ways to evade detection in order to attack others;
- Interfere with, overload, or disrupt the DKG network, its node operators, curators, or other users;
- Publish to any shared graph content that is unlawful, infringing, or that contains personal data you are not entitled to share.
- Use the Software to develop, test, stage, or deploy malware, exploits, ransomware, or other malicious code, or to facilitate an attack on any third-party system;
- Use the Software, or any output of the Software, in connection with any weapon or weapons system, or in any manner that would violate applicable export-control, sanctions, or arms-control laws;
- Attempt to gain unauthorized access to the DKG, to node infrastructure, to Umanitek's systems, or to any other user's systems or data; or
- Scrape, extract, or repurpose data from the community threat graph to build a competing shared threat-intelligence service in a manner inconsistent with the DKG's applicable terms of use.
The Software is not intended for use in circumstances where its failure could lead to death, personal injury, or severe physical or environmental damage. You use it in such contexts entirely at your own risk.

## 6A. Suspension and Removal from the Community Graph

Umanitek curates the public threat graph and may, in its sole discretion and without liability to you, rate-limit, throttle, flag, quarantine, or delist any pseudonymous submitter identifier, node, or report that it reasonably believes violates Section 6, is inaccurate, malicious, spam, or otherwise degrades the shared threat intelligence. Because the DKG is a decentralized, tamper-resistant ledger, delisting from Umanitek's curated view does not guarantee removal, alteration, or deletion of any report from the underlying DKG, which remains outside Umanitek's control. Umanitek may also decline to sync, mirror, or curate data from any node or address at its discretion.

## 7. Disclaimers - Security Software “As Is”

THE SOFTWARE IS PROVIDED “AS IS” AND “AS AVAILABLE” WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED. TO THE FULLEST EXTENT PERMITTED BY LAW, UMANITEK AG DISCLAIMS ALL WARRANTIES, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. Security software is not a guarantee of security. We do not warrant that the Software will detect or block all threats, that the threat graphs are complete or accurate, that the Software is free of errors or vulnerabilities, or that it will operate uninterrupted. Threat detection is probabilistic and may produce false positives (flagging safe actions) and false negatives (missing real threats). You remain solely responsible for the security of your systems, data, and AI agents; the Software is one layer of defence among many and is not a substitute for sound security practices, human review, backups, and independent safeguards. Umanitek is not liable for any inaccuracies in automated outputs or for any actions taken by you or third parties in reliance on them. Third-party dependencies. The Software relies on third-party open-source components and can interact with third-party services beyond our control, including the OriginTrail DKG, public vulnerability databases (such as OSV), and, if you enable the optional AI reviewer, third-party model providers (such as OpenAI or Anthropic). Data stored on or read from the decentralized DKG is maintained by independent node operators beyond Umanitek’s exclusive control. We do not warrant the continued availability, integrity, or security of such networks and are not liable for any loss, corruption, or unauthorized access attributable to decentralized infrastructure or to any third-party service. Not legal or security advice. The Software is a technology tool. Its findings, scores, and logs are for informational purposes only and do not constitute legal, compliance, or professional security advice. You are solely responsible for decisions you make based on Service outputs.

## 8. Limitation of Liability

To the maximum extent permitted by applicable law, in no event shall UMANITEK AG, Nous Research, or their respective contributors, officers, directors, employees, agents, or affiliates be liable for any indirect, incidental, special, consequential, exemplary, or punitive damages, or for any loss of profits, data, goodwill, or business interruption, arising out of or in connection with the Software or these Terms, whether in contract, tort (including negligence), strict liability, or otherwise, even if advised of the possibility of such damages. To the extent any liability cannot be excluded, the total aggregate liability of UMANITEK AG to you for all claims relating to the Software shall not exceed CHF 100 (one hundred Swiss francs) or the amount you paid for the Software (which, for free open-source use, is zero), whichever is greater. Nothing in these Terms excludes or limits liability that cannot be excluded or limited under applicable law, including liability for death or personal injury caused by negligence, for fraud, or for gross negligence or willful misconduct. Any claim or cause of action you may have arising out of or relating to the Software, these Terms, or the Privacy Policy must be filed within one (1) year after the claim or cause of action arose, or it shall be permanently barred, to the extent such limitation is permitted by applicable law.

## 8A. Indemnification

To the fullest extent permitted by applicable law, you agree to defend, indemnify, and hold harmless UMANITEK AG, Nous Research, and their respective contributors, officers, directors, employees, agents, and affiliates from and against any and all claims, damages, obligations, losses, liabilities, costs, and expenses (including reasonable attorneys' fees) arising out of or relating to: (a) your use or misuse of the Software; (b) your violation of these Terms or any applicable law; (c) any report, content, or data you submit to the community threat graph or any other shared graph; (d) any derivative work, fork, or redistribution of the Software that you create, publish, or distribute; or (e) your violation of any third party's rights, including intellectual property or privacy rights. Umanitek reserves the right, at your expense, to assume the exclusive defense and control of any matter otherwise subject to indemnification by you, in which case you agree to cooperate with Umanitek's defense of such claim.

## 8B. Term, Termination, and Survival

These Terms remain in effect for as long as you use the Software. Umanitek may modify, suspend, or discontinue the Software, the community threat graph, or any related infrastructure or services, in whole or in part, at any time and without liability, subject to your rights under the MIT License with respect to code you have already obtained. Sections 4 (Licence and Attribution), 6 (Acceptable Use), 6A (Suspension and Removal from the Community Graph), 7 (Disclaimers), 8 (Limitation of Liability), 8A (Indemnification), 9 (Trademarks), 10 (Contributions and Feedback), 12 (Governing Law and Jurisdiction), and this Section 8B, together with any other provision that by its nature should survive, will survive any termination or discontinuation of the Software.

## 8C. No Third-Party Beneficiaries

Except for Nous Research and Umanitek's contributors, officers, directors, employees, agents, and affiliates, who are express third-party beneficiaries of Sections 7, 8, and 8A for purposes of enforcing the disclaimers, limitations of liability, and indemnification obligations in their favor, these Terms do not confer any rights or remedies on any person or entity other than you and Umanitek.

## 8D. Assignment

You may not assign or transfer these Terms, by operation of law or otherwise, without Umanitek's prior written consent. Umanitek may freely assign or transfer these Terms, in whole or in part, without restriction, including in connection with a merger, acquisition, corporate reorganization, or sale of assets. Any attempted assignment in violation of this Section is void.

## 8E. Force Majeure

Umanitek will not be liable for any failure or delay in performance resulting from causes beyond its reasonable control, including acts of God, natural disaster, war, terrorism, riots, embargoes, acts of civil or military authority, fire, flood, accidents, network or infrastructure failures, strikes, or shortages of transportation, facilities, fuel, energy, labor, or materials, including any outage, fork, or unavailability of the DKG or other third-party infrastructure beyond Umanitek's control.

## 9. Trademarks

The MIT License grants rights in the Software’s code; it does not grant any right to use the names, logos, or trademarks of “UMANITEK,” “Umanitek Agent Blackbox,” “Agent Blackbox,” “Hermes,” or “Nous Research.” You may make accurate, factual reference to the Software (for example, “built on Umanitek Agent Blackbox”) as required for attribution under Section 4, but you must not use these marks in a way that suggests sponsorship or endorsement of your product without our prior written consent. All other trademarks are the property of their respective owners. You must not register, use, or apply for any domain name, social-media handle, or app-store listing that incorporates “Umanitek,” “Agent Blackbox,” “Agent Blackbox,” “Hermes,” or any confusingly similar term in a manner that suggests affiliation with or endorsement by Umanitek.

## 10. Contributions and Feedback

If you contribute code, threat reports, or other materials to the project, you represent that you have the right to do so and that your contribution may be distributed under the MIT License. Unless a separate contributor agreement states otherwise, contributions are licensed to the project and its users under the same MIT License terms. If you provide feedback, suggestions, or ideas about the Software, you grant us the right to use them without restriction or compensation. You grant Umanitek a perpetual, irrevocable, worldwide, royalty-free, fully paid-up, sublicensable, and transferable license to use, reproduce, modify, distribute, and otherwise exploit any feedback, suggestions, or ideas you provide about the Software for any purpose, without attribution, compensation, or restriction.

## 11. Changes to the Software and These Terms

The Software is under active development; features may be added, modified, or removed at any time. We may update these Terms, and material changes will be reflected in the project repository; the “Last Updated” date above indicates the current version. Your continued use of the Software after changes take effect constitutes acceptance. Because the Software is open source, prior versions remain available under the licence under which they were released.

## 12. Governing Law and Jurisdiction

Governing law. These Terms are governed by and construed in accordance with the substantive laws of Switzerland, excluding its conflict-of-laws rules and the United Nations Convention on Contracts for the International Sale of Goods (CISG). Jurisdiction. Subject to any mandatory consumer-protection rules that grant you the right to bring proceedings in your place of residence, the ordinary courts at the registered seat of UMANITEK AG in Zug, Switzerland shall have exclusive jurisdiction over disputes arising out of or relating to these Terms and the Software. Users in the EU / EEA. If you are a consumer resident in the EU or EEA, you retain the protection of mandatory provisions of the law of your country of residence, and nothing in these Terms deprives you of those protections. Our handling of personal data is described in the Privacy Policy and is intended to comply with the EU General Data Protection Regulation (GDPR) and the Swiss Federal Act on Data Protection (FADP) where applicable. Users in the United States. If you use the Software in the United States, these Terms are intended to be enforceable to the maximum extent permitted under applicable U.S. federal and state law. The disclaimers and liability limitations in Sections 7 and 8 apply to the fullest extent permitted; some U.S. states do not allow certain exclusions, in which case those exclusions apply only to the extent permitted in your state. Use of the Software is also subject to the export-control and sanctions provisions in Section 13. Notwithstanding the foregoing, Umanitek may seek injunctive or other equitable relief in any court of competent jurisdiction to prevent actual or threatened infringement of its intellectual property or violation of Section 6 (Acceptable Use), pending resolution of the dispute in the courts identified above.

## 13. Export Controls and Sanctions

You agree to comply with all applicable export-control and economic-sanctions laws, including those of Switzerland, the European Union, and the United States. You represent that you are not located in, and will not use or export the Software to, any jurisdiction or party subject to comprehensive sanctions or embargoes that would make such use unlawful. You further represent that the Software will not be used, directly or indirectly, in the design, development, production, stockpiling, or use of nuclear, chemical, or biological weapons, missiles, or drones capable of delivering such weapons, or for any other military end use restricted under applicable export-control law.

## 14. Severability, Waiver, and Entire Agreement

If any provision of these Terms is held invalid or unenforceable, the remaining provisions remain in full force, and the invalid provision will be interpreted to best accomplish its intended purpose to the extent permitted by law. Our failure to enforce any right or provision is not a waiver of that right. These Terms, together with the MIT License and the Privacy Policy, constitute the entire agreement between you and UMANITEK AG regarding the open-source Software and supersede any prior agreements on that subject.

## 15. Contact

UMANITEK AG Untermüli 7, 6300 Zug, Switzerland Company Registration Number: CHE-171.163.797 Contact: support@umanitek.ai · umanitek.ai
