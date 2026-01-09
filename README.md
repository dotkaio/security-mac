# macOS Security & Privacy Guide

> A comprehensive guide to hardening macOS for security-conscious users.

[![macOS](https://img.shields.io/badge/macOS-Sequoia%2015-blue)](https://www.apple.com/macos/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Overview

This guide provides actionable techniques for improving security and privacy on [Apple silicon](https://support.apple.com/116943) Macs running a [currently supported](https://support.apple.com/HT201222) version of macOS.

> ⚠️ **Intel Macs are not recommended.** They contain [unpatchable hardware vulnerabilities](https://github.com/axi0mX/ipwndfu) (checkm8) that Apple cannot fix. Apple silicon Macs are the minimum requirement—newer chips always offer stronger security.

### Who is this for?

- **Power users** seeking enterprise-grade security
- **Privacy-conscious individuals** looking to reduce their digital footprint
- **Developers and IT professionals** hardening their daily drivers

For organizational deployments, refer to the [NIST macOS Security Guidelines](https://github.com/usnistgov/macos_security).

### Important Disclaimers

- Security is an ongoing process—no single configuration guarantees protection
- This guide is provided **as-is** without warranties
- **You are responsible** for any changes you make to your system

💡 **Contributions welcome!** [Open an issue](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues) or submit a pull request.

---

## Table of Contents

- [Security Fundamentals](#security-fundamentals)
- [Threat Modeling](#threat-modeling)
- [Hardware](#hardware)
- [Installing macOS](#installing-macos)
- [Initial Setup](#initial-setup)
- [User Accounts](#user-accounts)
- [Firmware & Encryption](#firmware--encryption)
- [Lockdown Mode](#lockdown-mode)
- [Firewall](#firewall)
- [System Services](#system-services)
- [Spotlight & Siri](#spotlight--siri)
- [Package Management](#package-management)
- [DNS Security](#dns-security)
- [Certificate Authorities](#certificate-authorities)
- [Web Proxy](#web-proxy)
- [Web Browsers](#web-browsers)
- [Tor & Anonymity](#tor--anonymity)
- [VPN](#vpn)
- [Encryption (PGP/GPG)](#encryption-pgpgpg)
- [Secure Messaging](#secure-messaging)
- [Malware Protection](#malware-protection)
- [System Integrity Protection](#system-integrity-protection)
- [Metadata & Artifacts](#metadata--artifacts)
- [Password Security](#password-security)
- [Backup Strategy](#backup-strategy)
- [Wi-Fi Security](#wi-fi-security)
- [SSH Hardening](#ssh-hardening)
- [Physical Security](#physical-security)
- [System Monitoring](#system-monitoring)
- [Binary Authorization](#binary-authorization)
- [Additional Tweaks](#additional-tweaks)
- [Related Tools](#related-tools)
- [Resources](#resources)

---

## Security Fundamentals

General security best practices apply:

### Build a Threat Model

- Define what you're protecting and from whom
- Is your adversary a nation-state actor, a corporate competitor, or opportunistic attackers?
- Understand [Advanced Persistent Threats (APT)](https://en.wikipedia.org/wiki/Advanced_persistent_threat) and where you fall on the threat spectrum

### Stay Updated

- Enable automatic updates in **System Settings → General → Software Update**
- Or use the CLI: `softwareupdate --install --all`
- Subscribe to [Apple Security Announcements](https://lists.apple.com/mailman/listinfo/security-announce)

### Encrypt Everything

- Enable [FileVault](https://support.apple.com/guide/mac-help/mh11785) for full-disk encryption
- Use the [built-in password manager](https://support.apple.com/105115) (Passwords app in macOS Sequoia+) or a reputable third-party solution

### Backup Religiously

- Create [regular backups](https://support.apple.com/104984) with Time Machine
- Always [encrypt backup drives](https://support.apple.com/guide/mac-help/mh21241)
- Consider enabling [Advanced Data Protection](https://support.apple.com/guide/security/sec973254c5f) for iCloud

### Practice Vigilance

- Only install software from verified sources
- Verify downloads when possible (checksums, signatures)
- Be skeptical of unsolicited links and attachments

---

## Threat Modeling

The foundation of any security strategy is understanding _what_ you're protecting and _who_ you're protecting it from. See [OWASP Threat Modeling](https://www.owasp.org/index.php/Application_Threat_Modeling) for methodology.

### Step 1: Identify Assets

Catalog what matters most:

- Devices (Mac, iPhone, iPad)
- Data (passwords, financial info, private communications)
- Online accounts and identities
- Professional/intellectual property

Categorize by sensitivity: **public**, **sensitive**, or **secret**.

### Step 2: Identify Adversaries

Who might target you? Consider their motivations:

- **Opportunistic criminals** — Financial gain via ransomware, credential theft
- **Corporate actors** — Data harvesting, behavioral tracking
- **Nation-state actors** — Surveillance, espionage

### Step 3: Assess Capabilities

Rank threats from unsophisticated to advanced:

| Adversary       | Typical Capabilities                                  |
| --------------- | ----------------------------------------------------- |
| Common thief    | Physical access, shoulder surfing                     |
| Script kiddie   | Publicly available exploits, phishing                 |
| Organized crime | Custom malware, social engineering                    |
| Nation-state    | Zero-days, supply chain attacks, passive surveillance |

### Step 4: Define Mitigations

Match defenses to threats. Here's an example threat matrix:

| Adversary        | Motivation   | Capabilities                              | Mitigation                                           |
| ---------------- | ------------ | ----------------------------------------- | ---------------------------------------------------- |
| **Roommate**     | Curiosity    | Physical access, screen viewing           | Biometrics, privacy screen, auto-lock                |
| **Thief**        | Financial    | Device theft, shoulder surfing            | FileVault, Find My, strong passcode                  |
| **Criminal**     | Financial    | Phishing, malware, credential stuffing    | App Sandbox, Gatekeeper, 2FA, updates                |
| **Corporation**  | Data mining  | Telemetry, tracking                       | Block trackers, limit permissions, use privacy tools |
| **Nation-state** | Surveillance | Traffic analysis, zero-days, supply chain | Lockdown Mode, hardware keys, Tor, E2EE              |

📖 _Further reading: [Threat Model 101](https://www.netmeister.org/blog/threat-model-101.html)_

---

## Hardware

macOS security is strongest on [genuine Apple hardware](https://support.apple.com/guide/security/secf020d1074) with Apple silicon.

### Recommendations

- **Buy the newest Mac you can afford** — Each generation brings security improvements
- **Avoid Hackintoshes** — No Secure Enclave, no hardware root of trust
- **Skip older Intel Macs** — Missing critical security features, limited update support

### Purchase Privacy

Depending on your threat model:

- Pay with **cash** in-store to avoid linking the purchase to your identity
- Use a **prepaid card** if buying online

### Accessories

For Bluetooth peripherals (keyboard, mouse, headphones):

- Apple accessories receive automatic firmware updates
- They support [BLE Privacy](https://support.apple.com/guide/security/sec82597d97e) (randomized Bluetooth addresses)
- Third-party accessories may not offer these protections

---

## Installing macOS

Always install the [latest compatible macOS version](https://support.apple.com/102662). Older versions don't receive all security patches.

### Activation

Apple silicon Macs require [activation](https://support.apple.com/102541) with Apple's servers during reinstallation. This verifies the device isn't stolen or activation-locked.

Technical details: [LocalPolicy signing key creation and management](https://support.apple.com/guide/security/sec1f90fbad1)

### Apple ID

An Apple ID is **optional** but required for:

- App Store access
- iCloud services
- iMessage, FaceTime, Apple Music

**Privacy considerations:**

- Apple ID creation requires a phone number
- By default, [significant data syncs to iCloud](https://www.apple.com/legal/privacy/data/en/apple-id/)
- Enable [Advanced Data Protection](https://support.apple.com/guide/security/sec973254c5f) for E2EE on iCloud data
- You can [manage or delete](https://support.apple.com/102283) your Apple ID data anytime

### App Store

The Mac App Store provides:

- **Curated software** with [review guidelines](https://developer.apple.com/app-store/review/guidelines)
- **Mandatory sandboxing** and hardened runtime
- **Automatic updates** integrated with the system

Trade-off: Apple can associate downloads with your Apple ID.

### Virtualization

Run macOS in a VM for testing or isolation:

| Tool                                                         | Cost                     | Notes                                                                                                                                                     |
| ------------------------------------------------------------ | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [UTM](https://mac.getutm.app)                                | Free (paid on App Store) | Easy setup, [documentation](https://docs.getutm.app/guest-support/macos/)                                                                                 |
| [VMware Fusion](https://www.vmware.com/products/fusion.html) | Paid                     | Enterprise-grade, [documentation](https://docs.vmware.com/en/VMware-Fusion/13/com.vmware.fusion.using.doc/GUID-474FC78E-4E77-42B7-A1C6-12C2F378C5B9.html) |

---

## Initial Setup

During **Setup Assistant**, create your first account with a [strong password](https://www.eff.org/dice) (no hint!).

### Hostname Privacy

Your real name becomes part of the computer's network identity (e.g., _John Appleseed's MacBook_). Change it in **System Settings → General → About** or via Terminal:

Both should be verified and updated as needed in **System Settings > About** or with the following commands after installation:

```console
sudo scutil --set ComputerName MacBook
sudo scutil --set LocalHostName MacBook
```

---

## User Accounts

The first user created is an **admin account** with `sudo` access, which poses security risks—any program you run can potentially gain system-wide control.

### Best Practice: Separate Admin and Standard Accounts

Per [Apple](https://help.apple.com/machelp/mac/10.12/index.html#/mh11389) and [NIST recommendations](https://csrc.nist.gov/publications/drafts/800-179/sp800_179_draft.pdf):

- Use a **standard account** for daily work
- Reserve the **admin account** for installations and system changes

> 💡 You can [hide the admin account](https://support.apple.com/HT203998) for a cleaner experience.

### Considerations

| Feature                          | Standard Account       | Admin Account |
| -------------------------------- | ---------------------- | ------------- |
| Install to `/Applications`       | ❌ (prompts for admin) | ✅            |
| Install to `~/Applications`      | ✅                     | ✅            |
| Use `sudo`                       | ❌ (must use `su`)     | ✅            |
| App Store apps                   | ✅                     | ✅            |
| System Preferences (full access) | ❌                     | ✅            |

### Setup Commands

To demote an existing account from admin to standard:

```console
sudo dscl . -delete /Groups/admin GroupMembership <username>
sudo dscl . -delete /Groups/admin GroupMembers <GeneratedUID>
```

Find the GeneratedUID:

```console
dscl . -read /Users/<username> GeneratedUID
```

More details: [SuperUser discussion](https://superuser.com/a/395738)

---

## Firmware & Encryption

### Firmware Security

Ensure firmware security is set to **Full Security** (the default) to prevent OS tampering:

**System Settings → General → Startup Disk → Security Policy**

### FileVault

All Apple silicon Macs have encrypted storage by default. [FileVault](https://support.apple.com/guide/mac-help/mh11785) adds password protection to access that data.

**Enable via:** System Settings → Privacy & Security → FileVault

Your FileVault password also serves as a [firmware password](https://support.apple.com/102384), preventing:

- Booting from external drives
- Accessing Recovery Mode
- DFU revive attacks

> ⚠️ **Recovery Key:** Store it securely offline. Avoid iCloud recovery if you don't trust Apple with your decryption capability.

---

## Lockdown Mode

[Lockdown Mode](https://support.apple.com/105120) is Apple's extreme protection feature that significantly reduces attack surface by disabling:

- Most message attachment types
- Link previews
- Complex web technologies
- Incoming FaceTime from unknown callers
- Shared albums
- USB accessories when locked
- Configuration profiles

**Ideal for:** Journalists, activists, and high-risk individuals.

> 💡 You can whitelist trusted websites in Safari when Lockdown Mode is enabled.

**Enable via:** System Settings → Privacy & Security → Lockdown Mode

---

## Firewall

### Built-in Application Firewall

macOS includes a basic firewall that blocks **incoming connections only**.

**Enable via:** System Settings → Network → Firewall

Or via Terminal:

```console
# Enable firewall with logging and stealth mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Prevent auto-whitelisting signed apps
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off

# Apply changes
sudo pkill -HUP socketfilterfw
```

**Stealth mode** prevents your Mac from responding to ICMP pings and port scans.

### Third-Party Firewalls

For **outgoing** connection control, consider:

| App                                                          | Notes               |
| ------------------------------------------------------------ | ------------------- |
| [LuLu](https://objective-see.com/products/lulu.html)         | Free, open-source   |
| [Little Snitch](https://www.obdev.at/products/littlesnitch/) | Feature-rich, paid  |
| [Radio Silence](https://radiosilenceapp.com/)                | Simple, lightweight |

> ⚠️ These require [system extensions](https://support.apple.com/HT210999) and can be bypassed by root-level malware.

### Kernel-Level Filtering (pf)

For advanced users, macOS includes `pf` (packet filter). Example configuration:

```
# pf.rules
wifi = "en0"
ether = "en7"
set block-policy drop
set skip on lo0
scrub in all no-df
table <blocklist> persist
block in log
block in log quick from no-route to any
block log on $wifi from { <blocklist> } to any
block log on $wifi from any to { <blocklist> }
antispoof quick for { $wifi $ether }
pass out proto tcp from { $wifi $ether } to any keep state
pass out proto udp from { $wifi $ether } to any keep state
pass out proto icmp from $wifi to any keep state
```

Commands:

```console
sudo pfctl -e -f pf.rules  # Enable
sudo pfctl -d              # Disable
sudo pfctl -t blocklist -T add 1.2.3.4  # Block IP
```

For a GUI, try [Murus](https://www.murusfirewall.com/).

---

## System Services

macOS services are managed by **launchd**. See [launchd.info](https://launchd.info) for details.

### Viewing Services

- **Login Items:** System Settings → General → Login Items
- **Extensions:** System Settings → General → Extensions

```console
launchctl list                    # User agents
sudo launchctl list              # System daemons
launchctl list com.apple.Maps.mapspushd  # Specific service
```

### Inspecting Services

```console
defaults read /System/Library/LaunchDaemons/com.apple.apsd.plist
man apsd  # Read about the binary
```

> ⚠️ System services are protected by SIP. Don't disable SIP to tinker with them—it's a critical security feature.

### View Service Status

```console
find /var/db/com.apple.xpc.launchd/ -type f -print -exec defaults read {} \; 2>/dev/null
```

📖 _More info: [Apple Terminal scripting with launchd](https://support.apple.com/guide/terminal/apdc6c1077b-5d5d-4d35-9c19-60f2397b2369)_

---

## Spotlight & Siri

Apple has moved toward on-device processing for Siri, but some data is still sent to Apple. Review [Apple's Siri Privacy Policy](https://www.apple.com/legal/privacy/data/en/siri-suggestions-search/) to understand what's collected.

**Disable Siri Suggestions:** System Settings → Siri & Spotlight → Siri Suggestions & Privacy

---

## Package Management

[Homebrew](https://brew.sh/) simplifies software installation and updates.

### Installation

```console
xcode-select --install  # Install Command Line Tools first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Security Notes

- Homebrew uses TLS and [verifies package integrity](https://brew.sh/2022/05/17/homebrew-security-audit/)
- Run `brew upgrade` regularly on trusted networks
- Check packages before installing: `brew info <package>`

### Disable Analytics

```console
export HOMEBREW_NO_ANALYTICS=1
brew analytics off
```

### Additional Hardening

```console
export HOMEBREW_NO_INSECURE_REDIRECT=1
export HOMEBREW_CASK_OPTS=--require-sha
```

---

## DNS Security

### DNS Configuration Profiles

macOS supports encrypted DNS (DoH/DoT) via configuration profiles.

**Create profiles:** [dns.notjakob.com](https://dns.notjakob.com/)

**Popular providers:**

- [Quad9](<https://docs.quad9.net/Setup_Guides/MacOS/Big_Sur_and_later_(Encrypted)/#download-profile>)
- [AdGuard](https://adguard-dns.io/en/public-dns.html)
- [NextDNS](https://nextdns.io/)

### Hosts File Blocking

Block domains at the system level:

```console
sudo vi /etc/hosts
```

Add entries like:

```
0.0.0.0 ads.example.com
0.0.0.0 tracking.example.com
```

**Curated blocklists:**

- [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
- [someonewhocares.org](https://someonewhocares.org/hosts/zero/hosts)

### DNSCrypt

Encrypt DNS traffic with [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy):

```console
brew install dnscrypt-proxy
```

Configure to run on port 5355 (to combine with dnsmasq), then:

```console
sudo brew services restart dnscrypt-proxy
```

### Dnsmasq

Local DNS caching and filtering:

```console
brew install dnsmasq
sudo brew services start dnsmasq
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1
```

---

## Certificate Authorities

macOS ships with [100+ root CA certificates](https://support.apple.com/103723) from corporations and governments worldwide. Any of these can issue certificates for any domain.

Apple [blocks untrustworthy CAs](https://support.apple.com/103247#blocked) and enforces [strict requirements](https://www.apple.com/certificateauthority/ca_program.html).

### Viewing Certificates

- **Keychain Access** → System Roots
- Or via CLI: `security dump-keychain /System/Library/Keychains/SystemRootCertificates.keychain`

### Distrusting a CA

In Keychain Access, double-click a certificate → Trust → set to **Never Trust**.

> ⚠️ Don't distrust Apple root certificates—it will break macOS functionality.

📖 _More info: [CA/Browser Forum](https://cabforum.org/resources/browser-os-info/)_

---

## Web Proxy

[Privoxy](https://www.privoxy.org/) provides local web traffic filtering.

```console
brew install privoxy
brew services start privoxy
```

Configure system proxy:

```console
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8118
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8118
```

Example filter to block all traffic except specific domains:

```
{ +block{all} }
.

{ -block }
.apple.
.github.com
```

---

## Web Browsers

The Web browser likely poses the largest security and privacy risk, as its fundamental job is to download and execute untrusted code from the Internet.

An important property of modern browsers is the Same Origin Policy ([SOP](https://en.wikipedia.org/wiki/Same-origin_policy)) which prevents a malicious script on one page from obtaining access to sensitive data on another web page through the Document Object Model (DOM). If SOP is compromised, the security of the entire browser is compromised.

Many browser exploits are based on social engineering as a means of gaining persistence. Always be mindful of opening untrusted sites and especially careful when downloading new software.

Another important consideration about browser security is extensions. This is an issue affecting Firefox and [Chrome](https://courses.csail.mit.edu/6.857/2016/files/24.pdf) alike. The use of browser extensions should be limited to only critically necessary ones published by trustworthy developers.

[Mozilla Firefox](https://www.mozilla.org/en-US/firefox/new/), [Google Chrome](https://www.google.com/chrome/), [Safari](https://www.apple.com/safari/), and [Tor Browser](https://www.torproject.org/projects/torbrowser.html.en) are all recommended browsers for their own unique and individual purposes.

## Firefox

[Mozilla Firefox](https://www.mozilla.org/firefox/new/) is a popular open source browser. Firefox replaced major parts of its infrastructure and code base under the projects [Quantum](https://wiki.mozilla.org/Quantum) and [Photon](https://wiki.mozilla.org/Firefox/Photon/Updates). Part of the Quantum project is to replace C++ code with [Rust](https://www.rust-lang.org). Rust is a systems programming language with a focus on security and thread safety. It is expected that Rust adoption will greatly improve the overall security posture of Firefox.

Firefox offers a similar security model to Chrome: it has a [bug bounty program](https://www.mozilla.org/security/bug-bounty), although it is not as lucrative. Firefox follows a four-week release cycle similar to Chrome.

Firefox supports user-supplied configuration files. See [drduh/config/firefox.user.js](https://github.com/drduh/config/blob/master/firefox.user.js) and [arkenfox/user.js](https://github.com/arkenfox/user.js) for recommended preferences and hardening measures. Also see [NoScript](https://noscript.net/), an extension which allows selective script blocking.

Firefox [focuses on user privacy](https://www.mozilla.org/en-US/firefox/privacy/). It supports [tracking protection](https://developer.mozilla.org/docs/Web/Privacy/Firefox_tracking_protection) in Private Browsing mode. The tracking protection can be enabled for the default account, although it may break the browsing experience on some websites. Firefox in Strict tracking protection mode will [randomize your fingerprint](https://support.mozilla.org/kb/firefox-protection-against-fingerprinting) to foil basic tracking scripts. Firefox offers separate user [profiles](https://support.mozilla.org/kb/profile-manager-create-remove-switch-firefox-profiles). You can separate your browsing inside a profile with [Multi-Account Containers](https://support.mozilla.org/kb/containers).

Firefox only supports Web Extensions through the [Web Extension Api](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions), which is very similar to Chrome. Submission of Web Extensions in Firefox is free. Web Extensions in Firefox most of the time are open source, although certain Web Extensions are proprietary.

## Chrome

[Google Chrome](https://www.google.com/chrome) is based on the open source [Chromium project](https://www.chromium.org) with certain [proprietary components](https://fossbytes.com/difference-google-chrome-vs-chromium-browser):

- Automatic updates with GoogleSoftwareUpdateDaemon
- Usage tracking and crash reporting, which can be disabled through Chrome's settings
- Media Codec support for proprietary codecs
- Chrome Web Store
- PDF viewer
- Non-optional tracking. Google Chrome installer includes a randomly generated token. The token is sent to Google after the installation completes in order to measure the success rate. The RLZ identifier stores information – in the form of encoded strings – like the source of chrome download and installation week. It doesn’t include any personal information and it’s used to measure the effectiveness of a promotional campaign. **Chrome downloaded from Google’s website doesn’t have the RLZ identifier**. The source code to decode the strings is made open by Google.

Chrome offers account sync between multiple devices. Part of the sync data includes credentials to Web sites. The data is encrypted with the account password.

Chrome's Web Store for extensions requires a [5 USD lifetime fee](https://developer.chrome.com/docs/webstore/register) in order to submit extensions. The low cost allows the development of many quality Open Source Web Extensions that do not aim to monetize through usage.

Chrome has the largest share of global usage and is the preferred target platform for the majority of developers. Major technologies are based on Chrome's Open Source components, such as [node.js](https://nodejs.org) which uses [Chrome's V8](https://developers.google.com/v8) Engine and the [Electron](https://electron.atom.io) framework, which is based on Chromium and node.js. Chrome's vast user base makes it the most attractive target for threat actors and security researchers. Despite constant attacks, Chrome has retained an impressive security track record over the years. This is not a small feat.

Chrome offers [separate profiles](https://www.chromium.org/user-experience/multi-profiles), [robust sandboxing](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md), [frequent updates](https://chromereleases.googleblog.com), and carries [impressive credentials](https://www.chromium.org/Home/chromium-security/brag-sheet). In addition, Google offers a very lucrative [bounty program](https://bughunters.google.com/about/rules/5745167867576320/chrome-vulnerability-reward-program-rules) for reporting vulnerabilities, along with its own [Project Zero](https://googleprojectzero.blogspot.com/) team. This means that a large number of highly talented and motivated people are constantly auditing and securing Chrome code.

Create separate Chrome profiles to reduce XSS risk and compartmentalize cookies/identities. In each profile, either disable Javascript in Chrome settings and configure allowed origins. You should also disable the V8 Optimizer for sites where you do use Javascript to further reduce attack surface. Go to **Settings** -> **Privacy and security** -> **Security** -> **Manage v8 security** -> **Don't allow sites to use the V8 optimizer**

Read more about the benefits of disabling this [here](https://microsoftedge.github.io/edgevr/posts/Super-Duper-Secure-Mode).

You can block trackers with [uBlock Origin Lite](https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh).

Change the default search engine from Google to reduce additional tracking.

Disable [DNS prefetching](https://www.chromium.org/developers/design-documents/dns-prefetching) (see also [DNS Prefetching and Its Privacy Implications](https://www.usenix.org/legacy/event/leet10/tech/full_papers/Krishnan.pdf) (pdf)). Note that Chrome [may attempt](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/350) to resolve DNS using Google's `8.8.8.8` and `8.8.4.4` public nameservers.

Read [Chromium Security](https://www.chromium.org/Home/chromium-security) and [Chromium Privacy](https://www.chromium.org/Home/chromium-privacy) for more information. Read [Google's privacy policy](https://policies.google.com/privacy) to understand how personal information is collected and used.

## Safari

[Safari](https://www.apple.com/safari) is the default browser on macOS. It is also the most optimized browser for reducing battery use. Safari, like Chrome, has both Open Source and proprietary components. Safari is based on the open source Web Engine [WebKit](https://webkit.org), which is ubiquitous among the macOS ecosystem. WebKit is used by Apple apps such as Mail, iTunes, iBooks, and the App Store. Chrome's [Blink](https://www.chromium.org/blink) engine is a fork of WebKit and both engines share a number of similarities.

Safari supports certain unique features that benefit user security and privacy. [Content blockers](https://webkit.org/blog/3476/content-blockers-first-look) enables the creation of content blocking rules without using Javascript. This rule based approach greatly improves memory use, security, and privacy. Safari 11 introduced [Intelligent Tracking Prevention](https://webkit.org/blog/7675/intelligent-tracking-prevention), which removes tracking data stored in Safari after a period of non-interaction by the user from the tracker's website. Safari can randomize your fingerprint to reduce tracking. Safari doesn't support certain features like WebUSB or the Battery API intentionally for security and privacy reasons. Private tabs in Safari have isolated cookies and cache that is destroyed when you close the tab. Safari also support Profiles which are equivalent to Firefox's Multi-Account Containers for separating cookies and browsing. Safari can be made significantly more secure with [lockdown mode](#lockdown-mode), which can be disabled per-site. Read more about [tracking prevention](https://webkit.org/tracking-prevention) in Safari.

Safari offers an invite-only [bounty program](https://developer.apple.com/bug-reporting) for bug reporting to a select number of security researchers. The bounty program was announced during Apple's [presentation](https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf) at [BlackHat](https://www.blackhat.com/us-16/briefings.html#behind-the-scenes-of-ios-security) 2016.

Web Extensions in Safari have an additional option to use native code in the Safari's sandbox environment, in addition to Web Extension APIs. Web Extensions in Safari are also distributed through Apple's App store. App store submission comes with the added benefit of Web Extension code being audited by Apple. On the other hand App store submission comes at a steep cost. Yearly [developer subscription](https://developer.apple.com/support/compare-memberships) fee costs 100 USD (in contrast to Chrome's 5 USD fee and Firefox's free submission). The high cost is prohibitive for the majority of Open Source developers. As a result, Safari has very few extensions to choose from. However, you should keep the high cost in mind when installing extensions. It is expected that most Web Extensions will have some way of monetizing usage in order to cover developer costs. Be wary of Web Extensions whose source code is not open.

Safari syncs user preferences and passwords with [iCloud Keychain](https://support.apple.com/HT202303). In order to be viewed in plain text, a user must input the account password of the current device. This means that users can sync data across devices with added security.

Safari follows a slower release cycle than Chrome and Firefox (3-4 minor releases, 1 major release, per year). Newer features are slower to be adopted to the stable channel. Security updates in Safari are handled independent of the stable release schedule and are installed through the App Store.

See also [el1t/uBlock-Safari](https://github.com/el1t/uBlock-Safari/wiki/Disable-hyperlink-auditing-beacon) to disable hyperlink auditing beacons.

## Other browsers

Many Chromium-derived browsers are not recommended due to being closed source, poorly maintained, or making dubious privacy claims.

---

## Tor & Anonymity

[Tor Browser](https://www.torproject.org/download/) provides anonymity through the Tor network.

### Installation

1. Download from [torproject.org](https://www.torproject.org/download/)
2. Verify the signature (important!)
3. Mount the disk image and drag to Applications

```console
# Verify code signature
spctl -a -vv ~/Applications/Tor\ Browser.app
# Look for: Developer ID Application: The Tor Project, Inc (MADPSAYN6T)
```

> ⚠️ **Never** configure other browsers to use Tor—use only Tor Browser.

### Important Considerations

- Tor provides **anonymity**, not privacy
- Tor traffic is encrypted to exit nodes, but usage patterns can be identified
- Use [pluggable transports](https://tb-manual.torproject.org/circumvention/) to obfuscate Tor traffic
- For higher security, run Tor inside a VM

📖 _Alternative: [I2P](https://geti2p.net/en/about/intro) — [comparison with Tor](https://geti2p.net/en/comparison/tor)_

---

## VPN

### Protocol Recommendations

| Protocol      | Status                                 |
| ------------- | -------------------------------------- |
| **WireGuard** | ✅ Modern, fast, audited               |
| **OpenVPN**   | ✅ Battle-tested, widely supported     |
| PPTP          | ❌ Broken, avoid                       |
| L2TP/IPSec    | ⚠️ Acceptable if WireGuard unavailable |

### Considerations

- Research your provider's jurisdiction and logging policies
- Use a kill switch to prevent traffic leakage on disconnect
- Consider [self-hosting](https://github.com/hwdsl2/setup-ipsec-vpn) for maximum control

📖 _Technical details: [macOS VPN Architecture](https://blog.timac.org/2018/0717-macos-vpn-architecture/)_

---

## Encryption (PGP/GPG)

GPG enables end-to-end encryption for files and communications.

```console
brew install gnupg
```

For hardware key storage, see [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

Download recommended configuration:

```console
curl -o ~/.gnupg/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf
```

---

## Secure Messaging

### Recommended Messengers

| App              | Protocol          | Notes                                                               |
| ---------------- | ----------------- | ------------------------------------------------------------------- |
| **Signal**       | Signal Protocol   | Gold standard for E2EE, requires phone number                       |
| **iMessage**     | Apple proprietary | Enable [Contact Key Verification](https://support.apple.com/118246) |
| **XMPP + OMEMO** | Open standard     | Federated, requires OMEMO for E2EE                                  |

### iMessage Security

- Enable [Advanced Data Protection](https://support.apple.com/guide/security/sec973254c5f) to prevent key backup to Apple
- Verify contacts using Contact Key Verification
- Remember: your messaging partners should do the same!

---

## Malware Protection

Mac malware is [increasingly common](https://www.documentcloud.org/documents/2459197-bit9-carbon-black-threat-research-report-2015.html). Macs are **not** immune to viruses.

### Where Malware Comes From

- Bundled with pirated software
- Fake updates and phishing
- Supply chain attacks on legitimate software
- Malicious browser extensions

📖 _Stay informed: [Objective-See Blog](https://objective-see.com/blog.html), [Malwarebytes Blog](https://blog.malwarebytes.com/)_

### Safe Software Practices

| Source                      | Trust Level | Notes                     |
| --------------------------- | ----------- | ------------------------- |
| Mac App Store               | ✅ Highest  | Reviewed, sandboxed       |
| Notarized apps              | ✅ High     | Apple-scanned for malware |
| Developer websites (signed) | ⚠️ Medium   | Verify signatures         |
| Unsigned/pirated            | ❌ Avoid    | High malware risk         |

### Verifying App Security

**Check App Sandbox:**

```console
codesign -dvvv --entitlements - /path/to/app.app | grep sandbox
```

**Check Hardened Runtime:**

```console
codesign --display --verbose /path/to/app.app
# Look for: flags=0x10000(runtime)
```

### Built-in Protection

| Feature          | Description                                           |
| ---------------- | ----------------------------------------------------- |
| **XProtect**     | Automatic malware scanning and removal                |
| **Gatekeeper**   | Blocks unverified apps (right-click → Open to bypass) |
| **Notarization** | Apple scans apps before distribution                  |
| **MRT**          | Malware Removal Tool runs automatically               |

### Third-Party Tools

- [KnockKnock](https://objective-see.org/products/knockknock.html) — Examine persistent software
- [BlockBlock](https://objective-see.org/products/blockblock.html) — Alert on persistence mechanisms
- [VirusTotal](https://www.virustotal.com/) — Multi-engine malware scanning

> ⚠️ Third-party antivirus can introduce [attack surface](https://lock.cmpxchg8b.com/sophailv2.pdf) and privacy concerns due to privileged access.

---

## System Integrity Protection

SIP prevents modification of protected system files and processes.

**Verify SIP status:**

```console
csrutil status
# Should return: System Integrity Protection status: enabled.
```

> ⚠️ Never disable SIP unless absolutely necessary, and re-enable immediately after.

---

## Metadata & Artifacts

macOS tracks metadata that can reveal your activities. Periodically clean these for privacy.

### Download Metadata

View extended attributes on downloaded files:

```console
xattr -l ~/Downloads/example.dmg
mdls ~/Downloads/example.dmg
```

Remove download metadata:

```console
xattr -d com.apple.metadata:kMDItemWhereFroms ~/Downloads/example.dmg
xattr -d com.apple.quarantine ~/Downloads/example.dmg
```

### Common Artifact Locations

| Location                                         | Contains                      |
| ------------------------------------------------ | ----------------------------- |
| `~/Library/Preferences/`                         | App preferences, recent files |
| `/Library/Preferences/com.apple.Bluetooth.plist` | Bluetooth device history      |
| `~/Library/Application Support/Quick Look/`      | Thumbnail cache               |
| `/var/spool/cups/`                               | Print job history             |
| `~/Library/Saved Application State/`             | App window states             |

### Clear Bluetooth History

```console
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist DeviceCache
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist PANDevices
```

### Clear QuickLook Cache

```console
qlmanage -r disablecache
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/*
```

### Clear Print History

```console
sudo rm -rfv /var/spool/cups/c0* /var/spool/cups/tmp/* /var/spool/cups/cache/job.cache*
```

### Clear Finder Preferences

```console
defaults delete ~/Library/Preferences/com.apple.finder.plist FXRecentFolders
defaults delete ~/Library/Preferences/com.apple.finder.plist RecentMoveAndCopyDestinations
defaults delete ~/Library/Preferences/com.apple.finder.plist RecentSearches
```

### Clear Wi-Fi from NVRAM

```console
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:current-network
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-networks
```

> ⚠️ Clearing Document Revisions (`/.DocumentRevisions-V100`) may break some Apple apps.

---

## Password Security

### Generate Strong Passwords

```console
tr -dc '[:graph:]' < /dev/urandom | fold -w 20 | head -1
```

Or use [Diceware](https://www.eff.org/dice) for memorable passphrases.

### Multi-Factor Authentication

| Type                          | Security Level                |
| ----------------------------- | ----------------------------- |
| **Hardware keys (WebAuthn)**  | ✅ Strongest                  |
| **Authenticator apps (TOTP)** | ✅ Strong                     |
| **SMS codes**                 | ⚠️ Weak (SIM swap vulnerable) |

**Recommended:** [YubiKey](https://www.yubico.com/products/) — supports WebAuthn, TOTP, and GPG key storage.

See [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) for setup instructions.

---

## Backup Strategy

### The 3-2-1 Rule

Per [CISA guidelines](https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf):

- **3** copies of your data
- **2** different storage types
- **1** offsite copy

### Time Machine

1. Connect an external drive
2. **System Settings → General → Time Machine**
3. **Always encrypt backups**

### Encrypted Archives with GPG

```console
# Encrypt
tar zcvf - ~/Documents | gpg -c > backup-$(date +%F).tar.gz.gpg

# Decrypt
gpg -d backup-*.tar.gz.gpg | tar zxvf -
```

### Encrypted Disk Images

```console
hdiutil create ~/Desktop/secure.dmg -encryption -size 100M -volname "Secure"
```

---

## Wi-Fi Security

### Privacy Risks

Your Mac broadcasts remembered network names (SSIDs) when searching for networks, revealing location history.

**Remove old networks:** System Settings → Network → Wi-Fi → ⓘ on each network → Forget

### MAC Address Spoofing

Randomize your MAC address on untrusted networks:

```console
sudo ifconfig en0 ether $(openssl rand -hex 6 | sed 's%\(..\)%\1:%g; s%.$%%')
```

> Note: Resets to hardware MAC on reboot.

### Wi-Fi Encryption Standards

| Protocol | Status                |
| -------- | --------------------- |
| WPA3     | ✅ Best               |
| WPA2     | ✅ Acceptable         |
| WPA      | ⚠️ Legacy             |
| WEP      | ❌ Broken — never use |

---

## SSH Hardening

### Client Configuration

Use hardware-backed or password-protected keys. See [drduh/config/ssh_config](https://github.com/drduh/config/blob/master/ssh_config) for recommended options.

Consider hashing hostnames in `~/.ssh/known_hosts`:

```console
ssh-keygen -H
```

### SSH as SOCKS Proxy

```console
ssh -NCD 3000 you@remote-host.tld
```

Then configure your browser to use `localhost:3000` as a SOCKS5 proxy.

### SSH Tunneling

Forward a remote proxy locally:

```console
ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555
```

### Enabling Remote Login (sshd)

By default, macOS does **not** enable sshd. To enable:

**System Settings → General → Sharing → Remote Login**

If enabling, configure strong authentication:

- Disable password authentication
- Use key-based auth only
- See [drduh/config/sshd_config](https://github.com/drduh/config/blob/master/sshd_config)

Check if sshd is running:

```console
sudo lsof -Pni TCP:22
```

---

## Physical Security

Keep your Mac physically secure. A skilled attacker with physical access could:

- Install hardware keyloggers
- Extract data from an unencrypted drive
- Access Recovery Mode

### Anti-Theft Tools

| Tool                                                  | Description                                          |
| ----------------------------------------------------- | ---------------------------------------------------- |
| [BusKill](https://github.com/buskill/buskill-app)     | Dead-man switch — locks/shuts down on USB disconnect |
| [swiftGuard](https://github.com/Lennolium/swiftGuard) | Monitors USB events, blocks unauthorized devices     |

### Tamper Detection

- Use [nail polish](https://trmm.net/Glitter) on screws to detect physical tampering
- Consider privacy screens in public spaces

---

## System Monitoring

### OpenBSM Audit

macOS includes OpenBSM for auditing process execution, network activity, and more:

```console
sudo praudit -l /dev/auditpipe
```

See `man audit`, `man praudit`, and files in `/etc/security/`.

> ⚠️ Reboot required for audit configuration changes.

### DTrace Tools

> Note: Requires disabling SIP (not recommended).

| Tool        | Purpose           |
| ----------- | ----------------- |
| `iosnoop`   | Disk I/O          |
| `opensnoop` | File opens        |
| `execsnoop` | Process execution |
| `errinfo`   | Failed syscalls   |
| `dtruss`    | All syscalls      |

### Process Monitoring

```console
ps -ef                    # All processes
launchctl list            # User launch agents
sudo launchctl list       # System daemons
```

### Network Monitoring

```console
sudo lsof -Pni            # Open network connections
sudo netstat -atln        # Network structures
```

With [Wireshark](https://www.wireshark.org/) installed:

```console
# DNS queries
tshark -Y "dns.flags.response == 1" -Tfields -e dns.qry.name -e dns.a

# HTTP traffic
tshark -Y "http.request or http.response" -Tfields -e http.request.full_uri
```

---

## Binary Authorization with Santa

[Google Santa](https://github.com/google/santa/) provides binary allowlist/blocklist enforcement for macOS.

### How It Works

Santa uses macOS's Endpoint Security framework to monitor and allow/block binary execution based on:

- SHA-256 hash
- Signing certificate
- Team ID

### Installation

```console
# Download from GitHub Releases
hdiutil mount ~/Downloads/santa-*.dmg
sudo installer -pkg /Volumes/santa-*/santa-*.pkg -tgt /
```

### Verify Installation

```console
santactl status
```

### Usage Examples

**Block an application:**

```console
sudo santactl rule --block --path /Applications/SomeApp.app/
```

**Allow by certificate:**

```console
santactl fileinfo /Applications/App.app/   # Get signing chain
sudo santactl rule --allow --certificate --sha256 <CERT_SHA256>
```

**Lockdown mode** (only allow explicitly approved binaries):

```console
sudo defaults write /var/db/santa/config.plist ClientMode -int 2
```

> ⚠️ Santa cannot block scripts (Python, Bash) since interpreters are Apple-signed.

---

## Additional Tweaks

### Screen Lock

```console
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0
```

### Show Hidden Files

```console
defaults write com.apple.finder AppleShowAllFiles -bool true
chflags nohidden ~/Library
```

### Show All Extensions

Prevent "malware.jpg.app" disguises:

```console
defaults write NSGlobalDomain AppleShowAllExtensions -bool true
```

### Disable iCloud Document Saving

```console
defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
```

### Secure Keyboard Entry (Terminal)

Enable in **Terminal → Secure Keyboard Entry** to prevent other apps from reading keystrokes.

### Disable Crash Reporter Dialog

```console
defaults write com.apple.CrashReporter DialogType none
```

### Custom umask

Set restrictive default file permissions:

```console
sudo launchctl config user umask 077
```

### Disable Bonjour Advertisements

> ⚠️ Breaks AirPlay and AirPrint!

```console
sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES
```

---

## Related Tools

| Tool                                                    | Description                              |
| ------------------------------------------------------- | ---------------------------------------- |
| [Lynis](https://github.com/CISOfy/lynis)                | Security auditing and compliance testing |
| [osquery](https://github.com/osquery/osquery)           | SQL-based system information queries     |
| [Zentral](https://github.com/zentralopensource/zentral) | Santa/osquery log aggregation server     |

---

## Resources

| Resource                                                             | Description                      |
| -------------------------------------------------------------------- | -------------------------------- |
| [Apple Platform Security](https://support.apple.com/guide/security/) | Official security documentation  |
| [Apple Open Source](https://opensource.apple.com/)                   | Darwin and open components       |
| [CIS Benchmarks](https://www.cisecurity.org/benchmark/apple_os/)     | Security configuration standards |
| [EFF Surveillance Self-Defense](https://ssd.eff.org/)                | Privacy and security guides      |
| [Objective-See Blog](https://objective-see.com/blog.html)            | macOS security research          |
| [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide)        | Hardware key setup               |

---

## Contributing

Contributions welcome! Please see the guide for submitting improvements.

## License

This work is licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-nc-sa/4.0/).
