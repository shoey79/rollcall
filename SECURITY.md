# Security policy

Rollcall's agents run with high privileges (SYSTEM on Windows, root on Linux) and the add-on sits inside Home Assistant, so security problems matter. Thank you for reporting them responsibly.

## Reporting a vulnerability

**Please don't open a public issue.** Instead, use GitHub's private reporting: go to the **Security** tab of this repository and choose **Report a vulnerability**. Only the maintainer can see the report.

Useful things to include:

- what the problem is and what an attacker could do with it;
- the add-on and agent versions;
- steps to reproduce, or a proof of concept;
- anything you've found that limits it (e.g. it needs an approved agent, or access to the Home Assistant network).

Please leave out details of your own network.

## What happens next

- You'll get a reply as soon as possible, usually within a few days.
- Once confirmed, a fix is released as a new add-on version (and agent version if needed), with a changelog entry. Agents set to update automatically pick it up at their next report.
- You'll be credited in the changelog, unless you'd rather not be.

## Supported versions

Only the latest release is supported. Please update the add-on, and the agents (**Agents → Update**, or automatic updates), before reporting.

## In scope

- The add-on: the dashboard and its API, the agent API (port 8100), enrolment and approval, and anything that lets someone read data or make changes they shouldn't.
- The Windows and Linux agents, and the installer (.msi) the add-on builds.
- The syslog, SNMP and SIP listeners and probes.

Problems in Home Assistant itself, or in third-party devices Rollcall monitors, should go to those projects.
