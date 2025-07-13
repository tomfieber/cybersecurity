# Recon and Scanning

- [ ] Packet capture
- [ ] Find DCs
- [ ] Responder (Analyze mode)
- [ ] Email domain security
- [ ] Breached credentials
- [ ] Host discovery
    - [ ] fping
    - [ ] nmap
- [ ] Initial netexec sweep
    - [ ] Relay targets
    - [ ] SMBv1

# LDAP

See [[Searching LDAP]] for more.

- [ ] Anonymous bind
- [ ] enum4linux-ng
- [ ] LDAP signing
- [ ] ldapsearch

# SMB

- [ ] Unauthenticated shares
- [ ] Guest access
- [ ] Spider shares
- [ ] Manspider
- [ ] SMB vulnerability scanning (Netexec)
- [ ] WRITE access? Try dropping LNK, URL, searchConnector files, etc.

# Poisoning

- [ ] LLMNR/NBT-NS poisoning
- [ ] NTLM relay
    - [ ] SMB signing not required
    - [ ] LDAP
    - [ ] WebClient Service
- [ ] IPv6

# User Compromise

- [ ] AS-REPRoasting
- [ ] Kerberoasting
- [ ] Password spraying
- [ ] Credential stuffing
- [ ] Check user descriptions
- [ ] Re-check shares
- [ ] With admin access, check logged in users

# ADCS

- [ ] Check server
- [ ] Enumerate templates
- [ ] Vulnerable templates

# Machine Compromise

- [ ] WebClient service enabled
    - [ ] Shadow credentials
- [ ] Check local admin for all users
- [ ] Dump secrets

# MSSQL

- [ ] Can we access data
- [ ] Command execution
	- [ ] Check for linked servers
	- [ ] Any stored procedures available on linked servers
- [ ] Impersonation
- [ ] NTLM theft → Relay

# Internal Services

- [ ] Full enumeration
- [ ] Check for default credentials
- [ ] Plaintext protocols