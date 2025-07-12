# Web App Pentesting Methodology

## Information Gathering

- [ ]  Conduct Search Engine Discovery Reconnaissance for Information Leakage [WSTG-INFO-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage)
	- [Google Dorking](google-dorking.md)
	- [Github Searching](repo-searching)
- [ ]  Fingerprint Web Server [WSTG-INFO-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
    - Banner grabbing
    - whatweb, builtwith, etc. Make a note of technologies in use.
    - Try sending malformed requests
- [ ]  Review Webserver Metafiles for Information Leakage [WSTG-INFO-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)
    - Robots.txt
    - Check meta tags
    - Sitemaps?
    - Are there any `.well-known` files?
    - humans.txt
- [ ]  Enumerate Applications on Webserver [WSTG-INFO-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver)
    - Non-standard URLs
    - Non-standard ports
    - Virtual hosts
- [ ]  Review Web Page Content for Information Leakage [WSTG-INFO-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage)
- [ ]  Identify Application Entry Points [WSTG-INFO-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points)
    - Happy path!!
    - Look for parameters in query strings and POST bodies
    - Look out for anything that seems different, odd, or custom.
- [ ]  Map Execution Paths Through Application [WSTG-INFO-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application)
    - Spidering
- [ ]  Fingerprint Web Application Framework [WSTG-INFO-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
    - X-Powered-By
    - Cookies
    - HTML source code
    - Directory busting
    - Search for specific file extensions in use
- [ ]  ~~Fingerprint Web Application [WSTG-INFO-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application)~~
- [ ]  Map Application Architecture [WSTG-INFO-10](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture)
    - Web server
    - Platform-as-a-Service
    - Serverless
        - AWS Lambda
        - Azure
    - Microservices
    - Static storage
        - S3
        - Azure blob
    - Databases in use
    - Authentication
    - Third-party services and APIs
    - Network components - load balancer, CDN
    - WAF, IDS, IPS

## Configuration and Deployment Management Testing

- [ ]  Test Network Infrastructure Configuration [WSTG-CONF-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration)
    - Review any configurations
    - Check framework and system version information to identify vulns.
- [ ]  Test Application Platform Configuration [WSTG-CONF-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration)
    - Sample and known file directories
    - Review comments
    - Benchmarks
- [ ]  Test File Extensions Handling for Sensitive Information [WSTG-CONF-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information)
    - Check with different file extensions to see how they're handled
    - Specifically look for `.asa` , `.inc`, `.config` files
    - Look for old, archive, office docs, txt files, etc.
- [ ]  Review Old Backup and Unreferenced Files for Sensitive Information [WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)
    - Try appending `.old` and `.bak` to any files you find
    - Fuzz using old/backup extensions
- [ ]  Enumerate Infrastructure and Application Admin Interfaces [WSTG-CONF-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces)
    - Google Dorking
    - Check comments, cookies, etc. for any indications
    - Look for parameter tampering
- [ ]  Test HTTP Methods [WSTG-CONF-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)
- [ ]  Test HTTP Strict Transport Security [WSTG-CONF-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security)
- [ ]  ~~Test RIA Cross Domain Policy [WSTG-CONF-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy)~~
- [ ]  Test File Permission [WSTG-CONF-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission)
- [ ]  Test for Subdomain Takeover [WSTG-CONF-10](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- [ ]  Test Cloud Storage [WSTG-CONF-11](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage)
    - Check for anonymous access
    - Use any [[AWS]], [[Azure]], [[GCP]] tricks to extract information
- [ ]  Testing for Content Security Policy [WSTG-CONF-12](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy)
- [ ]  Test Path Confusion [WSTG-CONF-13](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/13-Test_for_Path_Confusion)
    - Replace all existing paths with paths that don't exist and observe the server's behavior
- [ ]  Test Other HTTP Security Header Misconfigurations [WSTG-CONF-14](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/14-Test_Other_HTTP_Security_Header_Misconfigurations)
    - Carefully review all security headers, including:
        - Empty values
        - Invalid names or typos
        - Overly permissive headers, e.g., *
        - Duplicate headers
        - Legacy or deprecated headers
        - Invalid placement
        - META tag handling mistakes

## Identity Management Testing

- [ ]  Test Role Definitions [WSTG-IDNT-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions)
    - If not given, try fuzzing for all possible roles
    - Check for parameter tampering
    - Autorize
- [ ]  Test User Registration Process [WSTG-IDNT-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process)
    - Can anyone just register an account?
    - Figure out how registrations are vetted
    - Can the same person register multiple times
    - Can users register for different roles or permissions?
    - What proof of identity is required?
    - Are registered identities verified? How?
- [ ]  Test Account Provisioning Process [WSTG-IDNT-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process)
    - Verify which accounts can provision other accounts. What levels/permissions?
    - Is there any verification required for provisioning/de-provisioning?
    - Can an admin provision other admins?
    - Can an admin or other user provision accounts with higher permissions?
    - Can an admin de-provision themselves?
    - How are files or resources owned by the de-provisioned user handled? Deleted? Access transferred?
- [ ]  Testing for Account Enumeration and Guessable User Account [WSTG-IDNT-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
    - Check for disparities between responses
    - Check anywhere user id is provided/all login forms
- [ ]  Testing for Weak or Unenforced Username Policy [WSTG-IDNT-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy)
    - Determine the structure of account names
    - Evaluate the responses to valid and invalid account names

## Authentication Testing

- [ ]  Testing for Credentials Transported over an Encrypted Channel [WSTG-ATHN-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel)
    - Check in the browser - look at URL bar/lock status
    - Watch the network tab
    - Wireshark
- [ ]  Testing for Default Credentials [WSTG-ATHN-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)
    - Use DBs of default passwords to check against
- [ ]  Testing for Weak Lock Out Mechanism [WSTG-ATHN-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
    - Can you still log in after 20+ invalid logon attempts?
- [ ]  Testing for Bypassing Authentication Schema [WSTG-ATHN-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema)
    - Forced browsing
    - Parameter modification
    - Session ID prediction
    - SQLi
- [ ]  Testing for Vulnerable Remember Password [WSTG-ATHN-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password)
    - Is the password stored anywhere on the client-side?
    - Check tokens for expiration
- [ ]  Testing for Browser Cache Weaknesses [WSTG-ATHN-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses)
    - Does the application store any sensitive information on the client-side?
    - Can we access without authorization?
- [ ]  Testing for Weak Authentication Methods [WSTG-ATHN-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Authentication_Methods)
    - What characters are permitted or required? Complexity enforced?
    - How often can a user change the password?
        - Is there a cooling off period? Can the user change the password several times in a row to effectively have the same password?
        - Is there anything that prevents using the username as a password?
        - Can we set weak or common passwords?
- [ ]  Testing for Weak Security Question Answer [WSTG-ATHN-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer)
    - Try to obtain a list of security questions
    - Is there any lockout mechanism in place for wrong answers to security questions?
- [ ]  Testing for Weak Password Change or Reset Functionalities [WSTG-ATHN-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities)
    - Does the application validate the user?
    - Is the current password required to change it?
    - Are forgot password tokens sufficiently random/encrypted?
        - Only good once
        - Limited time -- how long?
- [ ]  Testing for Weaker Authentication in Alternative Channel [WSTG-ATHN-10](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel)
    - Are multiple channels available?
    - Are the channels used for different things? What does each allow you to do?
- [ ]  Testing Multi-Factor Authentication (MFA) [WSTG-ATHN-11](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication)
    - If present, can it be brute forced?
    - Can you skip the MFA verification -- force browse away from the verification page?

## Authorization Testing

- [ ]  Testing Directory Traversal File Include [WSTG-ATHZ-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
    - Look for injection points, something like `/?file=test.txt`
    - Images are good for this
    - Fuzz for files based on OS
- [ ]  Testing for Bypassing Authorization Schema [WSTG-ATHZ-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
    - Is it possible to access a resource unauthenticated?
    - Can we access after logout?
    - Horizontal and vertical privilege escalation
- [ ]  Testing for Privilege Escalation [WSTG-ATHZ-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation)
    - Check every insertion point, e.g., any place a user can affect information in a database
    - Manipluate:
        - Condition values
        - IP address
        - Autorize
- [ ]  Testing for Insecure Direct Object References [WSTG-ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
    - BOLA - Can I see things I shouldn’t?
    - BFLA - Can I do things I shouldn’t be able to do?
- [ ]  Testing for OAuth Weaknesses [WSTG-ATHZ-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses)
    - Deprecated grant types, e.g., implicit grant flow

## Session Management Testing

- [ ]  Testing for Session Management Schema [WSTG-SESS-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema)
- [ ]  Testing for Cookies Attributes [WSTG-SESS-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
    - HttpOnly
    - Secure
    - Path
    - Domain
- [ ]  Testing for Session Fixation [WSTG-SESS-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation)
    - Are cookies updated after login?
- [ ]  Testing for Exposed Session Variables [WSTG-SESS-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables)
- [ ]  Testing for Cross Site Request Forgery [WSTG-SESS-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
    - Relevant action
    - Cookie-based auth
    - No unpredictable parameters
- [ ]  Testing for Logout Functionality [WSTG-SESS-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality)
    - Does logoff terminate the session?
        - Can we replay a request after logout?
- [ ]  Testing Session Timeout [WSTG-SESS-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout)
    - Does the application terminate inactive sessions?
    - Does it redirect to a non-sensitive page?
- [ ]  Testing for Session Puzzling [WSTG-SESS-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling)
- [ ]  Testing for Session Hijacking [WSTG-SESS-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking)
- [ ]  Testing JSON Web Tokens [WSTG-SESS-10](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
- [ ]  Testing for Concurrent Sessions [WSTG-SESS-11](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/11-Testing_for_Concurrent_Sessions)
    - Multiple tabs
    - Multiple devices
    - Does logging in on one log out of the other?
    - What happens when you try to edit the same data in different sessions?

## Input Validation Testing

- [ ]  Testing for Reflected Cross-Site Scripting [WSTG-INPV-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
    - Check CSP for any potential bypasses...look for `*.example.com`
    - Check the context
    - Try different ways to escape the context
- [ ]  Testing for Stored Cross Site Scripting [WSTG-INPV-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting)
- [ ]  Testing for HTTP Verb Tampering [WSTG-INPV-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)
    - Do different verbs result in different behavior?
- [ ]  Testing for HTTP Parameter Pollution [WSTG-INPV-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [ ]  Testing for SQLi [WSTG-INPV-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [ ]  Testing for LDAP Injection [WSTG-INPV-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)
- [ ]  Testing for XML Injection [WSTG-INPV-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
- [ ]  Testing for SSI Injection [WSTG-INPV-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection)
- [ ]  Testing for XPath Injection [WSTG-INPV-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection)
- [ ]  Testing for IMAP SMTP Injection [WSTG-INPV-10](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection)
- [ ]  Testing for Code Injection [WSTG-INPV-11](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection)
- [ ]  Testing for Command Injection [WSTG-INPV-12](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- [ ]  Testing for Buffer Overflow [WSTG-INPV-13](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Buffer_Overflow)
- [ ]  Testing for Format String Injection [WSTG-INPV-13](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection)
- [ ]  Testing for Incubated Vulnerability [WSTG-INPV-14](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_Incubated_Vulnerability)
- [ ]  Testing for HTTP Splitting Smuggling [WSTG-INPV-15](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling)
- [ ]  Testing for HTTP Incoming Requests [WSTG-INPV-16](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests)
- [ ]  Testing for Host Header Injection [WSTG-INPV-17](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- [ ]  Testing for Server-side Template Injection [WSTG-INPV-18](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [ ]  Testing for Server Side Request Forgery [WSTG-INPV-19](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery)
- [ ]  Testing for Mass Assignment [WSTG-INPV-20](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment)

## Testing for Error Handling

- [ ]  Testing for Improper Error Handling [WSTG-ERRH-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
    - Request non-existent resources
    - Request folders that exist and check the server response
    - Try sending a very large path
    - Change the HTTP version
    - Try sending malformed requests
    - Try sending invalid/duplicate headers
    - Try intercepting then dropping a request
- [ ]  ~~Testing for Stack Traces [WSTG-ERRH-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces)~~

## Testing for Weak Cryptography

- [ ]  Testing for Weak Transport Layer Security [WSTG-CRYP-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)
- [ ]  Testing for Padding Oracle [WSTG-CRYP-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [ ]  Testing for Sensitive Information Sent via Unencrypted Channels [WSTG-CRYP-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels)
- [ ]  Testing for Weak Encryption [WSTG-CRYP-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption)

## Business Logic Testing

- [ ]  Test Business Logic Data Validation [WSTG-BUSL-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation)
- [ ]  Test Ability to Forge Requests [WSTG-BUSL-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests)
- [ ]  Test Integrity Checks [WSTG-BUSL-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks)
- [ ]  Test for Process Timing [WSTG-BUSL-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing)
- [ ]  Test Number of Times a Function Can Be Used Limits [WSTG-BUSL-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits)
- [ ]  Testing for the Circumvention of Work Flows [WSTG-BUSL-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)
    - e.g., Try force browsing past MFA prompt
- [ ]  Test Defenses Against Application Misuse [WSTG-BUSL-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse)
- [ ]  Test Upload of Unexpected File Types [WSTG-BUSL-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types)
    - Try tricking the upload...bypass blacklist, etc.
- [ ]  Test Upload of Malicious Files [WSTG-BUSL-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files)
    - Upload EICAR file to test AV
- [ ]  Test Payment Functionality [WSTG-BUSL-10](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test-Payment-Functionality)

## Client Side Testing

- [ ]  Testing for DOM-Based Cross Site Scripting [WSTG-CLNT-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
- [ ]  Testing for JavaScript Execution [WSTG-CLNT-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution)
- [ ]  Testing for HTML Injection [WSTG-CLNT-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection)
- [ ]  Testing for Client-side URL Redirect [WSTG-CLNT-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
- [ ]  Testing for CSS Injection [WSTG-CLNT-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection)
- [ ]  Testing for Client-side Resource Manipulation [WSTG-CLNT-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation)
- [ ]  Testing Cross Origin Resource Sharing [WSTG-CLNT-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [ ]  Testing for Cross Site Flashing [WSTG-CLNT-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Cross_Site_Flashing)
- [ ]  Testing for Clickjacking [WSTG-CLNT-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)
- [ ]  Testing WebSockets [WSTG-CLNT-10](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)
- [ ]  Testing Web Messaging [WSTG-CLNT-11](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging)
- [ ]  Testing Browser Storage [WSTG-CLNT-12](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage)
- [ ]  Testing for Cross Site Script Inclusion [WSTG-CLNT-13](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion)
- [ ]  Testing for Reverse Tabnabbing [WSTG-CLNT-14](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/14-Testing_for_Reverse_Tabnabbing)

## API Testing

- [ ]  API Reconnaissance [WSTG-APIT-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-API_Reconnaissance)
- [ ]  Testing GraphQL [WSTG-APIT-99](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/99-Testing_GraphQL)