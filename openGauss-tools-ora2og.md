
## Basic Information

**Vulnerability Title**: Ora2Pg ora2pg_scanner Script Command Injection Vulnerability

**Discovery Date**: December 9, 2025

**Vulnerability Type**: Command Injection

**Affected Versions**: Ora2Pg 21.1 and earlier versions

**Vulnerability Status**: Unpatched

**submitter**:yudeshui

## Executive Summary

Ora2Pg is an open-source tool for migrating Oracle and MySQL databases to PostgreSQL. This version is a customized fork for the openGauss project. A critical command injection vulnerability has been discovered in the `scripts/ora2pg_scanner` script. Attackers can execute arbitrary commands on target systems by crafting malicious CSV input files.

**Project Repository**: https://github.com/opengauss-mirror/openGauss-tools-ora2og

## Technical Details

### Vulnerability Location
- **File**: `scripts/ora2pg_scanner`
- **Function**: Main execution loop
- **Code Lines**: Approximately lines 150-180

### Vulnerable Code
```perl
# Around line 150
print `$cmd_ora2pg -t SHOW_SCHEMA -s '$DB_DNS[$i]->{dsn}'`;

# Around line 160  
my @schema_list = `$cmd_ora2pg -t SHOW_SCHEMA -s '$DB_DNS[$i]->{dsn}'`;
```

### Root Cause Analysis
1. **Insufficient Input Validation**: The script directly trusts DSN field content from CSV files
2. **Unsafe String Concatenation**: Uses string concatenation to build system commands
3. **Lack of Escaping**: No escaping or filtering of special characters

### Attack Vector
Attackers need the ability to provide or modify CSV input files used by ora2pg_scanner.

## Vulnerability Exploitation

### Proof of Concept Payload
```csv
type,schema/database,dsn,user,password
ORACLE,test,dbi:Oracle:host=127.0.0.1;sid=XE' & echo PWNED > pwned.txt & echo ',system,manager
```


### Attack Flow
1. Attacker creates CSV file containing malicious DSN
2. Target user processes the file with ora2pg_scanner
3. Script parses CSV and constructs command
4. Malicious command is executed, granting attacker code execution

### Actual Test Results
- ✅ Successfully created file `pwned.txt`
- ✅ File content: "PWNED"
- ✅ Confirmed command injection vulnerability is exploitable


## Impact Assessment

### Affected Systems
- All systems using Ora2Pg 21.1 and earlier versions
- Particularly environments using ora2pg_scanner for batch database scanning

### Potential Impact
1. **Remote Code Execution**: Attackers can execute arbitrary system commands
2. **Data Exfiltration**: Can read sensitive files and database information
3. **Privilege Escalation**: May further obtain system administrator privileges
4. **Persistence**: Can establish backdoors and persistence mechanisms
5. **Lateral Movement**: Can serve as a pivot point for attacking other internal systems

### Attack Scenarios
- **Insider Threat**: Malicious insiders modify shared configuration files
- **Supply Chain Attack**: Upstream data providers compromised, malicious payloads planted
- **Social Engineering**: Attackers trick targets into processing malicious CSV files

## Remediation

### Immediate Actions
1. **Discontinue Use**: Stop using ora2pg_scanner until patched
2. **Input Validation**: Strictly validate CSV file contents
3. **Privilege Restriction**: Run scripts with minimal privileges

### Code Fix
```perl
# Use parameterized command execution
use IPC::Run qw(run);
my @cmd = ($cmd_ora2pg, '-t', 'SHOW_SCHEMA', '-s', $dsn);
my ($in, $out, $err);
run \@cmd, \$in, \$out, \$err;

# Input validation function
sub validate_dsn {
    my $dsn = shift;
    return 0 if $dsn =~ /[;&|`$()'"]/;
    return $dsn =~ /^dbi:(Oracle|mysql):[a-zA-Z0-9=;.:_-]+$/i;
}
```

## References

- **Project Repository**: https://github.com/opengauss-mirror/openGauss-tools-ora2og
- **Original Ora2Pg Project**: https://github.com/darold/ora2pg
- **Vulnerable File**: scripts/ora2pg_scanner
- **openGauss Documentation**: https://opengauss.org/
- **Original Documentation**: https://ora2pg.darold.net/

